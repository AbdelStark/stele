//! RFC-0002 §7 — separate control harness; never linked into a prover or verifier.
#![forbid(unsafe_code)]

pub mod catalog;

/// A one-value mutation applied after an honest witness has been constructed.
/// Each control must assert that exactly its intended value changes.
pub trait ProverHook<W> {
    /// Mutate the selected value without changing the public statement.
    fn tamper(&self, witness: &mut W);
}

/// A control passes only on the expected verifier rejection, never a prover error.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlFailure<P, V> {
    /// The unmodified witness could not be proven.
    HonestProverFailed(P),
    /// The verifier rejected the honest proof.
    HonestRejected(V),
    /// The hook did not change the witness.
    NoTamper,
    /// The modified witness did not reach the verifier.
    TamperedProverFailed(P),
    /// The verifier accepted the modified witness's proof.
    TamperAccepted,
    /// The verifier failed a different check than the control targets.
    WrongRejection {
        /// Required rejection.
        expected: V,
        /// Observed rejection.
        actual: V,
    },
}

/// Prove and verify the honest witness, then repeat with its tampered copy.
/// Callers supply the real prover/verifier; the harness has no check-disabling API.
pub fn check_control<W, H, Proof, P, V>(
    honest: &W,
    hook: &H,
    prove: impl Fn(&W) -> Result<Proof, P>,
    verify: impl Fn(&Proof) -> Result<(), V>,
    expected: V,
) -> Result<(), ControlFailure<P, V>>
where
    W: Clone + PartialEq,
    H: ProverHook<W>,
    V: PartialEq,
{
    let proof = prove(honest).map_err(ControlFailure::HonestProverFailed)?;
    verify(&proof).map_err(ControlFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == *honest {
        return Err(ControlFailure::NoTamper);
    }
    let proof = prove(&tampered).map_err(ControlFailure::TamperedProverFailed)?;
    match verify(&proof) {
        Ok(()) => Err(ControlFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ControlFailure::WrongRejection { expected, actual }),
    }
}
