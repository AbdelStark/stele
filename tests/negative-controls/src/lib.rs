//! RFC-0002 §7 — separate control harness; never linked into a prover or verifier.
#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod batching;
pub mod catalog;
#[doc(hidden)]
pub mod sumcheck;

extern crate self as stele_negative_controls;
#[path = "../pcs/nc_0602.rs"]
mod nc_0602;
#[path = "../transcript/nc_0801.rs"]
mod nc_0801;

/// Executable controls; configuration passes do not earn statement-binding credit.
pub const CONTROLS: &[catalog::RegisteredControl] = &[
    catalog::RegisteredControl {
        id: 602,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: nc_0602::run,
    },
    catalog::RegisteredControl {
        id: 200,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || sumcheck::run(200),
    },
    catalog::RegisteredControl {
        id: 201,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || sumcheck::run(201),
    },
    catalog::RegisteredControl {
        id: 205,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || sumcheck::run(205),
    },
    catalog::RegisteredControl {
        id: 800,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || sumcheck::run(800),
    },
    catalog::RegisteredControl {
        id: 802,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || sumcheck::run(802),
    },
    catalog::RegisteredControl {
        id: 801,
        kind: catalog::ControlKind::Configuration,
        expected_error: "DuplicateLabel",
        run: nc_0801::run,
    },
];

/// A one-value mutation applied to an honest witness, proof or configuration.
/// Each control must assert that exactly its intended value changes.
pub trait ProverHook<W> {
    /// Mutate the selected value without changing the public statement.
    fn tamper(&self, witness: &mut W);
}

/// A control passes only on the expected verifier rejection, never a prover error.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlFailure<P, V> {
    /// The honest proof could not be produced.
    HonestProverFailed(P),
    /// The verifier rejected the honest proof.
    HonestRejected(V),
    /// The hook did not change the witness or proof.
    NoTamper,
    /// The modified witness did not reach the verifier.
    TamperedProverFailed(P),
    /// The verifier accepted the tampered proof.
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

/// RFC-0006 A1: verify an honest production proof, then one mutated proof value.
/// The control asserts exactly one change and supplies the unchanged real verifier.
pub fn check_proof_control<Proof, H, P, V>(
    prove: impl FnOnce() -> Result<Proof, P>,
    hook: &H,
    verify: impl Fn(&Proof) -> Result<(), V>,
    expected: V,
) -> Result<(), ControlFailure<P, V>>
where
    Proof: Clone + PartialEq,
    H: ProverHook<Proof>,
    V: PartialEq,
{
    let honest = prove().map_err(ControlFailure::HonestProverFailed)?;
    verify(&honest).map_err(ControlFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == honest {
        return Err(ControlFailure::NoTamper);
    }
    match verify(&tampered) {
        Ok(()) => Err(ControlFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ControlFailure::WrongRejection { expected, actual }),
    }
}

/// Failure of a configuration-validation control (RFC-0012 A1, NC-0801 only).
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigurationFailure<E> {
    /// The production validator rejected the honest configuration.
    HonestRejected(E),
    /// The hook did not change the configuration.
    NoTamper,
    /// The production validator accepted the tampered configuration.
    TamperAccepted,
    /// Rejection occurred at a different boundary than the control targets.
    WrongRejection {
        /// Required rejection.
        expected: E,
        /// Observed rejection.
        actual: E,
    },
}

/// Validate the honest configuration and its one-value-tampered copy.
/// This path has no proof wrapper and earns no proof-statement binding coverage.
/// The caller must use the production validator and assert its exact mutation.
pub fn check_configuration<C, H, E>(
    honest: &C,
    hook: &H,
    validate: impl Fn(&C) -> Result<(), E>,
    expected: E,
) -> Result<(), ConfigurationFailure<E>>
where
    C: Clone + PartialEq,
    H: ProverHook<C>,
    E: PartialEq,
{
    validate(honest).map_err(ConfigurationFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == *honest {
        return Err(ConfigurationFailure::NoTamper);
    }
    match validate(&tampered) {
        Ok(()) => Err(ConfigurationFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ConfigurationFailure::WrongRejection { expected, actual }),
    }
}
