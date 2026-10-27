//! RFC-0006 A1 — harness self-checks; no protocol control coverage.
#![forbid(unsafe_code)]
use std::cell::Cell;
use stele_negative_controls::{check_proof_control, ControlFailure, ProverHook};

struct Change(usize);
impl ProverHook<[u8; 2]> for Change {
    fn tamper(&self, proof: &mut [u8; 2]) {
        proof[0] += self.0 as u8;
    }
}
fn verify(proof: &[u8; 2]) -> Result<(), u8> {
    if *proof == [3, 5] {
        Ok(())
    } else {
        Err(7)
    }
}

#[test]
fn accepts_one_prove_then_honest_and_tampered_verification() {
    let calls = Cell::new(0);
    assert_eq!(
        check_proof_control(
            || {
                assert_eq!(calls.replace(1), 0);
                Ok::<_, u8>([3, 5])
            },
            &Change(1),
            |proof| {
                let call = calls.get();
                assert_eq!(*proof, if call == 1 { [3, 5] } else { [4, 5] });
                calls.set(call + 1);
                verify(proof)
            },
            7,
        ),
        Ok(())
    );
    assert_eq!(calls.get(), 3);
}

#[test]
fn rejects_prover_failure_and_honest_rejection_before_hook() {
    struct Never;
    impl ProverHook<[u8; 2]> for Never {
        fn tamper(&self, _: &mut [u8; 2]) {
            unreachable!("invalid honest baseline");
        }
    }
    assert_eq!(
        check_proof_control(|| Err::<[u8; 2], _>(9), &Never, verify, 7),
        Err(ControlFailure::HonestProverFailed(9))
    );
    assert_eq!(
        check_proof_control(|| Ok::<_, u8>([4, 5]), &Never, verify, 7),
        Err(ControlFailure::HonestRejected(7))
    );
}

#[test]
fn rejects_no_mutation_acceptance_and_wrong_error() {
    let prove = || Ok::<_, u8>([3, 5]);
    assert_eq!(
        check_proof_control(prove, &Change(0), verify, 7),
        Err(ControlFailure::NoTamper)
    );
    assert_eq!(
        check_proof_control(prove, &Change(1), |_| Ok(()), 7),
        Err(ControlFailure::TamperAccepted)
    );
    assert_eq!(
        check_proof_control(prove, &Change(1), verify, 8),
        Err(ControlFailure::WrongRejection {
            expected: 8,
            actual: 7
        })
    );
}
