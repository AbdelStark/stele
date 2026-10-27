//! RFC-0002 §7 — harness self-controls; no inference binding is claimed.
#![forbid(unsafe_code)]
use stele_negative_controls::{check_control, ControlFailure, ProverHook};

#[derive(Clone, Debug, PartialEq)]
struct Witness([i32; 2]);

#[derive(Debug, PartialEq)]
enum Rejection {
    ClaimMismatch,
    Other,
}

struct ChangeCell;
impl ProverHook<Witness> for ChangeCell {
    fn tamper(&self, witness: &mut Witness) {
        witness.0[0] += 1;
    }
}

fn prove(witness: &Witness) -> Result<[i32; 2], ()> {
    Ok(witness.0)
}

fn verify(proof: &[i32; 2]) -> Result<(), Rejection> {
    if *proof == [3, 5] {
        Ok(())
    } else {
        Err(Rejection::ClaimMismatch)
    }
}

#[test]
fn accepts_honest_and_rejects_single_cell_tamper() {
    let honest = Witness([3, 5]);
    let mut tampered = honest.clone();
    ChangeCell.tamper(&mut tampered);
    assert_eq!(
        honest
            .0
            .iter()
            .zip(tampered.0)
            .filter(|(a, b)| **a != *b)
            .count(),
        1
    );
    assert_eq!(
        check_control(
            &honest,
            &ChangeCell,
            prove,
            verify,
            Rejection::ClaimMismatch
        ),
        Ok(())
    );
    assert_eq!(honest, Witness([3, 5]));
}

#[test]
fn rejects_verifier_accepting_tamper() {
    assert_eq!(
        check_control(
            &Witness([3, 5]),
            &ChangeCell,
            prove,
            |_| Ok(()),
            Rejection::ClaimMismatch
        ),
        Err(ControlFailure::TamperAccepted)
    );
}

#[test]
fn rejects_wrong_rejection_reason() {
    assert_eq!(
        check_control(
            &Witness([3, 5]),
            &ChangeCell,
            prove,
            verify,
            Rejection::Other
        ),
        Err(ControlFailure::WrongRejection {
            expected: Rejection::Other,
            actual: Rejection::ClaimMismatch
        })
    );
}

#[test]
fn rejects_invalid_honest_case() {
    assert_eq!(
        check_control(
            &Witness([4, 5]),
            &ChangeCell,
            prove,
            verify,
            Rejection::ClaimMismatch
        ),
        Err(ControlFailure::HonestRejected(Rejection::ClaimMismatch))
    );
}

#[test]
fn rejects_prover_failures() {
    let fail = |_: &Witness| -> Result<[i32; 2], ()> { Err(()) };
    assert_eq!(
        check_control(
            &Witness([3, 5]),
            &ChangeCell,
            fail,
            verify,
            Rejection::ClaimMismatch
        ),
        Err(ControlFailure::HonestProverFailed(()))
    );
    let fail_after_tamper = |w: &Witness| if w.0 == [3, 5] { prove(w) } else { Err(()) };
    assert_eq!(
        check_control(
            &Witness([3, 5]),
            &ChangeCell,
            fail_after_tamper,
            verify,
            Rejection::ClaimMismatch
        ),
        Err(ControlFailure::TamperedProverFailed(()))
    );
}

#[test]
fn rejects_no_op_hook() {
    struct NoChange;
    impl ProverHook<Witness> for NoChange {
        fn tamper(&self, _: &mut Witness) {}
    }
    assert_eq!(
        check_control(
            &Witness([3, 5]),
            &NoChange,
            prove,
            verify,
            Rejection::ClaimMismatch
        ),
        Err(ControlFailure::NoTamper)
    );
}
