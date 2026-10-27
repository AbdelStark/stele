//! RFC-0012 A1 / Workflow 08 — configuration controls must use the real validator.
#![forbid(unsafe_code)]
use stele_negative_controls::{check_configuration, ConfigurationFailure, ProverHook};

#[derive(Debug, PartialEq, Eq)]
enum Error {
    DuplicateLabel,
    Wrong,
}
struct Duplicate;
impl ProverHook<[u8; 2]> for Duplicate {
    fn tamper(&self, labels: &mut [u8; 2]) {
        labels[1] = labels[0];
    }
}
struct NoChange;
impl ProverHook<[u8; 2]> for NoChange {
    fn tamper(&self, _: &mut [u8; 2]) {}
}
fn validate(labels: &[u8; 2]) -> Result<(), Error> {
    if labels[0] == labels[1] {
        Err(Error::DuplicateLabel)
    } else {
        Ok(())
    }
}

#[test]
fn accepts_exact_configuration_rejection() {
    // Harness self-test only: this fixture is not NC-0801 and earns no catalog credit.
    assert_eq!(
        check_configuration(&[1, 2], &Duplicate, validate, Error::DuplicateLabel),
        Ok(())
    );
}
#[test]
fn rejects_invalid_honest_configuration_and_no_mutation() {
    assert_eq!(
        check_configuration(&[1, 1], &Duplicate, validate, Error::DuplicateLabel),
        Err(ConfigurationFailure::HonestRejected(Error::DuplicateLabel))
    );
    assert_eq!(
        check_configuration(&[1, 2], &NoChange, validate, Error::DuplicateLabel),
        Err(ConfigurationFailure::NoTamper)
    );
}
#[test]
fn rejects_configuration_acceptance_and_wrong_error() {
    assert_eq!(
        check_configuration(&[1, 2], &Duplicate, |_| Ok(()), Error::DuplicateLabel),
        Err(ConfigurationFailure::TamperAccepted)
    );
    assert_eq!(
        check_configuration(
            &[1, 2],
            &Duplicate,
            |v| {
                if v[0] == v[1] {
                    Err(Error::Wrong)
                } else {
                    Ok(())
                }
            },
            Error::DuplicateLabel
        ),
        Err(ConfigurationFailure::WrongRejection {
            expected: Error::DuplicateLabel,
            actual: Error::Wrong,
        })
    );
}
