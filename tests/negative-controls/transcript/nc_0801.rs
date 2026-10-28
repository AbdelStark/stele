//! RFC-0012 A1 — reject one duplicated label at the production registry boundary.
use stele_hash::{registry, validate_registry, Error, RegistryEntry};
use stele_negative_controls::{check_configuration, ProverHook};

struct DuplicateLabel;
impl ProverHook<[RegistryEntry<'static>; 12]> for DuplicateLabel {
    fn tamper(&self, entries: &mut [RegistryEntry<'static>; 12]) {
        let before = *entries;
        entries[4].label = entries[2].label;
        assert_eq!(
            before
                .iter()
                .zip(entries.iter())
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        assert_eq!(entries[4].kind, before[4].kind);
        assert_eq!(entries[4].loss, before[4].loss);
    }
}
/// Execute the actual configuration control; no proof verifier is substituted.
pub fn run() -> Result<(), String> {
    let honest = registry().map_err(|e| format!("honest registry: {e:?}"))?;
    check_configuration(
        honest,
        &DuplicateLabel,
        |entries| validate_registry(entries),
        Error::DuplicateLabel,
    )
    .map_err(|e| format!("{e:?}"))
}
#[test]
fn rejects_duplicate_registered_label() {
    run().expect("NC-0801 must reject at the production validator");
}
