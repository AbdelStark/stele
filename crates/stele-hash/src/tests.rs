//! RFC-0012 A1 — registry validation uses production code, not test-only checks.
use super::*;

#[test]
fn accepts_the_fixed_registry() {
    let entries = registry().expect("valid production registry");
    assert_eq!(entries.len(), 5);
    assert_eq!(entries.iter().filter(|e| e.loss.is_some()).count(), 1);
    assert_eq!(entries[4].loss, Some(LossLine::Sc));
}
#[test]
fn rejects_duplicate_labels_across_every_kind() {
    for left in 0..5 {
        for right in 0..5 {
            if left != right {
                let mut entries = REGISTRY;
                entries[right].label = entries[left].label;
                assert_eq!(validate_registry(&entries), Err(Error::DuplicateLabel));
            }
        }
    }
}
#[test]
fn rejects_invalid_label_bytes_and_accounting() {
    for label in ["", "unversioned", "stele/v0.1/é"] {
        let mut entries = REGISTRY;
        entries[1].label = label;
        assert_eq!(validate_registry(&entries), Err(Error::InvalidLabel));
    }
    let long = "stele/v0.1/".repeat(24);
    let mut entries = REGISTRY;
    entries[1].label = &long;
    assert_eq!(validate_registry(&entries), Err(Error::InvalidLabel));
    let mut entries = REGISTRY;
    entries[4].loss = None;
    assert_eq!(validate_registry(&entries), Err(Error::InvalidAccounting));
    for index in 0..4 {
        let mut entries = REGISTRY;
        entries[index].loss = Some(LossLine::Sc);
        assert_eq!(validate_registry(&entries), Err(Error::InvalidAccounting));
    }
}
