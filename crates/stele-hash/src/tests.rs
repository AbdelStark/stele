//! RFC-0012 A1 — registry validation uses production code, not test-only checks.
use super::*;

#[test]
fn accepts_the_fixed_registry() {
    let entries = registry().expect("valid production registry");
    assert_eq!(entries.len(), 37);
    assert_eq!(entries.iter().filter(|e| e.loss.is_some()).count(), 11);
    assert_eq!(entries[4].loss, Some(LossLine::Sc));
    assert_eq!(entries[7].loss, Some(LossLine::Rlc));
    assert_eq!(entries[9].loss, Some(LossLine::Sc));
    assert_eq!(entries[14].loss, Some(LossLine::Rlc));
    assert_eq!(entries[15].loss, Some(LossLine::Rlc));
    assert_eq!(entries[17].loss, Some(LossLine::PcsTensor));
    assert_eq!(entries[19].loss, Some(LossLine::PcsQuery));
    assert_eq!(entries[23].loss, Some(LossLine::PcsQuery));
    assert_eq!(AbsorbLabel::FieldSources.entry(), &entries[25]);
    assert_eq!(entries[25].kind, LabelKind::Absorb);
    assert_eq!(entries[25].loss, None);
    assert_eq!(AbsorbLabel::MatmulStatement.entry(), &entries[36]);
    assert_eq!(entries[36].label, "stele/v0.1/matmul/statement");
    assert_eq!(entries[36].kind, LabelKind::Absorb);
    assert_eq!(entries[36].loss, None);
    for (label, index) in [(AbsorbLabel::StackSources, 26), (AbsorbLabel::Stack, 27)] {
        assert_eq!(label.entry(), &entries[index]);
        assert_eq!(entries[index].kind, LabelKind::Absorb);
        assert_eq!(entries[index].loss, None);
    }
}
#[test]
fn matches_reference_lookup_label_classes() {
    let entries = registry().expect("valid fixed registry");
    for (label, suffix, index) in [
        (AbsorbLabel::LookupStatement, "statement", 28),
        (AbsorbLabel::LookupUnits, "units", 29),
        (AbsorbLabel::LookupMultiplicities, "multiplicities", 30),
        (AbsorbLabel::LookupRepetition, "repetition", 31),
        (
            AbsorbLabel::LookupMultiplicityClaims,
            "multiplicity-claims",
            32,
        ),
    ] {
        assert_eq!(label.entry(), &entries[index]);
        assert_eq!(
            entries[index].label.strip_prefix("stele/v0.1/lookup/"),
            Some(suffix)
        );
        assert_eq!(entries[index].kind, LabelKind::Absorb);
        assert_eq!(entries[index].loss, None);
    }
    for (label, suffix, index) in [
        (ChallengeLabel::LookupUnit, "unit", 33),
        (ChallengeLabel::LookupBeta, "beta", 34),
        (ChallengeLabel::LookupAlpha, "alpha", 35),
    ] {
        assert_eq!(label.entry(), &entries[index]);
        assert_eq!(
            entries[index].label.strip_prefix("stele/v0.1/lookup/"),
            Some(suffix)
        );
        assert_eq!(entries[index].kind, LabelKind::Challenge);
        assert_eq!(entries[index].loss, Some(LossLine::Lu));
    }
}
#[test]
fn rejects_duplicate_labels_across_every_kind() {
    for left in 0..REGISTRY.len() {
        for right in 0..REGISTRY.len() {
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
    for index in 0..REGISTRY.len() {
        let mut entries = REGISTRY;
        entries[index].loss = if entries[index].kind == LabelKind::Challenge {
            None
        } else {
            Some(LossLine::Sc)
        };
        assert_eq!(validate_registry(&entries), Err(Error::InvalidAccounting));
    }
}
