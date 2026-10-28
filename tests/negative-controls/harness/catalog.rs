//! RFC-0002 §7 — malformed catalogs and false coverage must be rejected.
#![forbid(unsafe_code)]
use stele_negative_controls::catalog::{parse, report, ControlKind, RegisteredControl};

const ROW: &str = "| NC-0001 | binding | 0002 §7 | change cell | ExactError | todo |";

#[test]
fn accepts_repository_catalog_without_crediting_stub() {
    let catalog = parse(include_str!("../catalog.md")).expect("valid repository catalog");
    assert_eq!(catalog.len(), 71);
    assert_eq!(catalog.first().map(|entry| entry.id), Some(1));
    assert_eq!(catalog.last().map(|entry| entry.id), Some(1203));
    assert!(
        report(&catalog, &[]).is_err(),
        "done requires executed registration"
    );
    let coverage =
        report(&catalog, stele_negative_controls::CONTROLS).expect("executed production controls");
    assert!(coverage.contains("3/17 bindings; 13/71 controls"));
    assert_eq!(coverage.matches("MISSING").count(), 58);
    assert!(coverage.contains("Configuration controls: 1 (not proof-statement coverage)"));
}

#[test]
fn rejects_malformed_catalogs() {
    for text in [
        "".to_owned(),
        "|".to_owned(),
        ROW.repeat(2),
        format!("{ROW}\n{ROW}"),
        ROW.replace("0001", "0002–0001"),
        ROW.replace("0001", "xyz"),
        ROW.replace("todo", "ignored"),
        ROW.replace("ExactError", "").replace("todo", "done"),
        ROW.trim_end_matches('|').to_owned(),
        ROW.replace("binding", ""),
        ROW.replace("NC-0001", "NC-0001–99999"),
        ROW.replace("| NC-", "NC-"),
    ] {
        assert!(parse(&text).is_err(), "unexpected acceptance: {text}");
    }
}

#[test]
fn accepts_range_expansion_and_detects_overlap() {
    let range = ROW.replace("NC-0001", "NC-0001–0003");
    let entries = parse(&range).expect("valid range");
    assert_eq!(
        entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(parse(&format!("{range}\n{ROW}")).is_err());
}

#[test]
fn rejects_unexecuted_or_failed_coverage() {
    let row = ROW.replace("todo", "done");
    let entries = parse(&row).expect("valid implemented row");
    assert!(report(&entries, &[]).is_err());
    let control = RegisteredControl {
        id: 1,
        kind: ControlKind::Proof,
        expected_error: "ExactError",
        run: || Err("failed".into()),
    };
    assert!(report(&entries, &[control]).is_err());
    let control = RegisteredControl {
        id: 1,
        kind: ControlKind::Proof,
        expected_error: "WrongError",
        run: || Ok(()),
    };
    assert!(report(&entries, &[control]).is_err());
    let control = RegisteredControl {
        id: 2,
        kind: ControlKind::Proof,
        expected_error: "ExactError",
        run: || Ok(()),
    };
    assert!(report(&entries, &[control]).is_err());
}

#[test]
fn accepts_executed_registration_and_rejects_duplicates() {
    let row = ROW.replace("todo", "done");
    let entries = parse(&row).expect("valid implemented row");
    let control = || RegisteredControl {
        id: 1,
        kind: ControlKind::Proof,
        expected_error: "ExactError",
        run: || Ok(()),
    };
    assert!(report(&entries, &[control()])
        .expect("executed fixture")
        .contains("1/1 bindings; 1/1 controls"));
    assert!(report(&entries, &[control(), control()]).is_err());
    assert!(report(&parse(ROW).expect("planned row"), &[control()]).is_err());
}

#[test]
fn rejects_configuration_credit_for_a_proof_binding() {
    use stele_negative_controls::catalog::ControlKind;
    let rows =
        "| NC-0801 | transcript/ledger | 0012 A1 | duplicate label | DuplicateLabel | done |";
    let entries = parse(rows).expect("configuration row");
    let registration = |kind| RegisteredControl {
        id: 801,
        kind,
        expected_error: "DuplicateLabel",
        run: || Ok(()),
    };
    let output = report(&entries, &[registration(ControlKind::Configuration)])
        .expect("executed configuration fixture");
    assert!(output.contains("0/1 bindings; 1/1 controls"));
    assert!(output.contains("passed (configuration)"));
    assert!(output.contains("Configuration controls: 1 (not proof-statement coverage)"));
    assert!(report(&entries, &[registration(ControlKind::Proof)]).is_err());
    let row = ROW.replace("todo", "done");
    let entries = parse(&row).expect("proof row");
    let mut control = registration(ControlKind::Configuration);
    control.id = 1;
    control.expected_error = "ExactError";
    assert!(report(&entries, &[control]).is_err());
}
