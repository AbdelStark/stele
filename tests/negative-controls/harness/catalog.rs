//! RFC-0002 §7 — malformed catalogs and false coverage must be rejected.
#![forbid(unsafe_code)]
use stele_negative_controls::catalog::{parse, report, ControlKind, RegisteredControl};

const ROW: &str = "| NC-0001 | binding | 0002 §7 | change cell | ExactError | todo |";

#[test]
fn rejects_composed_message_tampers() {
    for (id, error) in [
        (1302, "FinalEvaluationMismatch"),
        (1303, "NoncanonicalField"),
        (1306, "Policy 1: RootMismatch; Policy 2: GrindMismatch"),
        (1307, "RoundSumMismatch"),
        (
            1308,
            "Profiles 3/5: RoundSumMismatch; other profiles: ValueMismatch",
        ),
    ] {
        let control = stele_negative_controls::CONTROLS
            .iter()
            .find(|control| control.id == id)
            .expect("composed message control registered");
        assert_eq!(control.kind, ControlKind::Proof);
        assert_eq!(control.expected_error, error);
        assert_eq!((control.run)(), Ok(()), "NC-{id}");
    }
}

#[test]
fn rejects_registry_binding_tampers() {
    for (id, error) in [
        (1325, "RegistryKeyMismatch"),
        (1326, "RegistryStaticMismatch"),
        (1327, "RegistryKeyMismatch"),
        (1328, "RegistryRequestMismatch"),
        (1329, "RegistryRequestMismatch"),
        (1330, "RegistryRequestMismatch"),
        (1331, "RegistryRequestMismatch"),
        (1332, "RegistryRequestMismatch"),
        (1333, "RegistryRequestMismatch"),
        (1334, "RegistryTemplateMismatch"),
    ] {
        let control = stele_negative_controls::CONTROLS
            .iter()
            .find(|control| control.id == id)
            .expect("all A16 controls registered");
        assert_eq!(control.kind, ControlKind::Proof);
        assert_eq!(control.expected_error, error);
        assert_eq!((control.run)(), Ok(()), "NC-{id}");
    }
}

#[test]
fn accepts_repository_catalog_without_crediting_stub() {
    let catalog = parse(include_str!("../catalog.md")).expect("valid repository catalog");
    assert_eq!(catalog.len(), 252);
    assert_eq!(catalog.first().map(|entry| entry.id), Some(1));
    assert_eq!(catalog.last().map(|entry| entry.id), Some(1340));
    assert!(
        report(&catalog, &[]).is_err(),
        "done requires executed registration"
    );
    let coverage =
        report(&catalog, stele_negative_controls::CONTROLS).expect("executed production controls");
    assert!(
        coverage.contains("82/126 bindings; 154/252 controls"),
        "{coverage}"
    );
    assert_eq!(coverage.matches("MISSING").count(), 98);
    for id in [
        203, 210, 211, 212, 213, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317,
        318, 400, 401, 402, 403, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 603, 605, 609,
        611, 612, 613, 614, 806, 807, 808, 809, 813, 814, 815, 816, 817, 902, 903, 904, 905, 906,
        907, 908, 909, 910, 911, 913, 914, 915, 916, 930, 931, 932, 1300, 1301, 1302, 1303, 1304,
        1305, 1306, 1307, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315, 1316, 1317, 1318, 1319,
        1320, 1321, 1322, 1323, 1324, 1325, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334,
        1335, 1336, 1337, 1338,
    ] {
        assert!(
            catalog
                .iter()
                .find(|entry| entry.id == id)
                .expect("implemented source control")
                .done
        );
        assert!(coverage.lines().any(|line| {
            line.starts_with(&format!("NC-{id:04} |")) && line.ends_with("passed")
        }));
    }
    for id in (100..=126)
        .chain(704..=710)
        .chain(1204..=1206)
        .chain(1339..=1340)
    {
        assert!(
            !catalog
                .iter()
                .find(|entry| entry.id == id)
                .expect("pending reserved control")
                .done
        );
    }
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
