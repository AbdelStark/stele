//! RFC-0014 §5: malformed or incompletely executed shape inventories cannot pass.
use stele_masked_gpu_bench::{cpu, inventory::Inventory, K};

const RECORD: &str = "shape gkr_leaf field=4 vars=28 degree=5 masks=-,0,25 terms=0.1.2,- compact=1";

#[test]
fn accepts_mask_order_and_explicit_domain_reduction() {
    let inventory =
        Inventory::parse(&format!("masked-shapes-v1 1\n{RECORD}\n")).expect("valid inventory");
    assert_eq!(inventory.len(), 1);
    let case = inventory.case(0, 9);
    assert_eq!(case.original_variables, 28);
    assert!(case.compact);
    assert_eq!(case.shape.n, 4); // Original coordinates 0, 24, 25, 27.
    assert_eq!(case.shape.factors[1].mask.as_ref().map(|m| m.1), Some(0));
    assert_eq!(case.shape.factors[2].mask.as_ref().map(|m| m.1), Some(2));
    assert_eq!(case.shape.terms.len(), 2);
}

#[test]
fn matches_reference_deterministic_base_extension_and_mixed_cases() {
    let inventory =
        Inventory::parse(&format!("masked-shapes-v1 1\n{RECORD}\n")).expect("valid inventory");
    for index in 0..3 {
        let a = inventory.case(index, 42);
        let b = inventory.case(index, 42);
        assert_eq!(a.shape.factors[0].x.is_base(), index == 0 || index == 2);
        assert_eq!(a.shape.factors[1].x.is_base(), index == 0);
        let mut a = cpu(&a.shape);
        let mut b = cpu(&b.shape);
        for round in 0..4 {
            assert_eq!(a.round().expect("round"), b.round().expect("round"));
            let c = stele_masked_gpu_bench::challenge(round);
            a.fold(c).expect("fold");
            b.fold(c).expect("fold");
        }
        let finals = |s: &stele_reductions::zk::claims::bench::Masked<K>| {
            s.tables().map(|(x, _)| x[0]).collect::<Vec<_>>()
        };
        assert_eq!(finals(&a), finals(&b));
    }
}

#[test]
fn rejects_incomplete_or_malformed_inventory() {
    for input in [
        String::new(),
        "masked-shapes-v1 0\n".into(),
        format!("masked-shapes-v1 2\n{RECORD}\n"),
        format!("masked-shapes-v1 1\n{RECORD}\n{RECORD}\n"),
        format!("masked-shapes-v1 1\n{RECORD} witness=7\n"),
    ] {
        assert!(Inventory::parse(&input).is_err(), "{input}");
    }
    for (from, to) in [
        ("field=4", "field=8"),
        ("vars=28", "vars=0"),
        ("degree=5", "degree=32"),
        ("masks=-,0,25", "masks=-,0,28"),
        ("terms=0.1.2,-", "terms=0.1.3,-"),
        ("compact=1", "compact=2"),
    ] {
        assert!(Inventory::parse(&format!(
            "masked-shapes-v1 1\n{}\n",
            RECORD.replace(from, to)
        ))
        .is_err());
    }
}

#[test]
fn accepts_unmasked_first_round_before_a_later_mask() {
    let text =
        "masked-shapes-v1 1\nshape relation field=4 vars=8 degree=2 masks=6 terms=0 compact=0\n";
    let case = Inventory::parse(text).expect("valid later mask").case(0, 7);
    assert_eq!(case.shape.n, 4); // Original coordinates 0, 5, 6, 7.
    assert_eq!(case.shape.factors[0].mask.as_ref().map(|m| m.1), Some(2));
}
