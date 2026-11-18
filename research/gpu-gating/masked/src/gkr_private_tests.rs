//! RFC-0008 A7. Equal extents never permit exchanging occurrence and shared-layer windows.
use super::*;
use crate::gkr_build::{FactorPlan, InputKind, TablePlan};

fn test_span(op: Op, begin: u32, data: Vec<u32>) -> Span {
    Span {
        period: 16,
        begin,
        end: 16,
        op,
        arg: 2,
        shifts: vec![1],
        data,
        kind: InputKind::Mask,
        original: None,
    }
}

fn test_plan() -> Plan {
    let block = FactorPlan {
        values: TablePlan {
            base: false,
            spans: vec![test_span(Op::Block, 0, vec![5; 8])],
        },
        mask: None,
    };
    let mask = FactorPlan {
        values: TablePlan {
            base: true,
            spans: vec![],
        },
        mask: Some((
            TablePlan {
                base: true,
                spans: vec![
                    test_span(Op::GatherBase, 0, vec![6; 2]),
                    test_span(Op::GatherBase, 8, vec![7; 2]),
                ],
            },
            0,
        )),
    };
    Plan {
        len: 16,
        degree: 2,
        terms: vec![],
        factors: vec![block, mask],
    }
}

#[test]
fn accepts_permuted_private_mask_windows_and_keeps_public_challenge() {
    let windows = vec![
        vec![[0, 3, 8, 8, 3, 4]],
        vec![[8, 1, 8, 8, 7, 2], [0, 0, 8, 8, 1, 2]],
    ];
    let plan = test_plan().original_masks(&windows).unwrap();
    let span = &plan.factors[0].values.spans[0];
    assert!(matches!(span.op, Op::OriginalBlock));
    assert_eq!(span.data, vec![5; 4]);
    assert_eq!(plan.factors[0].values.storage_len(plan.len), 2);
    let masks = &plan.factors[1].mask.as_ref().unwrap().0.spans;
    assert_eq!(masks[0].original, Some(windows[1][1]));
    assert_eq!(masks[1].original, Some(windows[1][0]));
    assert!(masks
        .iter()
        .all(|m| m.data.is_empty() && matches!(m.op, Op::OriginalBase)));
}

#[test]
fn rejects_missing_short_and_misaligned_private_windows() {
    let good = vec![
        vec![[0, 3, 8, 8, 3, 4]],
        vec![[0, 0, 8, 8, 1, 2], [8, 1, 8, 8, 7, 2]],
    ];
    for (factor, leg, field, value) in [(0, 0, 5, 2), (0, 0, 4, 13), (1, 1, 0, 0), (1, 0, 2, 1)] {
        let mut bad = good.clone();
        bad[factor][leg][field] = value;
        assert!(test_plan().original_masks(&bad).is_err());
    }
    assert!(test_plan().original_masks(&good[..1]).is_err());
}
