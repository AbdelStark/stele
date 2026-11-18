//! RFC-0008 A7 / RFC-0013 A5. Only actual Gin::Leaf and combined member origins can borrow.
use super::*;
use std::collections::BTreeMap;

#[test]
#[ignore = "requires an allocated H100"]
fn matches_reference_original_gkr_gathers_on_h100() {
    let dev = Device::new().unwrap();
    assert!(dev.name.contains("H100"));
    let mut leaves = 0;
    let mut rounds = 0;
    let mut combined = 0;
    let mut top_leaf = 0;
    for case in 0..CASES {
        observe(case, |step| {
            if !step.leaf {
                return Ok(());
            }
            let input = step.construction()?;
            top_leaf += usize::from(step.first);
            combined += usize::from(step.reference()?.is_compact());
            let expected_views = input.column_origins.iter().flatten().flatten().count();
            assert!(expected_views > 0);
            let mut originals = BTreeMap::new();
            for &[_, id, rows, cols, _, _] in input.column_origins.iter().flatten().flatten() {
                let msg = &step.original_messages[id];
                originals.insert(id as u64, (rows, cols, msg.as_slice()));
            }
            for raw in [false, true] {
                let mut owners = BTreeMap::new();
                for (&id, &(rows, cols, message)) in &originals {
                    let upload = if raw {
                        OriginalMessage::upload_raw
                    } else {
                        OriginalMessage::upload
                    };
                    owners.insert(id, upload(&dev, id, rows, cols, message).unwrap());
                }
                if case == 0 && !raw {
                    let empty = BTreeMap::new();
                    assert!(dev
                        .build_gkr_original(&input, &input.column_origins, &empty)
                        .is_err());
                    let mut wrong = input.column_origins.clone();
                    wrong.iter_mut().flatten().flatten().next().unwrap()[4] = usize::MAX;
                    assert!(dev.build_gkr_original(&input, &wrong, &owners).is_err());
                }
                let (mut state, work) = if raw {
                    dev.build_gkr_original_raw(&input, &input.column_origins, &owners)
                } else {
                    dev.build_gkr_original(&input, &input.column_origins, &owners)
                }
                .expect("required resident GKR construction");
                assert_eq!(work.original_views, expected_views);
                assert_eq!(
                    work.original_bytes,
                    input
                        .column_origins
                        .iter()
                        .flatten()
                        .flatten()
                        .map(|d| d[5] * 4)
                        .sum::<usize>()
                );
                if !step.first {
                    assert_eq!(work.column_bytes, 0);
                }
                let mut cpu = step.reference()?;
                assert_eq!(state.tables().unwrap(), tables(&cpu));
                for point in step.point {
                    assert_eq!(state.round().unwrap(), cpu.round().unwrap());
                    state.fold(*point).unwrap();
                    cpu.fold(*point).unwrap();
                    assert_eq!(state.tables().unwrap(), tables(&cpu));
                    rounds += 1;
                }
                let got: Vec<_> = state.tables().unwrap().iter().map(|(x, _)| x[0]).collect();
                let wanted: Vec<_> = cpu.tables().map(|(x, _)| x[0]).collect();
                gkr::check_finals(step, &wanted, &got).unwrap();
                leaves += 1;
            }
            Ok(())
        });
    }
    assert_eq!(leaves, 2 * CASES);
    assert!(combined > 0 && rounds > leaves && top_leaf > 0);
    eprintln!("original_gkr_statements={CASES} leaf_representations={leaves} raw_original_statements={CASES} top_leaf={top_leaf} compact={combined} rounds={rounds} controls=2");
}

#[test]
fn matches_reference_original_gkr_provenance_before_device_access() {
    use stele_reductions::zk::claims::bench::GkrFactor;
    let mut genuine = 0;
    let mut top = 0;
    let mut one_level = 0;
    for case in 0..32 {
        observe(case, |step| {
            let input = step.construction()?;
            assert_eq!(input.factors.len(), input.column_origins.len());
            one_level += usize::from(step.first && step.leaf);
            for (factor, legs) in input.factors.iter().zip(&input.column_origins) {
                let columns = match factor {
                    GkrFactor::Column { values, .. } => vec![*values],
                    GkrFactor::Combined { members, .. } => {
                        members.iter().map(|m| m.values).collect()
                    }
                    _ => Vec::new(),
                };
                assert_eq!(columns.len(), legs.len());
                for (column, leg) in columns.into_iter().zip(legs) {
                    let Some([_, id, rows, cols, at, len]) = *leg else {
                        assert!(step.first && matches!(factor, GkrFactor::Column { .. }));
                        top += 1;
                        continue;
                    };
                    assert!(step.leaf);
                    let m = &step.original_messages[id];
                    assert_eq!(m.len(), rows * cols);
                    assert_eq!(column.len(), len);
                    let width = cols / 2;
                    for (j, &value) in column.iter().enumerate() {
                        let p = at + j;
                        assert_eq!(
                            value,
                            K::from_i64(i64::from(m[p / width * cols + p % width].as_u32()))
                        );
                    }
                    genuine += 1;
                }
            }
            Ok(())
        });
    }
    assert!(genuine > 0 && top > 0);
    eprintln!("host_gkr_original_cases=32 original_legs={genuine} top_legs={top} first_leaf_steps={one_level}");
}
