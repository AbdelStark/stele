//! RFC-0013 A5 / RFC-0008 A7. Seeded genuine private M' windows, including the top source.
use super::*;
use std::collections::BTreeMap;

#[test]
#[ignore = "requires an allocated H100"]
fn matches_reference_original_gkr_mask_windows_on_h100() {
    let dev = Device::new().unwrap();
    assert!(dev.name.contains("H100"));
    let (mut steps, mut masks, mut blocks, mut rounds) = (0, 0, 0, 0);
    for case in 0..CASES {
        observe(case, |step| {
            let input = step.construction()?;
            let mut geometry = BTreeMap::new();
            for &[_, id, rows, cols, ..] in input
                .private_windows
                .iter()
                .flatten()
                .chain(input.column_origins.iter().flatten().flatten())
            {
                if let Some(old) = geometry.insert(id, (rows, cols)) {
                    assert_eq!(old, (rows, cols));
                }
            }
            for raw in [false, true] {
                let mut owners = BTreeMap::new();
                for (&id, &(rows, cols)) in &geometry {
                    let message = (step.private_message)(id).unwrap();
                    let upload = if raw {
                        OriginalMessage::upload_raw
                    } else {
                        OriginalMessage::upload
                    };
                    owners.insert(
                        id as u64,
                        upload(&dev, id as u64, rows, cols, message).unwrap(),
                    );
                }
                let columns = step.leaf.then_some(input.column_origins.as_slice());
                let build = |views: &[Vec<[usize; 6]>]| {
                    dev.build_gkr_private(&input, columns, views, &owners, PrivateChild::Host, raw)
                };
                if case == 0 && !raw {
                    let mut wrong = input.private_windows.clone();
                    wrong.iter_mut().flatten().next().unwrap()[4] = usize::MAX;
                    assert!(build(&wrong).is_err());
                }
                let (mut state, w) = build(&input.private_windows).unwrap();
                assert_eq!((w.mask_bytes, w.block_mask_bytes), (0, 0));
                let windows: Vec<_> = input.private_windows.iter().flatten().collect();
                assert_eq!(w.mask_views + w.block_views, windows.len());
                assert_eq!(
                    w.mask_view_bytes + w.block_view_bytes,
                    windows.iter().map(|v| 4 * v[5]).sum()
                );
                masks += w.mask_views;
                blocks += w.block_views;
                let mut cpu = step.reference()?;
                assert_eq!(state.tables().unwrap(), tables(&cpu));
                for r in step.point {
                    assert_eq!(state.round().unwrap(), cpu.round().unwrap());
                    state.fold(*r).unwrap();
                    cpu.fold(*r).unwrap();
                    assert_eq!(state.tables().unwrap(), tables(&cpu));
                    rounds += 1;
                }
                let got = state
                    .tables()
                    .unwrap()
                    .iter()
                    .map(|(x, _)| x[0])
                    .collect::<Vec<_>>();
                let want = cpu.tables().map(|(x, _)| x[0]).collect::<Vec<_>>();
                gkr::check_finals(step, &want, &got).unwrap();
                steps += 1;
            }
            Ok(())
        });
    }
    assert!(steps > 2 * CASES && masks > steps && blocks > 0 && rounds > steps);
    eprintln!("private_gkr_statements={CASES} raw_private_statements={CASES} representations={steps} mask_views={masks} block_views={blocks} checked_rounds={rounds} bad_window_controls=1");
}

#[path = "private_source_check.rs"]
mod check;

#[test]
fn matches_reference_every_private_gkr_source_window_before_cuda() {
    let mut checked = 0;
    for case in 0..32 {
        observe(case, |step| {
            checked += check::check(step, &step.construction()?).0;
            Ok(())
        });
    }
    assert!(checked > 32);
    eprintln!("host_private_gkr_statements=32 compared_original_windows={checked}");
}
