//! RFC-0008 A7 / RFC-0014 §5: actual GKR domains, rounds and all compact finals.
//! The observed proof uses CPU values; CUDA comparisons supply no GPU-proof credit.
use super::*;
use crate::{
    gkr,
    gkr_cases::{observe, CASES, SEED},
};
use stele_reductions::zk::claims::bench::Masked;

fn tables(reference: &Masked<K>) -> Tables {
    reference
        .tables()
        .map(|(x, r)| (x.to_vec(), r.to_vec()))
        .collect()
}

fn table_bytes(state: &DeviceMasked<'_>) -> usize {
    4 * state
        .factors
        .iter()
        .map(|f| f.x.slice().len() + f.r.as_ref().map_or(0, |r| r.slice().len()))
        .sum::<usize>()
}

fn read_tables(state: &DeviceMasked<'_>, downloaded: &mut usize) -> Tables {
    *downloaded += table_bytes(state);
    state.tables().expect("canonical device tables")
}

#[test]
#[ignore = "requires an explicitly allocated H100 and an external deadline"]
fn matches_reference_genuine_gkr_on_h100() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    let mut totals = [0; 4];
    let mut representations = 0;
    let mut rounds = 0;
    for case in 0..CASES {
        eprintln!("gkr_case_start={case} seed={}", SEED + 2 * case as u64);
        let seen = observe(case, |step| {
            let shape = gkr::shape(&step.reference()?).expect("genuine production tables");
            let input_bytes: usize = shape
                .factors
                .iter()
                .flat_map(|f| std::iter::once(&f.x).chain(f.mask.as_ref().map(|(r, _)| r)))
                .map(|s| match s {
                    Source::Column { values } => 4 * values.len(),
                    Source::Tile { period } => 16 * period.len(),
                    _ => unreachable!("the production adapter only packs existing tables"),
                })
                .sum();
            for raw in [false, true] {
                let mut reference = step.reference()?;
                let (mut state, _, _) = dev.build(&shape).expect("upload production factors");
                let initial = state.device_buffer_bytes();
                let mut retained = initial;
                let mut downloaded = 0;
                let mut raw_transfers = 0;
                assert_eq!(read_tables(&state, &mut downloaded), tables(&reference));
                if raw {
                    let used = state.coef.len();
                    raw_transfers += 8 * used;
                    super::round_tests::lift(&dev, &mut state.coef, used);
                }
                for point in step.point {
                    if raw {
                        raw_transfers += 2 * table_bytes(&state);
                        for factor in &mut state.factors {
                            for table in std::iter::once(&mut factor.x).chain(factor.r.iter_mut()) {
                                let used = state.len * if table.is_base() { 1 } else { 4 };
                                let (Buf::Base(words) | Buf::Ext(words)) = table;
                                super::round_tests::lift(&dev, words, used);
                            }
                        }
                    }
                    assert_eq!(
                        state.round().unwrap(),
                        reference.round().unwrap(),
                        "case={case} step={} raw={raw}",
                        step.step
                    );
                    state.fold(*point).unwrap();
                    reference.fold(*point).unwrap();
                    retained = retained.max(state.device_buffer_bytes());
                    assert_eq!(read_tables(&state, &mut downloaded), tables(&reference));
                    rounds += 1;
                }
                let expected: Vec<_> = reference.tables().map(|(x, _)| x[0]).collect();
                let actual: Vec<_> = read_tables(&state, &mut downloaded)
                    .iter()
                    .map(|(x, _)| x[0])
                    .collect();
                gkr::check_finals(step, &expected, &actual)
                    .expect("all compact/expanded/routed finals");
                eprintln!("gkr_state case={case} step={} raw={raw} variables={} input_bytes={input_bytes} descriptor_upload_bytes={} round_upload_bytes={} table_download_bytes={downloaded} round_download_bytes={} raw_transfer_bytes={raw_transfers} initial_buffer_bytes={initial} max_retained_bytes={retained}", step.step, shape.n, state.descriptor_upload_bytes(), shape.n * state.round_upload_bytes(), 16 * shape.n * (shape.degree + 1));
                representations += 1;
            }
            Ok(())
        });
        for (total, n) in totals.iter_mut().zip(seen) {
            *total += n;
        }
        eprintln!(
            "gkr_case_pass={case} first={} interior={} leaf={} compact={}",
            seen[0], seen[1], seen[2], seen[3]
        );
    }
    assert!(totals.iter().all(|n| *n > 0));
    assert_eq!(representations, 2 * totals[..3].iter().sum::<usize>());
    assert!(rounds > representations);
    eprintln!("gkr_device_statements={CASES} first={} interior={} leaf={} compact={} representations={representations} rounds={rounds} seed={SEED} device={}", totals[0],totals[1],totals[2],totals[3],dev.name);
}

#[test]
#[ignore = "requires an allocated H100"]
fn matches_reference_borrowed_gkr_construction_on_h100() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    let mut repeated_rounds = 0;
    let mut period_transitions = 0;
    let mut total = 0;
    let mut representations = 0;
    for case in 0..CASES {
        let seen = observe(case, |step| {
            let input = step.construction()?;
            for raw in [false, true] {
                let mut reference = step.reference()?;
                let (mut state, work) = if raw {
                    dev.build_gkr_raw(&input)
                } else {
                    dev.build_gkr_bounded(&input)
                }
                .expect("construct from original inputs");
                assert!(work.input_bytes > 0 && work.descriptor_bytes > 0);
                assert_eq!(
                    work.input_bytes,
                    work.equality_bytes
                        + work.block_challenge_bytes
                        + work.block_mask_bytes
                        + work.column_bytes
                        + work.mask_bytes
                        + work.layer_upload_bytes
                        + work.public_challenge_bytes
                        + work.public_table_bytes
                        + work.selector_bytes
                );
                assert_eq!(
                    work.descriptor_bytes,
                    work.coordinate_bytes + work.term_bytes
                );
                assert!(state.device_buffer_bytes() <= work.peak_bytes);
                assert_eq!(
                    state.tables().unwrap(),
                    tables(&reference),
                    "initial case={case} step={} raw={raw}",
                    step.step
                );
                for point in step.point {
                    for factor in &state.factors {
                        if let Some(p) = factor.x.period(state.len) {
                            repeated_rounds += 1;
                            period_transitions += usize::from(p == state.len / 2);
                        }
                    }
                    assert_eq!(
                        state.round().unwrap(),
                        reference.round().unwrap(),
                        "round case={case} step={} raw={raw}",
                        step.step
                    );
                    state.fold(*point).unwrap();
                    reference.fold(*point).unwrap();
                    assert!(state.device_buffer_bytes() <= work.peak_bytes);
                    assert_eq!(
                        state.tables().unwrap(),
                        tables(&reference),
                        "fold case={case} step={} raw={raw}",
                        step.step
                    );
                }
                let expected: Vec<_> = reference.tables().map(|(x, _)| x[0]).collect();
                let actual: Vec<_> = state.tables().unwrap().iter().map(|(x, _)| x[0]).collect();
                gkr::check_finals(step, &expected, &actual).unwrap();
                representations += 1;
            }
            Ok(())
        });
        total += seen[..3].iter().sum::<usize>();
        if (case + 1) % 100 == 0 {
            eprintln!("constructed_gkr_cases_passed={} steps={total}", case + 1);
        }
    }
    assert!(period_transitions > 0 && repeated_rounds > period_transitions);
    assert_eq!(total, 2728);
    assert_eq!(representations, 2 * total);
    eprintln!("periodic_rounds={repeated_rounds} period_transitions={period_transitions} constructed_gkr_statements={CASES} steps={total} representations={representations} device={}", dev.name);
}

#[test]
fn matches_reference_original_gkr_gather_across_mask_columns() {
    // Exercise the exact CUDA expression on a CPU. Unused mask entries have
    // distinct poisoned values, and each projected read crosses a row boundary.
    let code = format!(
        r#"#include <cstdio>
        #define __device__
        #define __global__
        #define __forceinline__ inline
        {}
        #define GRID_STRIDE(i,n) for(u64 i=0;i<(n);++i)
        {}
        int main() {{
            u32 data[64] = {{}}, out[16] = {{}};
            u32 shifts[] = {{0, 2, 0}};
            for (u32 raw=0; raw<2; raw++) {{
                for (u32 i=0; i<64; ++i) data[i] = 900+i;
                for (u32 x=0; x<16; ++x) data[(x/4)*8+x%4]=17+x+raw*2147483647u;
                gkr_build_span(out,1,data,shifts,3,7,2147483640u,8,0,8,16,3,2,nullptr);
                std::fwrite(out,sizeof(u32),16,stdout);
            }}
        }}"#,
        crate::host_probe::helpers(),
        include_str!("gkr_build.cu")
    );
    let expected: Vec<_> = (0u32..32)
        .map(|i| {
            let x = ((i & 1) << 2) | (((i >> 2) & 1) << 1) | (i & 1);
            17 + 3 + x - 7
        })
        .collect();
    assert_eq!(crate::host_probe::run(&code, &[]), expected);
}
