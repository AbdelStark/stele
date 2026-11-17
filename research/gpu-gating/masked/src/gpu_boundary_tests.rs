//! RFC-0014 §5/§7: actual H100 field-copy/source kernels and full-width hash words.
use super::*;
use crate::boundary_cases::{fixture, Op, CASES, OPS, SEED};

#[test]
#[ignore = "requires an explicitly allocated H100 and an external deadline"]
fn matches_reference_copy_and_source_boundaries_on_h100() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    for case in 0..CASES {
        eprintln!("boundary_case_start={case}");
        for op in OPS {
            for raw in [false, true] {
                let c = fixture(op, case, raw);
                let [a, b, d] = c.args.map(u64::from);
                let input = dev.stream.clone_htod(&c.input).unwrap();
                let mut initial = vec![0xdeadbeef; c.expected.len()];
                match op {
                    Op::Duplicate => initial[..c.input.len()].copy_from_slice(&c.input),
                    Op::BitReverse | Op::Forward | Op::Inverse | Op::Scale => {
                        let len = initial.len();
                        initial.copy_from_slice(&c.input[..len]);
                    }
                    _ => {}
                }
                let output = dev.stream.clone_htod(&initial).unwrap();
                let (src, dst) = (dev.ptr(&input), dev.ptr(&output));
                let name = match op {
                    Op::Mask => "mask_kernel",
                    Op::Tile => "tile_kernel",
                    Op::Duplicate => "dup_kernel",
                    Op::Transpose => "transpose_kernel",
                    Op::BitReverse => "bitrev_kernel",
                    Op::Forward | Op::Inverse => "level_kernel",
                    Op::Scale => "scale_kernel",
                    Op::Leaf => "leaf_kernel",
                    Op::Node => "node_kernel",
                };
                let function = dev.function(name).unwrap();
                let mut launch = dev.stream.launch_builder(&function);
                let prefix = if matches!(op, Op::Leaf | Op::Node) {
                    Some(
                        dev.stream
                            .clone_htod(&c.input[..43].iter().map(|w| *w as u8).collect::<Vec<_>>())
                            .unwrap(),
                    )
                } else {
                    None
                };
                // SAFETY: RFC-0014 §5 fixtures provide the exact input/output extents;
                // all pointers stay live through the single ordered stream/readback.
                unsafe {
                    match op {
                        Op::Mask => launch
                            .arg(&dst)
                            .arg(&(src + 4 * b))
                            .arg(&src)
                            .arg(&(b as i32))
                            .arg(&(a as i32))
                            .arg(&(1u64 << a))
                            .launch(dev.grid(1usize << a)),
                        Op::Tile => launch
                            .arg(&dst)
                            .arg(&src)
                            .arg(&(a - 1))
                            .arg(&(2 * a))
                            .launch(dev.grid(2 * a as usize)),
                        Op::Duplicate => launch.arg(&dst).arg(&a).launch(dev.grid(a as usize)),
                        Op::Transpose => {
                            launch
                                .arg(&src)
                                .arg(&dst)
                                .arg(&a)
                                .arg(&b)
                                .launch(LaunchConfig {
                                    grid_dim: (b.div_ceil(32) as u32, a.div_ceil(32) as u32, 1),
                                    block_dim: (32, 8, 1),
                                    shared_mem_bytes: 0,
                                })
                        }
                        Op::BitReverse => launch
                            .arg(&dst)
                            .arg(&a)
                            .arg(&(b as i32))
                            .launch(dev.grid((a << b) as usize)),
                        Op::Forward | Op::Inverse => launch
                            .arg(&dst)
                            .arg(&(src + 4 * a * b))
                            .arg(&d)
                            .arg(&a)
                            .arg(&b)
                            .arg(&i32::from(matches!(op, Op::Inverse)))
                            .launch(dev.grid(((b / (2 * d)) * d.div_ceil(2) * a) as usize)),
                        Op::Scale => launch
                            .arg(&dst)
                            .arg(&(b as u32))
                            .arg(&a)
                            .launch(dev.grid(a as usize)),
                        Op::Leaf => launch
                            .arg(&(src + 4 * 68))
                            .arg(&a)
                            .arg(&b)
                            .arg(&dev.ptr(prefix.as_ref().unwrap()))
                            .arg(&(src + 4 * 43))
                            .arg(&(src + 4 * 51))
                            .arg(&c.input[67])
                            .arg(&dst)
                            .launch(dev.grid(b as usize)),
                        Op::Node => launch
                            .arg(&(src + 4 * 43))
                            .arg(&dst)
                            .arg(&a)
                            .arg(&(b as u32))
                            .arg(&dev.ptr(prefix.as_ref().unwrap()))
                            .launch(dev.grid(a as usize)),
                    }
                }
                .expect("boundary launch");
                let actual = dev.stream.clone_dtoh(&output).unwrap();
                assert_eq!(actual, c.expected, "case={case} op={op:?} raw={raw}");
            }
        }
        eprintln!("boundary_case_pass={case}");
    }
    eprintln!(
        "boundary_device_cases={CASES} operations=10 representations=2 seed={SEED} device={}",
        dev.name
    );
}
