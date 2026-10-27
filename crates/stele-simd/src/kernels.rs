//! Shared lane-wise quadratic identities (RFC-0003 §2/A1); no horizontal sums.
macro_rules! kernels {
    ($feature:literal, $width:expr, $v:ty) => {
        #[target_feature(enable=$feature)]
        unsafe fn cm(a: [$v; 2], b: [$v; 2]) -> [$v; 2] {
            // SAFETY: RFC-0003 §2: caller enables the feature; operands are canonical lanes.
            unsafe {
                let ac = mul(a[0], b[0]);
                let bd = mul(a[1], b[1]);
                [
                    sub(ac, bd),
                    sub(sub(mul(add(a[0], a[1]), add(b[0], b[1])), ac), bd),
                ]
            }
        }
        #[target_feature(enable=$feature)]
        pub(crate) unsafe fn m31(op: crate::Op, a: &[u32; 16], b: &[u32; 16]) -> [u32; 16] {
            let mut out = [0; 16];
            // SAFETY: RFC-0003 §6/INV-8: each unaligned load/store stays inside 16 lanes;
            // the feature is enabled and canonical() reduces the checked lazy inputs.
            unsafe {
                for i in (0..16).step_by($width) {
                    let x = canonical(load(a.as_ptr().add(i)));
                    let y = canonical(load(b.as_ptr().add(i)));
                    let z = match op {
                        crate::Op::Add => add(x, y),
                        crate::Op::Sub => sub(x, y),
                        crate::Op::Mul => mul(x, y),
                    };
                    store(out.as_mut_ptr().add(i), z);
                }
            }
            out
        }
        #[target_feature(enable=$feature)]
        pub(crate) unsafe fn qm31(
            op: crate::Op,
            a: &[[u32; 16]; 4],
            b: &[[u32; 16]; 4],
        ) -> [[u32; 16]; 4] {
            let mut out = [[0; 16]; 4];
            // SAFETY: RFC-0003 §2/A1/INV-8: feature enabled; fixed-size column accesses
            // are in bounds and every arithmetic helper returns canonical lanes.
            unsafe {
                for i in (0..16).step_by($width) {
                    let x = a.map(|c| canonical(load(c.as_ptr().add(i))));
                    let y = b.map(|c| canonical(load(c.as_ptr().add(i))));
                    let z = match op {
                        crate::Op::Add => std::array::from_fn(|j| add(x[j], y[j])),
                        crate::Op::Sub => std::array::from_fn(|j| sub(x[j], y[j])),
                        crate::Op::Mul => {
                            let ac = cm([x[0], x[1]], [y[0], y[1]]);
                            let bd = cm([x[2], x[3]], [y[2], y[3]]);
                            let cross = cm(
                                [add(x[0], x[2]), add(x[1], x[3])],
                                [add(y[0], y[2]), add(y[1], y[3])],
                            );
                            [
                                add(ac[0], sub(add(bd[0], bd[0]), bd[1])),
                                add(ac[1], add(bd[0], add(bd[1], bd[1]))),
                                sub(sub(cross[0], ac[0]), bd[0]),
                                sub(sub(cross[1], ac[1]), bd[1]),
                            ]
                        }
                    };
                    for j in 0..4 {
                        store(out[j].as_mut_ptr().add(i), z[j]);
                    }
                }
            }
            out
        }
    };
}
