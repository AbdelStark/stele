//! RFC-0028 §2.1 `Def::Contraction` over typed columns: one integer dot product per output
//! entry, exact over `Z`. A matmul's summed bits are the low index bits of both operands,
//! so each output reads two contiguous rows.
use super::{ColumnSlice, Ref};
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rayon::prelude::*;

/// Non-contiguous operands precompute their summed-bit indices up to this many bits.
const OFFSET_BITS: u8 = 20;
/// Output entries per parallel task.
#[cfg(feature = "std")]
const CHUNK: usize = 256;

/// One stored integer type of a [`ColumnSlice`].
trait Elem: Copy + Sync + Into<i64> {
    /// Largest magnitude of the type, or `None` when the values are scanned.
    const BOUND: Option<u64>;
    /// The value as `i32`: exact whenever the magnitude bound admits the `i32` path.
    fn narrow(self) -> i32;
}
macro_rules! elem {
    ($($t:ty => $bound:expr),*) => {$(
        impl Elem for $t {
            const BOUND: Option<u64> = $bound;
            #[inline]
            fn narrow(self) -> i32 {
                self as i32
            }
        }
    )*};
}
elem!(i8 => Some(1 << 7), u8 => Some(u8::MAX as u64), i16 => Some(1 << 15),
      u16 => Some(u16::MAX as u64), i32 => None, u32 => None, i64 => None);

fn bound<T: Elem>(values: &[T]) -> u64 {
    T::BOUND.unwrap_or_else(|| {
        values
            .iter()
            .map(|v| Into::<i64>::into(*v).unsigned_abs())
            .max()
            .unwrap_or(0)
    })
}

/// `out[x] = Σ_y lhs[lhs.index(x | y << free)] · rhs[rhs.index(x | y << free)]` for every
/// `x` in `{0,1}^free`, over the integers. `None` when a sum may leave `i64`, an index
/// leaves its column, or the shape is outside the fast paths: the caller then uses its
/// checked wide loop.
pub fn contract(
    free: u8,
    summed: u8,
    lhs: (&Ref, ColumnSlice<'_>),
    rhs: (&Ref, ColumnSlice<'_>),
) -> Option<Vec<i64>> {
    macro_rules! typed {
        ($slice:expr, $v:ident => $body:expr) => {
            match $slice {
                ColumnSlice::I8($v) => $body,
                ColumnSlice::U8($v) => $body,
                ColumnSlice::I16($v) => $body,
                ColumnSlice::U16($v) => $body,
                ColumnSlice::I32($v) => $body,
                ColumnSlice::U32($v) => $body,
                ColumnSlice::I64($v) => $body,
            }
        };
    }
    typed!(lhs.1, a => typed!(rhs.1, b => run(free, summed, (lhs.0, a), (rhs.0, b))))
}

fn run<A: Elem, B: Elem>(
    free: u8,
    summed: u8,
    (lr, a): (&Ref, &[A]),
    (rr, b): (&Ref, &[B]),
) -> Option<Vec<i64>> {
    let n_out = 1usize.checked_shl(u32::from(free))?;
    let n_sum = 1usize.checked_shl(u32::from(summed))?;
    // Bounds reach 2^63 each: the product is checked, never wrapped.
    let magnitude = u128::from(bound(a))
        .checked_mul(u128::from(bound(b)))
        .and_then(|m| m.checked_mul(n_sum as u128))?;
    if magnitude > i64::MAX as u128 {
        return None;
    }
    let narrow = magnitude <= i32::MAX as u128;
    // Summed bit j is index bit j of the operand and no higher index bit reads a summed
    // bit: its row is contiguous.
    let summed_bits = usize::from(free)..usize::from(free) + usize::from(summed);
    let low = |r: &Ref| {
        r.vars.len() >= usize::from(summed)
            && r.vars[..usize::from(summed)]
                .iter()
                .enumerate()
                .all(|(j, &v)| usize::from(v) == usize::from(free) + j)
            && r.vars[usize::from(summed)..]
                .iter()
                .all(|&v| !summed_bits.contains(&usize::from(v)))
    };
    let contiguous = low(lr) && low(rr);
    let offsets: Vec<(usize, usize)> = if contiguous {
        Vec::new()
    } else if summed <= OFFSET_BITS {
        (0..n_sum as u64)
            .map(|y| (lr.index(y << free), rr.index(y << free)))
            .collect()
    } else {
        return None;
    };
    let row = |x: usize| -> Option<i64> {
        let (l0, r0) = (lr.index(x as u64), rr.index(x as u64));
        if !contiguous {
            return offsets.iter().try_fold(0i64, |sum, &(l, r)| {
                Some(sum + Into::<i64>::into(*a.get(l0 | l)?) * Into::<i64>::into(*b.get(r0 | r)?))
            });
        }
        let (a, b) = (a.get(l0..l0 + n_sum)?, b.get(r0..r0 + n_sum)?);
        Some(if narrow {
            let dot: i32 = a.iter().zip(b).map(|(p, q)| p.narrow() * q.narrow()).sum();
            i64::from(dot)
        } else {
            a.iter()
                .zip(b)
                .map(|(p, q)| Into::<i64>::into(*p) * Into::<i64>::into(*q))
                .sum()
        })
    };
    let mut out = alloc::vec![0i64; n_out];
    let fill = |start: usize, chunk: &mut [i64]| -> Option<()> {
        for (j, slot) in chunk.iter_mut().enumerate() {
            *slot = row(start + j)?;
        }
        Some(())
    };
    #[cfg(feature = "std")]
    out.par_chunks_mut(CHUNK)
        .enumerate()
        .try_for_each(|(c, chunk)| fill(c * CHUNK, chunk))?;
    #[cfg(not(feature = "std"))]
    fill(0, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::ColumnId;

    fn reference(
        free: u8,
        summed: u8,
        lhs: (&Ref, ColumnSlice<'_>),
        rhs: (&Ref, ColumnSlice<'_>),
    ) -> Vec<i64> {
        (0..1u64 << free)
            .map(|x| {
                (0..1u64 << summed)
                    .map(|y| {
                        let xy = x | (y << free);
                        lhs.1.at(lhs.0.index(xy)) * rhs.1.at(rhs.0.index(xy))
                    })
                    .sum()
            })
            .collect()
    }

    /// Deterministic values below `2^bits` in magnitude.
    fn values(len: usize, bits: u32, seed: u64) -> Vec<i64> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 33) as i64 % (1 << bits)) - (1 << (bits - 1))
            })
            .collect()
    }

    #[test]
    fn matches_reference_contraction_on_typed_permuted_and_fixed_operands() {
        let (free, summed) = (3u8, 4u8);
        let col = |id: u32, vars: Vec<u8>| Ref {
            column: ColumnId(id),
            vars,
        };
        // Contiguous: summed bits low on both; lhs also reads x bits 0 and 2, rhs x bit 1
        // and a fixed one.
        let rows = (
            col(0, alloc::vec![3, 4, 5, 6, 0, 2]),
            col(1, alloc::vec![3, 4, 5, 6, 1, Ref::FIXED_1]),
        );
        // Permuted: summed bits interleaved with x bits and a fixed zero.
        let mixed = (
            col(0, alloc::vec![0, 3, 6, Ref::FIXED_0, 4, 5]),
            col(1, alloc::vec![5, 4, 2, 3, 6, 1]),
        );
        let (a, b) = (values(64, 7, 1), values(64, 7, 2));
        let a8: Vec<i8> = a.iter().map(|&v| v as i8).collect();
        let b8: Vec<i8> = b.iter().map(|&v| v as i8).collect();
        let a16: Vec<i16> = values(64, 15, 3).iter().map(|&v| v as i16).collect();
        let b32: Vec<i32> = values(64, 30, 4).iter().map(|&v| v as i32).collect();
        let bu8: Vec<u8> = b.iter().map(|&v| v as u8).collect();
        let wide: Vec<i64> = values(64, 40, 5);
        for (l, r) in [&rows, &mixed] {
            let pairs: [(ColumnSlice<'_>, ColumnSlice<'_>); 5] = [
                (ColumnSlice::I8(&a8), ColumnSlice::I8(&b8)),
                (ColumnSlice::I16(&a16), ColumnSlice::U8(&bu8)),
                (ColumnSlice::I16(&a16), ColumnSlice::I32(&b32)),
                (ColumnSlice::I64(&wide), ColumnSlice::I8(&b8)),
                (ColumnSlice::I8(&a8), ColumnSlice::I64(&wide)),
            ];
            for (x, y) in pairs {
                assert_eq!(
                    contract(free, summed, (l, x), (r, y)),
                    Some(reference(free, summed, (l, x), (r, y)))
                );
            }
        }
        // Scalars and empty sums.
        let one = (col(0, alloc::vec![]), col(1, alloc::vec![]));
        assert_eq!(
            contract(
                0,
                0,
                (&one.0, ColumnSlice::I8(&a8[..1])),
                (&one.1, ColumnSlice::I8(&b8[..1]))
            ),
            Some(alloc::vec![i64::from(a8[0]) * i64::from(b8[0])])
        );
    }

    #[test]
    fn rejects_sums_past_i64_and_indices_past_the_column() {
        let r = |id: u32| Ref {
            column: ColumnId(id),
            vars: alloc::vec![0],
        };
        let big = [i64::MAX, i64::MAX];
        assert_eq!(
            contract(
                0,
                1,
                (&r(0), ColumnSlice::I64(&big)),
                (&r(1), ColumnSlice::I64(&big))
            ),
            None
        );
        let short = [1i8];
        assert_eq!(
            contract(
                0,
                1,
                (&r(0), ColumnSlice::I8(&short)),
                (&r(1), ColumnSlice::I8(&short))
            ),
            None
        );
        // The guard itself must not wrap: 4 · (2^63)^2 = 2^128.
        let wide = |id: u32| Ref::identity(ColumnId(id), 2);
        let least = [i64::MIN; 4];
        assert_eq!(
            contract(
                0,
                2,
                (&wide(0), ColumnSlice::I64(&least)),
                (&wide(1), ColumnSlice::I64(&least))
            ),
            None
        );
    }

    #[test]
    fn matches_reference_definition_when_a_higher_index_bit_reads_a_summed_bit() {
        // Index bits 0 and 1 of the left operand both read the summed bit: its row is not
        // contiguous, and the sum is a[0]·b[0] + a[3]·b[1].
        let twice = Ref {
            column: ColumnId(0),
            vars: alloc::vec![0, 0],
        };
        let once = Ref {
            column: ColumnId(1),
            vars: alloc::vec![0],
        };
        assert_eq!(
            contract(
                0,
                1,
                (&twice, ColumnSlice::I64(&[1, 10, 100, 50])),
                (&once, ColumnSlice::I64(&[1, 1]))
            ),
            Some(alloc::vec![51])
        );
    }
}
