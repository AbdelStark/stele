//! RFC-0008 A5 §2: deterministic rank-two prefix projection of canonical K limbs.
use super::{eq, reserve, zeros, Error};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_pcs::Source;

pub(super) struct Piece<K> {
    pub(super) id: u8,
    pub(super) a: Vec<K>,
    pub(super) b: Vec<K>,
}
impl<K: ChallengeField> Piece<K> {
    // Actual producer scalar, computed before binding/querying any piece.
    pub(super) fn value(&self, message: &[M31]) -> K {
        let mut sum = K::from_i64(0);
        for (row, a) in message.chunks_exact(self.b.len()).zip(&self.a) {
            for (limb, b) in row.iter().zip(&self.b) {
                sum = sum + *a * *b * K::from_i64(i64::from(limb.as_u32()));
            }
        }
        sum
    }
}
pub(super) fn pieces<K: ChallengeField>(
    source: &Source<K>,
    point: &[K],
    real: usize,
) -> Result<Vec<Piece<K>>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let ell = source.rows().trailing_zeros() as usize;
    let width = source.columns() / K::DEGREE;
    if point.len() != ell + width.trailing_zeros() as usize
        || real == 0
        || real > source.rows().checked_mul(width).ok_or(Error::Capacity)?
    {
        return Err(Error::Statement);
    }
    let a = eq(&point[..ell])?;
    let e = eq(&point[ell..])?;
    let (q, s) = (real / width, real % width);
    let mut basis = [K::from_i64(0); 8];
    for (i, value) in basis[..K::DEGREE].iter_mut().enumerate() {
        let mut bytes = [0; 32];
        bytes[4 * i] = 1;
        *value = K::from_le_bytes(
            K::Bytes::try_from(&bytes[..4 * K::DEGREE]).map_err(|_| Error::Capacity)?,
        )
        .ok_or(Error::Fraction(
            stele_lookup::fraction::Error::NoncanonicalField,
        ))?;
    }
    let mut pieces = reserve(2)?;
    // Structural conditions only: zero weights and zero scalar values never omit a piece.
    for id in 0..2u8 {
        if (id == 0 && q == 0) || (id == 1 && s == 0) {
            continue;
        }
        let mut rows = zeros(source.rows())?;
        for (u, row) in rows.iter_mut().enumerate() {
            if (id == 0 && u < q) || (id == 1 && u == q) {
                *row = a[u];
            }
        }
        let mut columns = zeros(source.columns())?;
        for (v, weight) in e.iter().enumerate() {
            if id == 0 || v < s {
                for i in 0..K::DEGREE {
                    columns[v * K::DEGREE + i] = *weight * basis[i];
                }
            }
        }
        pieces.push(Piece {
            id,
            a: rows,
            b: columns,
        });
    }
    Ok(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Debug;
    use stele_field::{Field, Serialize, OM31, QM31};

    fn parity<K: ChallengeField + Eq + Debug>()
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let mut seed = 307252u64;
        let mut word = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            M31::from_i64((seed % 2_147_483_646 + 1) as i64)
        };
        let decode = |limbs: &[M31]| {
            let mut bytes = [0u8; 32];
            for (dest, limb) in bytes.chunks_exact_mut(4).zip(limbs) {
                dest.copy_from_slice(&limb.to_le_bytes());
            }
            K::from_le_bytes(
                K::Bytes::try_from(&bytes[..4 * K::DEGREE])
                    .ok()
                    .expect("width"),
            )
            .expect("canonical limbs")
        };
        let mut checked = 0;
        for k in 0..=4u8 {
            let n = 1usize << k;
            for ell in 0..=k {
                let source = Source::<K>::new(
                    7,
                    ell,
                    k - ell + K::DEGREE.trailing_zeros() as u8,
                    1,
                    [0; 32],
                )
                .expect("physical limb geometry; no certificate authority");
                let width = n >> ell;
                for real in 1..=n {
                    for trial in 0..80 {
                        // Every physical tail is nonzero; only the logical mask may remove it.
                        let message: Vec<_> = (0..n * K::DEGREE).map(|_| word()).collect();
                        let point: Vec<_> = (0..k)
                            .map(|_| {
                                if trial < 2 {
                                    K::from_i64(trial)
                                } else {
                                    decode(&(0..K::DEGREE).map(|_| word()).collect::<Vec<_>>())
                                }
                            })
                            .collect();
                        let actual = pieces(&source, &point, real).expect("prefix pieces");
                        let (q, tail) = (real / width, real % width);
                        assert_eq!(actual.len(), usize::from(q > 0) + usize::from(tail > 0));
                        let mut expected = [K::from_i64(0); 2];
                        for i in 0..real {
                            // Direct MSB Boolean equality product, independent of eq_table.
                            let mut weight = K::from_i64(1);
                            for (bit, x) in point.iter().enumerate() {
                                weight = weight
                                    * if i & (1 << (usize::from(k) - 1 - bit)) == 0 {
                                        K::from_i64(1) - *x
                                    } else {
                                        *x
                                    };
                            }
                            let value = decode(&message[i * K::DEGREE..(i + 1) * K::DEGREE]);
                            let piece = usize::from(i / width == q);
                            expected[piece] = expected[piece] + weight * value;
                        }
                        for piece in actual {
                            assert_eq!(piece.value(&message), expected[usize::from(piece.id)]);
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 10_320);
    }
    #[test]
    fn matches_reference_qm31_lookup_prefix_functionals() {
        parity::<QM31>();
    }
    #[test]
    fn matches_reference_om31_lookup_prefix_functionals() {
        parity::<OM31>();
    }
}
