//! RFC-0013 A2 item 1: hiding-source message layout and the prover's public
//! rank check. Prover-only; the verifier sees neither masks nor this check.
use crate::{Error, Source};
use alloc::vec::Vec;
use stele_field::{Inverse, Serialize, M31};
use stele_hash::mask::{MaskStream, SOURCE_MASK};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};

/// Build `M' = [X | Rm ; S0 | S1]` (`2R × 2C`, row-major) from row-major data `X`
/// (`R = 2^ell`, `C = 2^m`). Masks are read from the seed's stream: `Rm`
/// row-major, then the mask rows row-major. The seed must be fresh and secret.
pub fn hiding_message(
    id: u64,
    ell: u8,
    m: u8,
    data: &[M31],
    seed: &[u8; 32],
) -> Result<Vec<M31>, Error> {
    if ell >= 30 || m >= 30 {
        return Err(Error::UnsupportedSource);
    }
    let (rows, columns) = (1usize << ell, 1usize << m);
    if rows.checked_mul(columns) != Some(data.len()) {
        return Err(Error::MessageShape);
    }
    let total = data.len().checked_mul(4).ok_or(Error::Capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| Error::Capacity)?;
    out.resize(total, M31::ZERO);
    let mut stream = MaskStream::new(seed, SOURCE_MASK, id);
    for (row, x) in data.chunks_exact(columns).enumerate() {
        let target = &mut out[row * 2 * columns..(row + 1) * 2 * columns];
        target[..columns].copy_from_slice(x);
        for value in &mut target[columns..] {
            *value = stream.m31();
        }
    }
    for value in &mut out[rows * 2 * columns..] {
        *value = stream.m31();
    }
    Ok(out)
}

/// The certificate's row weights, a function of the source bytes alone (A9 §3),
/// so an opening's rank check needs no certificate state.
pub(crate) fn certificate_weights<K: ChallengeField>(source: &Source<K>) -> Result<Vec<K>, Error> {
    let mut public = Vec::new();
    public.extend_from_slice(b"stele/v0.1/pcs-certificate/public");
    public.extend_from_slice(&source.bytes());
    let mut t = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
    let mut point = Vec::new();
    for _ in 0..source.rows().trailing_zeros() {
        point.push(
            t.challenge(ChallengeLabel::CertificateWeight)
                .map_err(Error::Transcript)?,
        );
    }
    stele_poly::eq_table(&point).map_err(|_| Error::Capacity)
}

/// A2's rank check: the M31 coordinates of the mask-row parts of every revealed
/// row-coefficient vector must be linearly independent (`D` per vector).
/// The check depends on public coefficients only; failure aborts with MaskRank.
pub(crate) fn check_mask_rank<K: ChallengeField>(
    source: &Source<K>,
    revealed: &[&[K]],
) -> Result<(), Error> {
    let half = source.rows() / 2;
    let mut matrix = Vec::new();
    for a in revealed {
        let masks = a.get(half..).ok_or(Error::FunctionalShape)?;
        for d in 0..K::DEGREE {
            let mut row = Vec::new();
            row.try_reserve_exact(half).map_err(|_| Error::Capacity)?;
            for value in masks {
                let bytes = value.to_le_bytes();
                let limb = bytes.as_ref()[4 * d..4 * d + 4]
                    .try_into()
                    .map_err(|_| Error::NoncanonicalField)?;
                row.push(M31::from_le_bytes(limb).ok_or(Error::NoncanonicalField)?);
            }
            matrix.push(row);
        }
    }
    if rank(&mut matrix) == matrix.len() {
        Ok(())
    } else {
        Err(Error::MaskRank)
    }
}

fn rank(rows: &mut [Vec<M31>]) -> usize {
    let width = rows.first().map_or(0, Vec::len);
    let mut rank = 0;
    for column in 0..width {
        let Some(pivot) = (rank..rows.len()).find(|&i| rows[i][column] != M31::ZERO) else {
            continue;
        };
        rows.swap(rank, pivot);
        // The pivot is nonzero, so its inverse exists.
        let inverse = rows[rank][column].inverse().unwrap_or(M31::ZERO);
        for value in rows[rank].iter_mut() {
            *value = *value * inverse;
        }
        let (head, tail) = rows.split_at_mut(rank + 1);
        for row in tail {
            let factor = row[column];
            for (value, p) in row.iter_mut().zip(&head[rank]) {
                *value = *value - factor * *p;
            }
        }
        rank += 1;
    }
    rank
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn rejects_dependent_mask_coefficients() {
        let mut rows = [
            vec![M31::ONE, M31::from_u64(2)],
            vec![M31::from_u64(2), M31::from_u64(4)],
        ];
        assert_eq!(rank(&mut rows), 1);
        assert_eq!(
            hiding_message(0, 0, 1, &[M31::ONE], &[0; 32]),
            Err(Error::MessageShape)
        );
    }
}
