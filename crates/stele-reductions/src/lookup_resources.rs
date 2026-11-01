//! RFC-0008 A5 §6: conservative named producer storage, not observed capacity/RSS.
use super::{addressable, mul, sum, Descriptor, Error};
use core::mem::size_of;
use stele_field::M31;
use stele_hash::{merkle, ChallengeField};
use stele_pcs::CodeField;

// Caller leaves, actual copied levels, largest five-table A1 layer, proof scalars,
// point buffers, descriptor units, and 2+3+5 layer/term/scratch field values.
fn tree(v: usize, units: usize) -> Result<usize, Error> {
    let domain = 1usize.checked_shl(v as u32).ok_or(Error::Capacity)?;
    let levels = mul(2, domain)?.checked_sub(1).ok_or(Error::Capacity)?;
    let proof = sum(&[2, mul(2, mul(v, v)?)?, mul(3, v)?])?;
    sum(&[
        mul(2, domain)?,
        mul(2, levels)?,
        mul(5, domain / 2)?,
        proof,
        mul(3, v)?,
        units,
        10,
    ])
}
pub(super) fn elements<K: ChallengeField + CodeField>(
    dsc: &Descriptor<'_, '_, K>,
) -> Result<usize, Error> {
    let s = &dsc.statement;
    let (c, r) = (s.originals.len(), s.multiplicities.len());
    let (m, k, h) = (usize::from(s.m), usize::from(dsc.k), usize::from(s.m - s.b));
    let n_positions = s.selector.len();
    let n = s.table.descriptor().shape().padded() as usize;
    let degree = <K as CodeField>::DEGREE as usize;
    let groups = 1usize.checked_shl(h as u32).ok_or(Error::Capacity)?;
    for count in [n_positions, n] {
        addressable::<[K; 2]>(count)?;
    }
    for count in [n_positions, n, groups] {
        addressable::<K>(count)?;
    }
    addressable::<M31>(mul(n, degree)?)?;
    addressable::<([u32; 2], usize)>(s.table.descriptor().shape().rows() as usize)?;

    // c original lifts, sigma; unit vectors/pairs, group weights and mu values.
    let mut extension = sum(&[mul(c + 1, n_positions)?, mul(r, sum(&[h, 2, groups, n])?)?])?;
    // SelectedProduct's (c+2)N Dense inputs, N selector scratch, proof, point,
    // coefficients, final claims and Dense scratch. Dense itself folds in place.
    let selected = sum(&[mul(c + 3, n_positions)?, mul(5, m)?, mul(4, c)?, 4])?;
    extension = sum(&[
        extension,
        mul(r, sum(&[tree(m, h)?, tree(k, 0)?, selected])?)?,
    ])?;
    for certificate in s.originals {
        let source = certificate.record().source();
        extension = sum(&[extension, mul(r, sum(&[source.rows(), source.columns()])?)?])?;
    }
    let mut base = mul(r, mul(n, degree)?)?; // All stable record-major mu limbs.
    let mut local_hashes = 1u64; // Actual Table encoding plus actual preparation only.
    for (j, source) in dsc.mu[..r].iter().enumerate() {
        let (rows, columns, length) = (
            source.rows(),
            source.columns(),
            source.code().codeword_len(),
        );
        let suffix = columns / degree;
        let nodes = mul(2, length)?.checked_sub(1).ok_or(Error::Capacity)?;
        for count in [rows, columns, length, suffix] {
            addressable::<K>(count)?;
        }
        addressable::<u8>(mul(4, mul(rows, length)?)?)?;
        addressable::<merkle::Digest>(nodes)?;
        addressable::<&[u8]>(length)?;
        addressable::<merkle::Digest>(source.path_height())?;
        // Opaque Circle scratch uses <=L-1 M31 twiddle/prefix values per
        // preparation/verification; L>=2C bounds the inverse-transform overlap.
        base = sum(&[
            base,
            mul(rows, length)?,
            mul(3, length)?.checked_sub(2).ok_or(Error::Capacity)?,
        ])?;
        // Two independent registration weight vectors, verifier row/encoded row;
        // shared prefix/suffix equality tables and every retained piece's a/b.
        extension = sum(&[
            extension,
            mul(2, rows)?,
            columns,
            length,
            rows,
            suffix,
            mul(dsc.pieces[j], sum(&[rows, columns])?)?,
            8, // Fixed canonical basis storage, including QM31's unused slots.
            dsc.pieces[j],
        ])?;
        local_hashes = local_hashes
            .checked_add(u64::try_from(nodes).map_err(|_| Error::Capacity)?)
            .ok_or(Error::Capacity)?;
        // Known non-field PCS buffers are separately addressable; no total-memory
        // or byte-cap claim is inferred from the dense-slot admission policy.
        sum(&[
            mul(4, mul(rows, length)?)?,
            mul(nodes, size_of::<merkle::Digest>())?,
            mul(length, size_of::<&[u8]>())?,
        ])?;
    }
    // m<=59,k<=16,c/r/p<=2 bound metadata/Vec-header counts. Existing checked
    // statement/proof and opening-frame sizes cover individual byte allocations.
    let _ = local_hashes;
    sum(&[mul(degree, extension)?, base])
}
