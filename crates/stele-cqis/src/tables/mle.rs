//! RFC-0021 §4: canonical-field table MLEs and a separate valid-row selector.
use super::{Error, Table};
use stele_field::{Field, OM31, QM31};

mod private {
    pub trait Sealed {}
}
impl private::Sealed for QM31 {}
impl private::Sealed for OM31 {}

/// Only canonical QM31 and OM31 support CQIS table evaluation.
/// ```compile_fail
/// fn supported<K: stele_cqis::tables::TableField>() {}
/// supported::<stele_field::M31>();
/// ```
/// ```compile_fail
/// fn supported<K: stele_cqis::tables::TableField>() {}
/// supported::<stele_field::CM31>();
/// ```
/// ```compile_fail
/// fn supported<K: stele_cqis::tables::TableField>() {}
/// supported::<stele_field::KoalaBear>();
/// ```
/// Matching the base characteristic cannot supply the private field seal.
#[doc = concat!("```\n",include_str!("mle-field-doctest.md"),
    "\nfn field<K: Field>() {}\nfield::<Other>();\n```\n",
    "```compile_fail,E0277\n",include_str!("mle-field-doctest.md"),
    "\nimpl stele_cqis::tables::TableField for Other {}\n```")]
pub trait TableField: Field + private::Sealed {}
impl TableField for QM31 {}
impl TableField for OM31 {}

/// Public polynomial values only: no authenticated query, membership or proof claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evaluation<K: TableField> {
    columns: [K; 2],
    width: u8,
    valid_rows: K,
}

impl<K: TableField> Evaluation<K> {
    /// Column evaluations in canonical tuple order, including all zero padding.
    pub fn columns(&self) -> &[K] {
        &self.columns[..usize::from(self.width)]
    }
    /// Value of sum_(i<N) eq(MSB_bits(i),r), separately from table-data columns.
    /// It need not be Boolean at a non-Boolean query point.
    pub fn valid_rows(&self) -> K {
        self.valid_rows
    }
}

fn columns<K: TableField>(entries: &[i32], point: &[K], width: usize) -> [K; 2] {
    if let Some((r, rest)) = point.split_first() {
        // The checked root has 2^point.len() complete tuples. Splitting rows in
        // half assigns the current MSB to zero/one, preserving this invariant.
        let (a, b) = entries.split_at(entries.len() / 2);
        let mut left = columns(a, rest, width);
        let right = columns(b, rest, width);
        for i in 0..width {
            left[i] = left[i] + (right[i] - left[i]) * *r;
        }
        left
    } else {
        let mut result = [K::from_i64(0); 2];
        for (out, value) in result.iter_mut().zip(entries) {
            *out = K::from_i64(i64::from(*value));
        }
        result
    }
}

fn valid<K: TableField>(rows: usize, padded: usize, point: &[K]) -> Result<K, Error> {
    let one = K::from_i64(1);
    if rows == padded {
        return Ok(one);
    }
    if rows == 0 {
        return Ok(K::from_i64(0));
    }
    let (r, rest) = point.split_first().ok_or(Error::PointDimension)?;
    let half = padded / 2;
    // Prefix [0,N): one half is wholly valid/invalid, so only the boundary half
    // recurses. This is exactly the separate Boolean validity table's MLE.
    Ok(if rows <= half {
        (one - *r) * valid(rows, half, rest)?
    } else {
        one - *r + *r * valid(rows - half, half, rest)?
    })
}

impl Table {
    /// Evaluate all canonical columns and validity at an exact-dimension MSB-first
    /// point. Costs O(Lc) field work and O(log L) stack, without heap allocation.
    /// The operation draws no challenge and does not authenticate the supplied point.
    pub fn evaluate<K: TableField>(&self, point: &[K]) -> Result<Evaluation<K>, Error> {
        let shape = self.descriptor().shape();
        let padded = usize::try_from(shape.padded()).map_err(|_| Error::Capacity)?;
        let rows = usize::try_from(shape.rows()).map_err(|_| Error::Capacity)?;
        let width = usize::from(shape.columns());
        if !padded.is_power_of_two()
            || padded > 65536
            || rows == 0
            || rows > padded
            || !(1..=2).contains(&width)
            || padded.checked_mul(width).ok_or(Error::Capacity)? != self.entries().len()
        {
            return Err(Error::Shape);
        }
        if point.len() != padded.ilog2() as usize {
            return Err(Error::PointDimension);
        }
        Ok(Evaluation {
            columns: columns(self.entries(), point, width),
            width: shape.columns(),
            valid_rows: valid(rows, padded, point)?,
        })
    }
}
