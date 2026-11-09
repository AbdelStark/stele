//! Development-profile modules over `stele_ir::relation` (RFC-0026 §5).
//!
//! Each module declares columns and relations from plan data only and fills its
//! witness columns from a module-local capture (RFC-0026 §3.8). Shared helpers:
//! a column [`Builder`] that names groups `{prefix}/{log_len}` (RFC-0026 §2.3) and
//! range-checks every witness column, and the byte [`Chain`] that proves one wide
//! integer identity as small per-position identities with carries (limb rule,
//! RFC-0026 §3.5).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Identity, Kind, Range, Ref, Relation, Term, Values, Violation, Width,
};

pub mod attention;
pub mod embedding;
mod limbs;
pub mod projection;
pub mod rmsnorm;
pub mod row;

pub use attention::{Attention, AttentionCapture, AttentionPlan, PositionCapture};
pub use projection::{Projection, ProjectionCapture, ProjectionPlan};
pub use row::{ConversionCapture, Policy, RowConversion, RowOutput};

#[cfg(test)]
mod norm_embedding_tests;
#[cfg(test)]
pub(crate) mod tests;

/// A plan the development profile cannot express; rejected before proving
/// (RFC-0026 §1.3 `UnsupportedModel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// A dimension, row count or group size outside the supported domain.
    Shape,
    /// A row policy or scale outside the supported domain.
    Policy,
    /// A column or matmul would exceed the relation API's widths or variables.
    Domain,
}

/// `ceil(log2(n))` for `n >= 1`: the index bits of a dimension padded to a power of two.
pub(crate) fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

/// Bits of the binary representation of `n` (0 for 0).
pub(crate) fn bit_length(n: u128) -> u8 {
    (128 - n.leading_zeros()) as u8
}

/// Signed width whose members include every integer in `[-bound, bound]`.
pub(crate) fn signed_for(bound: u128) -> Width {
    Width::signed(bit_length(bound) + 1)
}

/// A read of `column` with column bit `j` on domain bit `vars[j]`.
pub(crate) fn r(column: ColumnId, vars: impl IntoIterator<Item = u8>) -> Ref {
    Ref {
        column,
        vars: vars.into_iter().collect(),
    }
}

pub(crate) fn term(coeff: i64, factors: Vec<Ref>) -> Term {
    Term { coeff, factors }
}

/// Declares one module's columns: names are `{prefix}/{name}`, witness columns of
/// one `log_len` share the group `{prefix}/{log_len}`.
pub(crate) struct Builder<'a> {
    pub(crate) relation: &'a mut Relation,
    prefix: &'a str,
}

impl<'a> Builder<'a> {
    pub(crate) fn new(relation: &'a mut Relation, prefix: &'a str) -> Self {
        Self { relation, prefix }
    }

    /// The module prefix of every name this builder issues.
    pub(crate) fn prefix(&self) -> &str {
        self.prefix
    }

    fn name(&self, name: &str) -> String {
        format!("{}/{}", self.prefix, name)
    }

    /// Witness column with no range: its discipline comes from a lookup or matmul.
    pub(crate) fn column(&mut self, name: &str, width: Width, log_len: u8) -> ColumnId {
        let group_name = format!("{}/{}", self.prefix, log_len);
        let group = match self
            .relation
            .groups
            .iter()
            .position(|g| g.name == group_name)
        {
            Some(index) => stele_ir::relation::GroupId(index as u32),
            None => self.relation.add_group(&group_name, log_len),
        };
        let name = self.name(name);
        self.relation
            .add_column(&name, Kind::Witness(group), width, log_len)
    }

    /// Witness column range-checked to exactly its declared width (at most 16 bits).
    pub(crate) fn witness(&mut self, name: &str, width: Width, log_len: u8) -> ColumnId {
        let column = self.column(name, width, log_len);
        // Distinct from identity names, so every constraint has a unique name.
        self.relation.ranges.push(Range {
            name: self.name(&format!("{name}/range")),
            column,
            width,
        });
        column
    }

    pub(crate) fn public(
        &mut self,
        name: &str,
        values: Vec<i64>,
        width: Width,
        log_len: u8,
    ) -> ColumnId {
        let name = self.name(name);
        self.relation
            .add_column(&name, Kind::Public(values), width, log_len)
    }

    pub(crate) fn identity(&mut self, name: &str, vars: u8, terms: Vec<Term>) {
        let name = self.name(name);
        self.relation
            .identities
            .push(Identity { name, vars, terms });
    }
}

/// A wide identity `sum_k R^k * E_k = 0` (radix `R = 2^radix`) over one domain,
/// proven as one small identity per position: `E_k + c_(k-1) - R*c_k = 0`, with
/// `c_(-1) = 0` and no carry out of the last position. Summing position `k` times
/// `R^k` telescopes the carries away, so the small identities hold over Z exactly
/// when the wide one does (each small identity is wrap-free by the bound rule).
/// Carries are determined by the terms; a carry wider than 16 bits is a low
/// unsigned 16-bit limb plus a signed high limb (RFC-0026 §3.5).
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    vars: u8,
    radix: u8,
    positions: Vec<Vec<Term>>,
    carries: Vec<Option<Carry>>,
}

#[derive(Clone, Copy, Debug)]
enum Carry {
    One(ColumnId),
    Split(ColumnId, ColumnId),
}

impl Carry {
    /// Terms for `coeff * carry`.
    fn terms(self, coeff: i64, vars: u8) -> Vec<Term> {
        match self {
            Carry::One(c) => vec![term(coeff, vec![r(c, 0..vars)])],
            Carry::Split(lo, hi) => vec![
                term(coeff, vec![r(lo, 0..vars)]),
                term(coeff << 16, vec![r(hi, 0..vars)]),
            ],
        }
    }
}

impl Chain {
    /// Declare the carries and the per-position identities of `positions`.
    pub(crate) fn declare(
        b: &mut Builder<'_>,
        name: &str,
        vars: u8,
        radix: u8,
        positions: Vec<Vec<Term>>,
    ) -> Self {
        let mut carries = Vec::with_capacity(positions.len());
        let mut incoming = 0u128;
        let last = positions.len().saturating_sub(1);
        for (k, terms) in positions.iter().enumerate() {
            let bound = terms.iter().fold(incoming, |sum, t| {
                sum + t
                    .factors
                    .iter()
                    .fold(t.coeff.unsigned_abs() as u128, |p, f| {
                        p * b.relation.columns[f.column.0 as usize].width.magnitude()
                    })
            });
            incoming = if k == last { 0 } else { bound >> radix };
            carries.push(match incoming {
                0 => None,
                c if c < 1 << 15 => Some(Carry::One(b.witness(
                    &format!("{name}/carry{k}"),
                    signed_for(c),
                    vars,
                ))),
                c => Some(Carry::Split(
                    b.witness(&format!("{name}/carry{k}/lo"), Width::unsigned(16), vars),
                    b.witness(&format!("{name}/carry{k}/hi"), signed_for(c >> 16), vars),
                )),
            });
        }
        for (k, terms) in positions.iter().enumerate() {
            let mut all = terms.clone();
            if let Some(c) = k.checked_sub(1).and_then(|p| carries[p]) {
                all.extend(c.terms(1, vars));
            }
            if let Some(c) = carries[k] {
                all.extend(c.terms(-(1 << radix), vars));
            }
            if !all.is_empty() {
                b.identity(&format!("{name}/{k}"), vars, all);
            }
        }
        Self {
            vars,
            radix,
            positions,
            carries,
        }
    }

    /// Fill the carries. With `skip = Some(k)`, carries below position `k` run
    /// forward from position 0 and the others run backward from the top, so every
    /// position identity except `k` holds whenever the terms allow it: the strongest
    /// carries for a mutation test that removes identity `k`.
    pub(crate) fn assign_around(
        &self,
        relation: &Relation,
        values: &mut Values,
        skip: Option<usize>,
    ) -> Result<(), Violation> {
        let size = 1usize << self.vars;
        let n = self.positions.len();
        let mut columns: Vec<Vec<i64>> = vec![vec![0; size]; n];
        for x in 0..size as u64 {
            let mut sums = Vec::with_capacity(n);
            for terms in &self.positions {
                let mut sum = 0i128;
                for t in terms {
                    let mut product = t.coeff as i128;
                    for f in &t.factors {
                        let column = values
                            .get(relation, f.column)
                            .ok_or(Violation::Missing(f.column))?;
                        product *= column[f.index(x)] as i128;
                    }
                    sum += product;
                }
                sums.push(sum);
            }
            let split = skip.unwrap_or(n);
            let mut carry = 0i128;
            for (k, sum) in sums.iter().enumerate().take(split) {
                carry = (sum + carry).div_euclid(1 << self.radix);
                columns[k][x as usize] = carry as i64;
            }
            let mut carry = 0i128;
            for k in (split + 1..n).rev() {
                carry = (carry << self.radix) - sums[k];
                columns[k - 1][x as usize] = carry as i64;
            }
        }
        for (carry, column) in self.carries.iter().zip(columns) {
            match *carry {
                None => {}
                Some(Carry::One(c)) => values.set(relation, c, column)?,
                Some(Carry::Split(lo, hi)) => {
                    values.set(
                        relation,
                        lo,
                        column.iter().map(|v| v.rem_euclid(1 << 16)).collect(),
                    )?;
                    values.set(
                        relation,
                        hi,
                        column.iter().map(|v| v.div_euclid(1 << 16)).collect(),
                    )?;
                }
            }
        }
        Ok(())
    }
}
