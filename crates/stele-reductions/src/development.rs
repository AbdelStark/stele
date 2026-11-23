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
    eval_column, ColumnId, Def, Identity, Kind, Range, Ref, Relation, Term, Values, Violation,
    Width,
};

pub mod attention;
pub mod embedding;
mod limbs;
pub mod power;
pub mod projection;
pub mod rmsnorm;
pub mod row;

pub use attention::{Attention, AttentionCapture, AttentionPlan, PositionCapture};
pub use power::{PowerGated, PowerGatedCapture, PowerOutput, PowerPlan, PowerProjection, PowerRow};
pub use projection::{Projection, ProjectionCapture, ProjectionPlan};
pub use row::{ConversionCapture, Policy, RowConversion, RowOutput};

#[cfg(test)]
mod norm_embedding_tests;
#[cfg(test)]
mod power_tests;
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

    /// Virtual column defined by `def` (RFC-0028 §2.1), never committed.
    pub(crate) fn virtual_col(&mut self, name: &str, def: Def, log_len: u8) -> ColumnId {
        let name = self.name(name);
        self.relation.add_virtual(&name, def, log_len)
    }

    /// Virtual column with a range check (RFC-0028 §1.2, A1), never committed.
    pub(crate) fn virtual_ranged(
        &mut self,
        name: &str,
        def: Def,
        width: Width,
        log_len: u8,
    ) -> ColumnId {
        let column = self.virtual_col(name, def, log_len);
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
                        let m = b.relation.column_magnitude(f.column).unwrap_or_else(|| {
                            b.relation.columns[f.column.0 as usize].width.magnitude()
                        });
                        p * m
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

    /// Declare a wide chain `sum_k R^k * E_k = 0` where selected positions `k` carry an
    /// unsigned remainder/output limb `target_k ∈ [0, R)` appearing with coefficient `-1`
    /// (`E_k + c_{k-1} - R*c_k = target_k`, RFC-0028 §1.2, A1).
    ///
    /// Whenever `E_k + c_{k-1} - R*c_k` satisfies the static `<= HALF_MODULUS` bound, `target_k`
    /// is declared as a ranged virtual column (`Def::Linear` when linear, else `Def::Pointwise`)
    /// with no committed column and no position identity; otherwise it falls back to a committed
    /// ranged witness column and an identity. Returns `(chain, target_ids)` in `targets` order.
    pub(crate) fn declare_virtual(
        b: &mut Builder<'_>,
        name: &str,
        vars: u8,
        radix: u8,
        mut positions: Vec<Vec<Term>>,
        targets: &[(usize, String, Width)],
    ) -> (Self, Vec<ColumnId>) {
        use stele_ir::relation::HALF_MODULUS;
        let mut target_at: Vec<Option<(usize, &str, Width)>> = vec![None; positions.len()];
        for (idx, (pos, tname, width)) in targets.iter().enumerate() {
            if positions.len() <= *pos {
                positions.resize(*pos + 1, Vec::new());
                target_at.resize(*pos + 1, None);
            }
            target_at[*pos] = Some((idx, tname.as_str(), *width));
        }
        let mut carries = Vec::with_capacity(positions.len());
        let mut incoming = 0u128;
        let last = positions.len().saturating_sub(1);
        let mut pos_bounds = Vec::with_capacity(positions.len());
        for (k, terms) in positions.iter().enumerate() {
            let mut bound = terms.iter().fold(incoming, |sum, t| {
                sum + t
                    .factors
                    .iter()
                    .fold(t.coeff.unsigned_abs() as u128, |p, f| {
                        let m = b.relation.column_magnitude(f.column).unwrap_or_else(|| {
                            b.relation.columns[f.column.0 as usize].width.magnitude()
                        });
                        p * m
                    })
            });
            let t_mag = target_at[k].map_or(0u128, |(_, _, w)| w.magnitude());
            pos_bounds.push(bound);
            bound = bound.saturating_add(t_mag);
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
        let mut target_ids = vec![ColumnId(0); targets.len()];
        let carry_bounds: Vec<u128> = carries
            .iter()
            .map(|c| {
                let col_m = |id: ColumnId| {
                    b.relation
                        .column_magnitude(id)
                        .unwrap_or_else(|| b.relation.columns[id.0 as usize].width.magnitude())
                };
                match *c {
                    None => 0u128,
                    Some(Carry::One(id)) => col_m(id) << radix,
                    Some(Carry::Split(lo, hi)) => (col_m(lo) + (col_m(hi) << 16)) << radix,
                }
            })
            .collect();
        for k in 0..positions.len() {
            let mut all = positions[k].clone();
            if let Some(c) = k.checked_sub(1).and_then(|p| carries[p]) {
                all.extend(c.terms(1, vars));
            }
            if let Some(c) = carries[k] {
                all.extend(c.terms(-(1 << radix), vars));
            }
            if let Some((idx, tname, width)) = target_at[k] {
                let def_bound = pos_bounds[k].saturating_add(carry_bounds[k]);
                if def_bound <= HALF_MODULUS && !all.is_empty() {
                    let is_linear = all.iter().all(|t| t.factors.len() <= 1);
                    let def = if is_linear {
                        let mut constant = 0i64;
                        let mut lterms = Vec::new();
                        for t in all {
                            if let Some(f) = t.factors.into_iter().next() {
                                lterms.push((t.coeff, f));
                            } else {
                                constant += t.coeff;
                            }
                        }
                        Def::Linear {
                            constant,
                            terms: lterms,
                        }
                    } else {
                        Def::Pointwise { terms: all }
                    };
                    target_ids[idx] = b.virtual_ranged(tname, def, width, vars);
                } else {
                    let col = b.witness(tname, width, vars);
                    target_ids[idx] = col;
                    let neg = term(-1, vec![r(col, 0..vars)]);
                    positions[k].push(neg.clone());
                    all.push(neg);
                    b.identity(&format!("{name}/{k}"), vars, all);
                }
            } else if !all.is_empty() {
                b.identity(&format!("{name}/{k}"), vars, all);
            }
        }
        (
            Self {
                vars,
                radix,
                positions,
                carries,
            },
            target_ids,
        )
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
        // Resolve every referenced column once (supporting virtual columns, RFC-0028).
        let mut cache: alloc::collections::BTreeMap<ColumnId, Vec<i64>> =
            alloc::collections::BTreeMap::new();
        for terms in &self.positions {
            for t in terms {
                for f in &t.factors {
                    if let alloc::collections::btree_map::Entry::Vacant(e) = cache.entry(f.column) {
                        e.insert(eval_column(relation, values, f.column)?);
                    }
                }
            }
        }
        // Every factor's column and index map, resolved once and not once per point.
        type Factors<'c> = Vec<(&'c [i64], stele_ir::relation::Indexer<'c>)>;
        let mut positions: Vec<Vec<(i128, Factors<'_>)>> = Vec::with_capacity(n);
        for terms in &self.positions {
            let mut resolved = Vec::with_capacity(terms.len());
            for t in terms {
                let mut factors = Vec::with_capacity(t.factors.len());
                for f in &t.factors {
                    let column = cache.get(&f.column).ok_or(Violation::Missing(f.column))?;
                    factors.push((column.as_slice(), stele_ir::relation::Indexer::new(f, size)));
                }
                resolved.push((t.coeff as i128, factors));
            }
            positions.push(resolved);
        }
        let mut columns: Vec<Vec<i64>> = vec![vec![0; size]; n];
        let mut sums = Vec::with_capacity(n);
        for x in 0..size as u64 {
            sums.clear();
            for terms in &positions {
                let mut sum = 0i128;
                for (coeff, factors) in terms {
                    let mut product = *coeff;
                    for (column, at) in factors {
                        product *= column[at.index(x)] as i128;
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
