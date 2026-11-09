//! Helpers of the embedding and rmsnorm_q modules (RFC-0026 §5 rows 1-2) on top of the
//! shared [`Builder`] and [`Chain`] (RFC-0026 §2.3, §3.5, §3.5a): least-width public
//! columns, byte limbs with a Compose, and the sign table.
//!
//! [`Scope`] is a module's prefix. Each call opens a [`Builder`] on the relation, so
//! groups, names and range checks are exactly the shared helper's.

use super::{bit_length, Builder, Chain};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Compose, Range, Relation, Table, TableId, Term, Values, Violation, Width,
};

pub(crate) use super::{log2_ceil, r as at, term};

/// Least declared width holding every integer of `[low, high]`.
pub(crate) fn width_of(low: i128, high: i128) -> Width {
    if low >= 0 {
        Width::unsigned(bit_length(high as u128).max(1))
    } else {
        Width::signed(bit_length((-low - 1).max(high) as u128) + 1)
    }
}

/// Little-endian bytes of `v`, exactly `n` of them; the top byte keeps any excess,
/// so an out-of-range value yields an out-of-range top byte, never a silent wrap.
pub(crate) fn bytes(v: i128, n: usize) -> Vec<i64> {
    let mut out = Vec::with_capacity(n);
    let mut rest = v;
    for i in 0..n {
        if i + 1 == n {
            out.push(rest as i64);
        } else {
            out.push(rest.rem_euclid(256) as i64);
            rest = rest.div_euclid(256);
        }
    }
    out
}

/// `{(v, [v < 0]) : v ∈ signed(bits)}`: binds a sign bit and range-checks `v`.
pub(crate) fn sign_table(relation: &mut Relation, bits: u8) -> TableId {
    let half = 1i64 << (bits - 1);
    relation.add_table(Table {
        name: format!("sign/{bits}"),
        widths: vec![Width::signed(bits), Width::unsigned(1)],
        rows: (-half..half).map(|v| vec![v, i64::from(v < 0)]).collect(),
    })
}

/// A module's name prefix; groups are `{prefix}/{log_len}` (RFC-0026 §2.3).
pub(crate) struct Scope {
    pub(crate) name: String,
}

impl Scope {
    /// A witness column whose discipline comes from a lookup, matmul or Compose.
    pub(crate) fn witness(
        &self,
        relation: &mut Relation,
        name: &str,
        width: Width,
        log_len: u8,
    ) -> ColumnId {
        Builder::new(relation, &self.name).column(name, width, log_len)
    }

    /// A witness column range-checked at its own width (`width.bits <= 16`).
    pub(crate) fn ranged(
        &self,
        relation: &mut Relation,
        name: &str,
        width: Width,
        log_len: u8,
    ) -> ColumnId {
        Builder::new(relation, &self.name).witness(name, width, log_len)
    }

    pub(crate) fn range(&self, relation: &mut Relation, column: ColumnId, width: Width) {
        let name = relation.columns[column.0 as usize].name.clone();
        relation.ranges.push(Range {
            name,
            column,
            width,
        });
    }

    /// A public column at the least width holding its values.
    pub(crate) fn public(
        &self,
        relation: &mut Relation,
        name: &str,
        values: Vec<i64>,
        log_len: u8,
    ) -> ColumnId {
        let low = values.iter().copied().min().unwrap_or(0);
        let high = values.iter().copied().max().unwrap_or(0);
        let width = width_of(i128::from(low), i128::from(high));
        Builder::new(relation, &self.name).public(name, values, width, log_len)
    }

    pub(crate) fn identity(&self, relation: &mut Relation, name: &str, vars: u8, terms: Vec<Term>) {
        Builder::new(relation, &self.name).identity(name, vars, terms);
    }

    /// `column = Σ_i 256^i · limb_i` (RFC-0026 §3.5a), named `{column}/compose`.
    pub(crate) fn compose(&self, relation: &mut Relation, column: ColumnId, limbs: &[ColumnId]) {
        let name = format!("{}/compose", relation.columns[column.0 as usize].name);
        relation.composes.push(Compose {
            name,
            column,
            limbs: limbs
                .iter()
                .enumerate()
                .map(|(i, &l)| (l, 8 * i as u8))
                .collect(),
        });
    }

    /// Byte limbs of a value in `[low, high]`: unsigned 8 except the top one, which takes
    /// the remaining range (signed when `low < 0`). Every limb is range-checked.
    pub(crate) fn byte_limbs(
        &self,
        relation: &mut Relation,
        name: &str,
        low: i128,
        high: i128,
        log_len: u8,
    ) -> Vec<ColumnId> {
        let mut count = 1;
        while width_of(low >> (8 * (count - 1)), high >> (8 * (count - 1))).bits > 16 {
            count += 1;
        }
        (0..count)
            .map(|i| {
                let width = if i + 1 == count {
                    width_of(low >> (8 * i), high >> (8 * i))
                } else {
                    Width::unsigned(8)
                };
                self.ranged(relation, &format!("{name}{i}"), width, log_len)
            })
            .collect()
    }

    /// A radix-256 [`Chain`] named `{prefix}/{name}`.
    pub(crate) fn chain(
        &self,
        relation: &mut Relation,
        name: &str,
        vars: u8,
        positions: Vec<Vec<Term>>,
    ) -> Chain {
        Chain::declare(
            &mut Builder::new(relation, &self.name),
            name,
            vars,
            8,
            positions,
        )
    }
}

/// Fill a chain's carries from its assigned terms (never rejects: `check` decides).
pub(crate) fn assign_chain(
    chain: &Chain,
    relation: &Relation,
    values: &mut Values,
) -> Result<(), Violation> {
    chain.assign_around(relation, values, None)
}
