//! SiLU gated FFN product module of the development-profile relation (RFC-0026 §5
//! row 10, task E16-08).
//!
//! Integer definition (RFC-0025 §2.5, RFC-0004 A8, RFC-0021 §2.2): for gate `G` and up
//! `U` (int16, E16-05 outputs), `a = silu_q[G]` and the exact product `T = U·a`, with
//! no rounding. Units are `fu + E`. `T` feeds [`GatedConversion`].
//!
//! `|T|` approaches `2^30`, beyond any column width, and `U·a` alone already has static
//! magnitude `2^30` under the §3.6 bound rule. Under RFC-0028 §1.2, the product commits
//! only three advice columns (`silu`, `up_high`, `carry`) via a radix-`2^14` split:
//! - `U = 2^14·Uh + Ul`, `Uh` in signed 2 (committed), `Ul` in unsigned 14 (virtual);
//! - `Ul·a·mask = 2^14·c + Tl`, `c` in signed 16 (committed), `Tl` in unsigned 14 (virtual;
//!   static magnitude `16383·32768 + 16384·32768 = 1,073,709,056 <= HALF_MODULUS`);
//! - `Th = Uh·a·mask + c` (virtual, static magnitude `98,304`, actual value in `[-2^16, 2^16)`).
//!
//! Then `T = 2^14·Th + Tl` exactly. On padding (`mask = 0`), `Tl = -2^14·c ∈ [0, 2^14)`
//! forces `c = 0` over Z, which pins `Tl = Th = 0` (RFC-0026 §2.1).
//! The output-uniqueness lemma is in `agents/reviews/e16-08-silu.md` (restated for
//! radix `2^14` in `agents/reviews/e18-05-module-conversions.md`). The gated row
//! conversion of `T` to down-projection codes is [`GatedConversion`].

mod conversion;
pub use conversion::{ConversionColumns, GatedConversion, GATED_SCALE};

use crate::development::log2_ceil;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::tables::{Error as TableError, Table as CqisTable};
use stele_ir::relation::{
    ColumnId, Def, Kind, Lookup, Module, Range, Ref, Relation, Table, Term, Values, Violation,
    Width,
};

/// Radix of the high product limb: `T = 2^14·high + low`.
pub const LOW_BITS: u8 = 14;

/// Column ids allocated by [`GatedProduct::declare`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatedColumns {
    /// `Th = Uh·a·mask + carry` (virtual): the high limb of `T`, consumed by [`GatedConversion`].
    pub high: ColumnId,
    /// `Tl = Ul·a·mask - 2^14·carry` (virtual, unsigned 14): the low limb of `T`,
    /// consumed by [`GatedConversion`].
    pub low: ColumnId,
    /// `silu_q[G]`, signed 16 (committed advice).
    pub activation: ColumnId,
    /// `Ul = U - 2^14·Uh`, unsigned 14 (virtual).
    pub up_low: ColumnId,
    /// `Uh = U >> 14`, signed 2 (committed advice).
    pub up_high: ColumnId,
    /// `c = (Ul·a·mask) >> 14`, signed 16 (committed advice).
    pub carry: ColumnId,
}

/// Executor values this module needs: the unpadded `(tokens, hidden)` gate and up
/// projection outputs, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatedCapture {
    pub gate: Vec<i16>,
    pub up: Vec<i16>,
}

/// The SiLU gated product `T = U·silu_q[G]` of one layer.
#[derive(Clone, Debug)]
pub struct GatedProduct {
    layer: usize,
    gate: ColumnId,
    up: ColumnId,
    tokens: usize,
    hidden: usize,
    /// `silu_q[t]` at index `t + 32768`.
    silu: Vec<i64>,
    columns: Option<GatedColumns>,
}

impl GatedProduct {
    /// Plan data: the gate and up columns of shape `(tokens, hidden)` (int16, each
    /// dimension padded to a power of two) and the block's SiLU component table,
    /// `Table::generate(block.activation().components()[0])`.
    pub fn new(
        layer: usize,
        gate: ColumnId,
        up: ColumnId,
        tokens: usize,
        hidden: usize,
        table: &CqisTable,
    ) -> Result<Self, TableError> {
        if table.descriptor().name() != "silu_q" {
            return Err(TableError::Parameters);
        }
        let silu = silu_outputs(table.entries())?;
        Ok(Self {
            layer,
            gate,
            up,
            tokens,
            hidden,
            silu,
            columns: None,
        })
    }

    /// Column ids, once declared.
    pub fn columns(&self) -> Option<GatedColumns> {
        self.columns
    }

    fn bits(&self) -> (u8, u8) {
        (log2_ceil(self.hidden), log2_ceil(self.tokens))
    }

    /// `(t, j)` of a padded index, `None` on padding.
    fn entry(&self, index: usize) -> Option<(usize, usize)> {
        let (h, _) = self.bits();
        let (j, t) = (index & ((1 << h) - 1), index >> h);
        (j < self.hidden && t < self.tokens).then_some((t, j))
    }
}

/// The outputs of a complete `silu_q` table, row `i` being input `i − 2^15`.
///
/// Every output must lie in `(−2^15, 2^15)`, so `|U·a| < 2^30` and the high limb of `T`
/// always fits signed 16 (totality). Generated `silu_q` tables satisfy this (their
/// negative outputs stay above `−2^14`, SILU-CONSUMER); anything else is rejected.
fn silu_outputs(entries: &[i32]) -> Result<Vec<i64>, TableError> {
    if entries.len() != 2 << 16 {
        return Err(TableError::Parameters);
    }
    entries
        .chunks_exact(2)
        .enumerate()
        .map(|(i, row)| {
            let ok = i64::from(row[0]) == i as i64 - 32768 && (-32767..=32767).contains(&row[1]);
            ok.then_some(i64::from(row[1])).ok_or(TableError::Shape)
        })
        .collect()
}

fn term(coeff: i64, factors: &[&Ref]) -> Term {
    Term {
        coeff,
        factors: factors.iter().map(|&f| f.clone()).collect(),
    }
}

impl Module for GatedProduct {
    type Capture = GatedCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (h, t) = self.bits();
        let n = h + t;
        let name = format!("L{}/gated", self.layer);
        let group = relation.add_group(&format!("{name}/{n}"), n);
        let witness = |relation: &mut Relation, label: &str, width: Width, ranged: bool| {
            let id =
                relation.add_column(&format!("{name}/{label}"), Kind::Witness(group), width, n);
            if ranged {
                relation.ranges.push(Range {
                    name: format!("{name}/{label}"),
                    column: id,
                    width,
                });
            }
            id
        };
        let virtual_ranged = |relation: &mut Relation, label: &str, def: Def, width: Width| {
            let id = relation.add_virtual(&format!("{name}/{label}"), def, n);
            relation.ranges.push(Range {
                name: format!("{name}/{label}"),
                column: id,
                width,
            });
            id
        };
        let mask = (0..1usize << n)
            .map(|x| i64::from(self.entry(x).is_some()))
            .collect();
        let mask = relation.add_column(
            &format!("{name}/mask"),
            Kind::Public(mask),
            Width::unsigned(1),
            n,
        );
        let at = |c: ColumnId| Ref::identity(c, n);
        // Committed advice only (RFC-0028 §1.2): silu table output, up_high (s2), carry (s16).
        let activation = witness(relation, "silu", Width::signed(16), false);
        let up_high = witness(relation, "up_high", Width::signed(2), true);
        let carry = witness(relation, "carry", Width::signed(16), true);

        let table = relation.add_table(Table {
            name: "silu_q".into(),
            widths: vec![Width::signed(16), Width::signed(16)],
            rows: (0..1 << 16)
                .map(|i| vec![i as i64 - 32768, self.silu[i]])
                .collect(),
        });
        let (gate, a, mask_ref) = (at(self.gate), at(activation), at(mask));
        relation.lookups.push(Lookup {
            name: format!("{name}/silu"),
            vars: n,
            selector: None,
            tuple: vec![gate, a.clone()],
            table,
        });
        // Virtual up_low = U - 2^14 * Uh ∈ [0, 2^14) (RFC-0028 §1.2, A1).
        let up_low = virtual_ranged(
            relation,
            "up_low",
            Def::Linear {
                constant: 0,
                terms: vec![(1, at(self.up)), (-(1 << LOW_BITS), at(up_high))],
            },
            Width::unsigned(LOW_BITS),
        );
        // Virtual low Tl = Ul * a * mask - 2^14 * c ∈ [0, 2^14) (RFC-0028 §1.2, A1).
        // Static mag = 16383 * 32768 + 16384 * 32768 = 1,073,709,056 <= HALF_MODULUS.
        let low = virtual_ranged(
            relation,
            "low",
            Def::Pointwise {
                terms: vec![
                    term(1, &[&at(up_low), &a, &mask_ref]),
                    term(-(1 << LOW_BITS), &[&at(carry)]),
                ],
            },
            Width::unsigned(LOW_BITS),
        );
        // Virtual high Th = Uh * a * mask + c (static mag = 98,304; no range needed).
        let high = relation.add_virtual(
            &format!("{name}/high"),
            Def::Pointwise {
                terms: vec![
                    term(1, &[&at(up_high), &a, &mask_ref]),
                    term(1, &[&at(carry)]),
                ],
            },
            n,
        );
        let columns = GatedColumns {
            high,
            low,
            activation,
            up_low,
            up_high,
            carry,
        };
        self.columns = Some(columns);
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &GatedCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let columns = self.columns.expect("GatedProduct::assign before declare");
        let len = self.tokens * self.hidden;
        if capture.gate.len() != len {
            return Err(Violation::Missing(self.gate));
        }
        if capture.up.len() != len {
            return Err(Violation::Missing(self.up));
        }
        let size = 1usize << (self.bits().0 + self.bits().1);
        let mut activation = vec![0i64; size];
        let mut up_high = vec![0i64; size];
        let mut carry = vec![0i64; size];
        let mask_low = (1i64 << LOW_BITS) - 1;
        for index in 0..size {
            // Padding: the producer pins G = U = 0, so a = silu_q[0], and the mask pins T.
            let (g, u) = self.entry(index).map_or((0, 0), |(t, j)| {
                let k = t * self.hidden + j;
                (i64::from(capture.gate[k]), i64::from(capture.up[k]))
            });
            let a = self.silu[(g + 32768) as usize];
            let m = i64::from(self.entry(index).is_some());
            let (uh, ul) = (u >> LOW_BITS, u & mask_low);
            let c = (ul * a * m) >> LOW_BITS;
            activation[index] = a;
            up_high[index] = uh;
            carry[index] = c;
        }
        for (id, column) in [
            (columns.activation, activation),
            (columns.up_high, up_high),
            (columns.carry, carry),
        ] {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
