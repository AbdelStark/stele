//! SiLU gated FFN product module of the development-profile relation (RFC-0026 §5
//! row 10, task E16-08).
//!
//! Integer definition (RFC-0025 §2.5, RFC-0004 A8, RFC-0021 §2.2): for gate `G` and up
//! `U` (int16, E16-05 outputs), `a = silu_q[G]` and the exact product `T = U·a`, with
//! no rounding. Units are `fu + E`. `T` feeds the E16-05 gated row conversion.
//!
//! `T` reaches `2^30`, beyond any column width, and `U·a` alone already has static
//! magnitude `2^30` under the §3.6 bound rule. So the product is a byte-split limb
//! product with explicit carries (RFC-0026 §3.5):
//! - `U = 2^8·Uh + Ul`, `Ul` in unsigned 8, `Uh` in signed 8 (a `Compose`);
//! - `Ul·a = 2^8·c + d`, `d` in unsigned 8, carry `c` in signed 16;
//! - `Uh·a + c = 2^7·Th + w`, `w` in unsigned 7, `Th` in signed 16;
//! - `Tl = 2^8·w + d` in unsigned 15 (a `Compose`).
//!
//! Then `T = 2^15·Th + Tl` exactly. Both product identities carry a public mask that is
//! 0 on padding, which pins `Th = Tl = 0` there (RFC-0026 §2.1).
//! The output-uniqueness lemma is in `agents/reviews/e16-08-silu.md`.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::tables::{Error as TableError, Table as CqisTable};
use stele_ir::relation::{
    ColumnId, Compose, Identity, Kind, Lookup, Module, Range, Ref, Relation, Table, Term, Values,
    Violation, Width,
};

/// Radix of the high product limb: `T = 2^15·high + low`.
pub const LOW_BITS: u8 = 15;

fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

/// Column ids allocated by [`GatedProduct::declare`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatedColumns {
    /// `Th`, signed 16: the high limb of `T`, consumed by E16-05.
    pub high: ColumnId,
    /// `Tl`, unsigned 15: the low limb of `T`, consumed by E16-05.
    pub low: ColumnId,
    /// `silu_q[G]`, signed 16.
    pub activation: ColumnId,
    pub up_low: ColumnId,
    pub up_high: ColumnId,
    pub carry: ColumnId,
    pub byte: ColumnId,
    pub middle: ColumnId,
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
        let entries = table.entries();
        if table.descriptor().name() != "silu_q" || entries.len() != 2 << 16 {
            return Err(TableError::Parameters);
        }
        let silu = entries
            .chunks_exact(2)
            .enumerate()
            .map(|(i, row)| {
                // Row `i` is input `i − 32768`; the output must fit int16.
                let ok = i64::from(row[0]) == i as i64 - 32768
                    && Width::signed(16).contains(i64::from(row[1]));
                ok.then_some(i64::from(row[1])).ok_or(TableError::Shape)
            })
            .collect::<Result<_, _>>()?;
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
        // `activation` is disciplined by the lookup, `low` by its Compose.
        let columns = GatedColumns {
            high: witness(relation, "high", Width::signed(16), true),
            low: witness(relation, "low", Width::unsigned(LOW_BITS), false),
            activation: witness(relation, "silu", Width::signed(16), false),
            up_low: witness(relation, "up_low", Width::unsigned(8), true),
            up_high: witness(relation, "up_high", Width::signed(8), true),
            carry: witness(relation, "carry", Width::signed(16), true),
            byte: witness(relation, "byte", Width::unsigned(8), true),
            middle: witness(relation, "middle", Width::unsigned(7), true),
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
        let table = relation.add_table(Table {
            name: "silu_q".into(),
            widths: vec![Width::signed(16), Width::signed(16)],
            rows: (0..1 << 16)
                .map(|i| vec![i as i64 - 32768, self.silu[i]])
                .collect(),
        });
        let at = |c: ColumnId| Ref::identity(c, n);
        let (gate, a, mask) = (at(self.gate), at(columns.activation), at(mask));
        let (ul, uh, c, d, w, th) = (
            at(columns.up_low),
            at(columns.up_high),
            at(columns.carry),
            at(columns.byte),
            at(columns.middle),
            at(columns.high),
        );
        relation.lookups.push(Lookup {
            name: format!("{name}/silu"),
            vars: n,
            selector: None,
            tuple: vec![gate, a.clone()],
            table,
        });
        relation.composes.push(Compose {
            name: format!("{name}/up"),
            column: self.up,
            limbs: vec![(columns.up_low, 0), (columns.up_high, 8)],
        });
        relation.composes.push(Compose {
            name: format!("{name}/low"),
            column: columns.low,
            limbs: vec![(columns.byte, 0), (columns.middle, 8)],
        });
        relation.identities.push(Identity {
            name: format!("{name}/low_product"),
            vars: n,
            terms: vec![
                term(1, &[&ul, &a, &mask]),
                term(-(1 << 8), &[&c]),
                term(-1, &[&d]),
            ],
        });
        relation.identities.push(Identity {
            name: format!("{name}/high_product"),
            vars: n,
            terms: vec![
                term(1, &[&uh, &a, &mask]),
                term(1, &[&c]),
                term(-(1 << 7), &[&th]),
                term(-1, &[&w]),
            ],
        });
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
        let mut cols = [(); 8].map(|_| vec![0i64; size]);
        for index in 0..size {
            // Padding: the producer pins G = U = 0, so a = silu_q[0], and the mask pins T.
            let (g, u) = self.entry(index).map_or((0, 0), |(t, j)| {
                let k = t * self.hidden + j;
                (i64::from(capture.gate[k]), i64::from(capture.up[k]))
            });
            let a = self.silu[(g + 32768) as usize];
            let m = i64::from(self.entry(index).is_some());
            let (uh, ul) = (u >> 8, u & 0xff);
            let low = ul * a * m;
            let (c, d) = (low >> 8, low & 0xff);
            let middle = uh * a * m + c;
            let (th, w) = (middle >> 7, middle & 0x7f);
            // T = 2^30 (only U = a = −32768) has no int16 high limb.
            if !Width::signed(16).contains(th) {
                return Err(Violation::Range {
                    relation: format!("L{}/gated/high", self.layer),
                    index,
                });
            }
            let row = [th, (w << 8) | d, a, ul, uh, c, d, w];
            for (column, v) in cols.iter_mut().zip(row) {
                column[index] = v;
            }
        }
        let ids = [
            columns.high,
            columns.low,
            columns.activation,
            columns.up_low,
            columns.up_high,
            columns.carry,
            columns.byte,
            columns.middle,
        ];
        for (id, column) in ids.into_iter().zip(cols) {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
