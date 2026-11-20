//! Greedy argmax check of the development-profile relation (RFC-0026 §5 row 13,
//! RFC-0028 §1.2, tasks E16-09 and E18-05).
//!
//! Integer definition (RFC-0025 §2.6): the checked token `c_i` of row `i ∈ [r, e)` is the
//! least vocabulary id attaining the row maximum of the int16 logits. `c_i = x_{i+1}`
//! for `i < T−1` and the next token `y` for `i = T−1` (RFC-0026 §1.1).
//!
//! Committed columns: **none** (all three module columns are virtual under RFC-0028 §1.2):
//! - public one-hot `O[i,v] = [i checked]·[v = c_i]`, `lt[i,v] = chk[i,v]·[v < c_i]`, and
//!   `chk[i,v] = row[i]·real[v]` (checked row, real id `v < V`) as two broadcast factors;
//! - virtual contraction `sel_i = Σ_v O[i,v]·L[i,v]`. A vocabulary wider than `2^14` ids
//!   is summed in plan-fixed blocks of `2^14` (`blocks`, virtual contraction) and then
//!   summed over blocks (`selected`, virtual contraction), so each contraction meets the
//!   strict `<= (p − 1)/2` bound (`2^14 · 1 · 2^15 = 2^29 < p/2`), tightened via RFC-0028 A1
//!   signed-16 range checks;
//! - virtual pointwise margin `Mg = row·real·sel − row·real·L − lt`, unsigned 16 range.
//!
//! **Output uniqueness (RFC-0026 §5.2, RFC-0028 §1.2).** Every module column is a fixed
//! polynomial function of the public indicators and int16 logits `L` with no witness advice:
//! `sel_i = L[i, c_i]` on checked rows (and `0` elsewhere), and `Mg >= 0` makes `sel_i` a
//! row maximum while ruling out any earlier tie `v < c_i` (which would give `Mg = −1`).
//! Unchecked rows and padded ids evaluate to `Mg = 0`.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Def, Invalid, Kind, Module, Range, Ref, Relation, Term, Values, Violation, Width,
};

/// Largest summed width of one virtual selection contraction: `2^14 · 1 · 2^15 = 2^29 <= (p - 1)/2`.
const BLOCK_BITS: u8 = 14;
const NAME: &str = "G/argmax";

fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

/// Column ids allocated by [`Argmax::declare`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgmaxColumns {
    pub selected: ColumnId,
    /// Per-block selections when the vocabulary is wider than `2^15`.
    pub blocks: Option<ColumnId>,
    pub margin: ColumnId,
}

/// Greedy check of the checked rows `[r, e)` of one logits column.
#[derive(Clone, Debug)]
pub struct Argmax {
    logits: ColumnId,
    /// `c_i` for checked rows, `None` elsewhere.
    choices: Vec<Option<usize>>,
    vocabulary: usize,
    columns: Option<ArgmaxColumns>,
}

impl Argmax {
    /// Plan data: the head's int16 `logits` column of shape `(T, vocabulary)` with
    /// `T = tokens.len()`, the checked range `[r, e)` and the next token `y`, which is
    /// required exactly when `e = T`. Every checked token must be a real id `< V`.
    pub fn new(
        logits: ColumnId,
        tokens: &[u32],
        (r, e): (usize, usize),
        next: Option<u32>,
        vocabulary: usize,
    ) -> Result<Self, Invalid> {
        let t = tokens.len();
        let shape = || Invalid::Shape {
            relation: NAME.into(),
        };
        if r >= e || e > t || next.is_some() != (e == t) || vocabulary == 0 {
            return Err(shape());
        }
        if log2_ceil(t) + log2_ceil(vocabulary) > stele_ir::relation::MAX_VARS
            || log2_ceil(vocabulary) > 2 * BLOCK_BITS
        {
            return Err(shape());
        }
        let mut choices = vec![None; t];
        for (i, choice) in choices.iter_mut().enumerate().take(e).skip(r) {
            let c = if i + 1 < t {
                tokens[i + 1]
            } else {
                next.ok_or_else(shape)?
            } as usize;
            if c >= vocabulary {
                return Err(shape());
            }
            *choice = Some(c);
        }
        Ok(Self {
            logits,
            choices,
            vocabulary,
            columns: None,
        })
    }

    /// Column ids, once declared.
    pub fn columns(&self) -> Option<ArgmaxColumns> {
        self.columns
    }

    /// `(row bits, vocabulary bits, block bits)`.
    fn bits(&self) -> (u8, u8, u8) {
        let v = log2_ceil(self.vocabulary);
        (
            log2_ceil(self.choices.len()),
            v,
            v.saturating_sub(BLOCK_BITS),
        )
    }

    /// `(O, lt)` at a padded `(i, v)` index.
    fn public(&self, index: usize) -> (i64, i64) {
        let (_, v, _) = self.bits();
        let (i, id) = (index >> v, index & ((1 << v) - 1));
        match self.choices.get(i).copied().flatten() {
            Some(c) if id < self.vocabulary => (i64::from(id == c), i64::from(id < c)),
            _ => (0, 0),
        }
    }
}

impl Module for Argmax {
    /// Logits rows `L[i]` of the executor (`Full::logits`, E16-03 `Head::logits`).
    type Capture = [Vec<i16>];

    fn declare(&mut self, relation: &mut Relation) {
        let (t, v, nb) = self.bits();
        let (n, vb) = (t + v, v - nb);
        let mut public = |label: &str, values: Vec<i64>, log_len: u8| {
            relation.add_column(
                &format!("{NAME}/{label}"),
                Kind::Public(values),
                Width::unsigned(1),
                log_len,
            )
        };
        let (onehot, below): (Vec<_>, Vec<_>) = (0..1usize << n).map(|x| self.public(x)).unzip();
        let onehot = public("onehot", onehot, n);
        let below = public("below", below, n);
        let rows = (0..1usize << t)
            .map(|i| i64::from(self.choices.get(i).copied().flatten().is_some()))
            .collect();
        let rows = public("rows", rows, t);
        let real = (0..1usize << v)
            .map(|id| i64::from(id < self.vocabulary))
            .collect();
        let real = public("real", real, v);
        let ones = (nb > 0).then(|| public("ones", vec![1; 1 << nb], nb));

        let mut add_ranged_virtual = |label: &str, def: Def, width: Width, log_len: u8| {
            let name = format!("{NAME}/{label}");
            let id = relation.add_virtual(&name, def, log_len);
            relation.ranges.push(Range {
                name,
                column: id,
                width,
            });
            id
        };

        // sel_b[i, b] = Σ_{v_low} O[i, b, v_low]·L[i, b, v_low]: free bits (b, i),
        // summed bits v_low (RFC-0028 §1.2 virtual contraction).
        let free = t + nb;
        let read = |column| Ref {
            column,
            vars: (free..free + vb).chain(0..free).collect(),
        };
        let select_def = Def::Contraction {
            free,
            summed: vb,
            lhs: read(onehot),
            rhs: read(self.logits),
        };
        let (blocks, selected) = if let Some(ones) = ones {
            let blocks = add_ranged_virtual("blocks", select_def, Width::signed(16), free);
            let selected = add_ranged_virtual(
                "selected",
                Def::Contraction {
                    free: t,
                    summed: nb,
                    lhs: Ref {
                        column: blocks,
                        vars: (t..t + nb).chain(0..t).collect(),
                    },
                    rhs: Ref {
                        column: ones,
                        vars: (t..t + nb).collect(),
                    },
                },
                Width::signed(16),
                t,
            );
            (Some(blocks), selected)
        } else {
            let selected = add_ranged_virtual("selected", select_def, Width::signed(16), t);
            (None, selected)
        };

        // Virtual pointwise margin: Mg = row·real·sel − row·real·L − lt ∈ [0, 2^16).
        let at = |column| Ref::identity(column, n);
        let (row, real, sel) = (
            Ref {
                column: rows,
                vars: (v..n).collect(),
            },
            Ref::identity(real, v),
            Ref {
                column: selected,
                vars: (v..n).collect(),
            },
        );
        let margin = add_ranged_virtual(
            "margin",
            Def::Pointwise {
                terms: vec![
                    Term {
                        coeff: 1,
                        factors: vec![row.clone(), real.clone(), sel],
                    },
                    Term {
                        coeff: -1,
                        factors: vec![row, real, at(self.logits)],
                    },
                    Term {
                        coeff: -1,
                        factors: vec![at(below)],
                    },
                ],
            },
            Width::unsigned(16),
            n,
        );
        self.columns = Some(ArgmaxColumns {
            selected,
            blocks,
            margin,
        });
    }

    fn assign(
        &self,
        _relation: &Relation,
        capture: &[Vec<i16>],
        _values: &mut Values,
    ) -> Result<(), Violation> {
        let _columns = self.columns.expect("Argmax::assign before declare");
        if capture.len() != self.choices.len()
            || capture.iter().any(|row| row.len() != self.vocabulary)
        {
            return Err(Violation::Missing(self.logits));
        }
        // RFC-0028 §1.2: every Argmax column is virtual; no committed witness values are assigned.
        Ok(())
    }
}

#[cfg(test)]
mod tests;
