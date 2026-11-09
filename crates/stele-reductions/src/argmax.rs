//! Greedy argmax check of the development-profile relation (RFC-0026 §5 row 13, task
//! E16-09).
//!
//! Integer definition (RFC-0025 §2.6): the checked token `c_i` of row `i ∈ [r, e)` is the
//! least vocabulary id attaining the row maximum of the int16 logits. `c_i = x_{i+1}`
//! for `i < T−1` and the next token `y` for `i = T−1` (RFC-0026 §1.1).
//!
//! Columns on the logits layout `(i, v)` (`v` padded to `2^nv`, row index high):
//! - public one-hot `O[i,v] = [i checked]·[v = c_i]`, `lt[i,v] = chk[i,v]·[v < c_i]`, and
//!   `chk[i,v] = row[i]·real[v]` (checked row, real id `v < V`) as two broadcast factors;
//! - `sel_i = Σ_v O[i,v]·L[i,v]` by matmul. A vocabulary wider than `2^15` ids is
//!   summed in plan-fixed blocks of `2^15` (the block bits are free bits of the first
//!   matmul, `sel_b`), then over blocks, so each matmul meets the §3.6 bound;
//! - the margin `Mg = chk·(sel − L) − lt`, unsigned 16 (one identity, one range).
//!
//! `Mg ≥ 0` makes `sel_i` a maximum, and every `v < c_i` attaining it would give
//! `Mg = −1`; unchecked rows and padded ids have `Mg = 0`, so they never compete. The
//! soundness argument is RFC-0026 §5 row 13; the lemma is in
//! `agents/reviews/e16-09-residual-argmax.md`.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, GroupId, Identity, Invalid, Kind, Matmul, Module, Range, Ref, Relation, Term, Values,
    Violation, Width,
};

/// Largest summed width of one selection matmul: `2^15 + 2^15·1·2^15 < p`.
const BLOCK_BITS: u8 = 15;
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

    fn group(relation: &mut Relation, n: u8) -> GroupId {
        let name = format!("{NAME}/{n}");
        match relation.groups.iter().position(|g| g.name == name) {
            Some(g) => GroupId(g as u32),
            None => relation.add_group(&name, n),
        }
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

        let mut witness = |label: &str, width: Width, log_len: u8| {
            let group = Self::group(relation, log_len);
            let name = format!("{NAME}/{label}");
            let id = relation.add_column(&name, Kind::Witness(group), width, log_len);
            relation.ranges.push(Range {
                name,
                column: id,
                width,
            });
            id
        };
        let selected = witness("selected", Width::signed(16), t);
        let blocks = ones.map(|_| witness("blocks", Width::signed(16), t + nb));
        let margin = witness("margin", Width::unsigned(16), n);

        // sel_b[i, b] = Σ_{v_low} O[i, b, v_low]·L[i, b, v_low]: free bits (b, i),
        // summed bits v_low.
        let free = t + nb;
        let read = |column| Ref {
            column,
            vars: (free..free + vb).chain(0..free).collect(),
        };
        relation.matmuls.push(Matmul {
            name: format!("{NAME}/select"),
            free,
            summed: vb,
            out: Ref::identity(blocks.unwrap_or(selected), free),
            lhs: read(onehot),
            rhs: read(self.logits),
        });
        if let (Some(blocks), Some(ones)) = (blocks, ones) {
            // sel[i] = Σ_b sel_b[i, b].
            relation.matmuls.push(Matmul {
                name: format!("{NAME}/block_sum"),
                free: t,
                summed: nb,
                out: Ref::identity(selected, t),
                lhs: Ref {
                    column: blocks,
                    vars: (t..t + nb).chain(0..t).collect(),
                },
                rhs: Ref {
                    column: ones,
                    vars: (t..t + nb).collect(),
                },
            });
        }
        // Mg − row·real·sel + row·real·L + lt = 0.
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
        relation.identities.push(Identity {
            name: format!("{NAME}/greedy"),
            vars: n,
            terms: vec![
                Term {
                    coeff: 1,
                    factors: vec![at(margin)],
                },
                Term {
                    coeff: -1,
                    factors: vec![row.clone(), real.clone(), sel],
                },
                Term {
                    coeff: 1,
                    factors: vec![row, real, at(self.logits)],
                },
                Term {
                    coeff: 1,
                    factors: vec![at(below)],
                },
            ],
        });
        self.columns = Some(ArgmaxColumns {
            selected,
            blocks,
            margin,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &[Vec<i16>],
        values: &mut Values,
    ) -> Result<(), Violation> {
        let columns = self.columns.expect("Argmax::assign before declare");
        if capture.len() != self.choices.len()
            || capture.iter().any(|row| row.len() != self.vocabulary)
        {
            return Err(Violation::Missing(self.logits));
        }
        let (t, v, nb) = self.bits();
        let vb = v - nb;
        let mut selected = vec![0; 1 << t];
        let mut blocks = vec![0; 1 << (t + nb)];
        let mut margin = vec![0; 1 << (t + v)];
        for (i, (choice, row)) in self.choices.iter().zip(capture).enumerate() {
            let Some(c) = *choice else { continue };
            let sel = i64::from(row[c]);
            selected[i] = sel;
            blocks[(i << nb) | (c >> vb)] = sel;
            for (id, l) in row.iter().enumerate() {
                margin[(i << v) | id] = sel - i64::from(*l) - i64::from(id < c);
            }
        }
        values.set(relation, columns.selected, selected)?;
        if let Some(id) = columns.blocks {
            values.set(relation, id, blocks)?;
        }
        values.set(relation, columns.margin, margin)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
