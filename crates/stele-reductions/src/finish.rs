//! Final norm, final row conversion, head projection and greedy check of the
//! development-profile relation (RFC-0026 §5 rows 12-13, task E16-09).
//!
//! Integer definition (RFC-0025 §2.5-2.6; executor `Executor::finish`): the last
//! residual cut `R_L` is normalised by the configured `rmsnorm_q`, the whole row is
//! converted under the Model's final policy, the head projects it to int16 logits in
//! units `2^-fl` (`fl ∈ [0, 30]`, unbiased), and each checked token is the least id
//! attaining its row's maximum.
//!
//! This module adds no relation of its own. It composes, in plan order:
//! - [`RmsNorm`] (E16-04, row 2) reading `R_L`, scope `G/norm`;
//! - [`RowConversion`] (E16-05, row 3) reading the norm output, prefix `G/row`;
//! - [`Projection`] (E16-05, row 4) reading that row, prefix `G/head`. Its weight is
//!   the head source, declared here in plan order (after every layer), or the
//!   embedding's column for a tied head (RFC-0026 §2.2);
//! - [`Argmax`] (row 13) reading the head output as the logits.
//!
//! Wiring passes `ColumnId`s only (RFC-0026 §3.8). Output uniqueness is the
//! composition of the four modules' lemmas along RFC-0026 §5.1.

use crate::argmax::Argmax;
use crate::development::rmsnorm::{RmsNorm, RmsNormPlan, RmsNormRow};
use crate::development::{
    ConversionCapture, Policy, Projection, ProjectionCapture, ProjectionPlan, RowConversion,
    Unsupported,
};
use alloc::vec::Vec;
use stele_ir::relation::{Column, ColumnId, Invalid, Kind, Module, Relation, Values, Violation};

/// Plan data of the model boundary after the last block.
#[derive(Clone, Debug)]
pub struct FinishPlan {
    /// The final `rmsnorm_q` descriptor and gains; `rows` is `T`.
    pub norm: RmsNormPlan,
    /// The Model's final row policy.
    pub policy: Policy,
    /// The head: `rows = T`, `inner = d`, `outputs = V`, shift `e − f + fl`.
    pub head: ProjectionPlan,
    /// A tied head reads this (embedding) weight column instead of its own source.
    pub tied: Option<ColumnId>,
    /// Statement: tokens `x`, checked range `[r, e)` and next token `y` (RFC-0026 §1.1).
    pub tokens: Vec<u32>,
    pub checked: (usize, usize),
    pub next: Option<u32>,
}

/// Why a plan or statement cannot be declared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinishError {
    /// Outside the supported model class (RFC-0026 §1.3 `UnsupportedModel`).
    Unsupported(Unsupported),
    /// A malformed checked range, next token or out-of-vocabulary token.
    Statement(Invalid),
}

/// Executor intermediates of the model boundary (E16-03 `Capture::head`, mapped).
#[derive(Clone, Debug)]
pub struct FinishCapture {
    pub norm: Vec<RmsNormRow>,
    pub row: ConversionCapture,
    /// Codes and scales repeat `row`'s; `outputs` are the logits.
    pub head: ProjectionCapture,
}

/// Column ids of the composed modules, once declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinishColumns {
    pub normalised: ColumnId,
    pub codes: ColumnId,
    pub weight: ColumnId,
    pub logits: ColumnId,
}

/// RFC-0026 §5 rows 12-13 over `R_L`.
pub struct Finish {
    plan: FinishPlan,
    input: ColumnId,
    norm: Option<RmsNorm>,
    row: Option<RowConversion>,
    head: Option<Projection>,
    argmax: Option<Argmax>,
}

impl Finish {
    /// Checks every module plan and the statement by declaring into a scratch copy of
    /// `relation`, the relation `declare` will later extend.
    pub fn new(
        plan: FinishPlan,
        input: ColumnId,
        relation: &Relation,
    ) -> Result<Self, FinishError> {
        // One row per token, T a power of two: a same-log2 mismatch (60 tokens against
        // 64 rows) would otherwise move the row that is checked against y.
        let t = plan.tokens.len();
        if !t.is_power_of_two() || plan.head.rows != t || plan.norm.rows != t {
            return Err(FinishError::Statement(Invalid::Shape {
                relation: "G/finish".into(),
            }));
        }
        let mut this = Self {
            plan,
            input,
            norm: None,
            row: None,
            head: None,
            argmax: None,
        };
        // A scratch copy of `relation`'s columns and groups (public values dropped)
        // stands in for it, so upstream ids such as `input` and `tied` resolve.
        let mut scratch = Relation {
            groups: relation.groups.clone(),
            columns: relation
                .columns
                .iter()
                .map(|c| Column {
                    kind: match c.kind {
                        Kind::Public(_) => Kind::Weight,
                        ref kind => kind.clone(),
                    },
                    ..c.clone()
                })
                .collect(),
            ..Relation::default()
        };
        this.build(&mut scratch)?;
        (this.norm, this.row, this.head, this.argmax) = (None, None, None, None);
        Ok(this)
    }

    fn build(&mut self, relation: &mut Relation) -> Result<(), FinishError> {
        let p = &self.plan;
        let unsupported = FinishError::Unsupported;
        let mut norm = RmsNorm::new(p.norm.clone(), self.input, "G/norm").map_err(unsupported)?;
        norm.declare(relation);
        let normalised = norm.output().expect("declared");
        let (rows, inner) = (p.head.rows, p.head.inner);
        let mut row =
            RowConversion::new("G/row", normalised, rows, inner, p.policy).map_err(unsupported)?;
        row.declare(relation);
        let mut head = Projection::new(
            "G/head",
            row.output().expect("declared"),
            p.tied,
            p.head.clone(),
        )
        .map_err(unsupported)?;
        head.declare(relation);
        let logits = head.output().expect("declared");
        let mut argmax = Argmax::new(logits, &p.tokens, p.checked, p.next, p.head.outputs)
            .map_err(FinishError::Statement)?;
        argmax.declare(relation);
        (self.norm, self.row, self.head, self.argmax) =
            (Some(norm), Some(row), Some(head), Some(argmax));
        Ok(())
    }

    /// Column ids, once declared.
    pub fn columns(&self) -> Option<FinishColumns> {
        let (norm, row, head) = (self.norm.as_ref()?, self.row.as_ref()?, self.head.as_ref()?);
        Some(FinishColumns {
            normalised: norm.output()?,
            codes: row.output()?.codes,
            weight: head.weight()?,
            logits: head.output()?,
        })
    }

    /// The greedy check, once declared.
    pub fn argmax(&self) -> Option<&Argmax> {
        self.argmax.as_ref()
    }
}

impl Module for Finish {
    type Capture = FinishCapture;

    fn declare(&mut self, relation: &mut Relation) {
        self.build(relation).expect("validated by Finish::new");
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &FinishCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let missing = || Violation::Missing(self.input);
        let (norm, row, head, argmax) = (
            self.norm.as_ref().ok_or_else(missing)?,
            self.row.as_ref().ok_or_else(missing)?,
            self.head.as_ref().ok_or_else(missing)?,
            self.argmax.as_ref().ok_or_else(missing)?,
        );
        norm.assign(relation, &capture.norm, values)?;
        row.assign(relation, &capture.row, values)?;
        head.assign(relation, &capture.head, values)?;
        let logits: Vec<Vec<i16>> = capture
            .head
            .outputs
            .iter()
            .map(|r| {
                r.iter()
                    .map(|&v| i16::try_from(v).unwrap_or(i16::MAX))
                    .collect()
            })
            .collect();
        argmax.assign(relation, &logits, values)
    }
}

#[cfg(test)]
mod tests;
