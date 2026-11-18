//! RFC-0008 A7: borrowed construction inputs for the bench-only GKR observer.
//! Columns, layers, selectors and tables remain borrowed; only descriptors and
//! small mask blocks are copied. These private values are never public inventory.
use super::{
    block_entries, compact_terms, complex, Coord, Error, Gin, GkrStep, Occurrence, Plan, Run,
};
use alloc::vec::Vec;
use core::ops::Range;
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_pcs::CodeField;
use stele_sumcheck::Term;

/// Unmaterialized inputs in the actual compact producer's order.
/// Creating this receipt is host work. It neither evaluates factors nor changes
/// the CPU proof; consumers must compare with `GkrCase::reference` independently.
pub struct GkrConstruction<'a, K> {
    /// Full sumcheck domain, with the selector coordinate first when present.
    pub num_vars: u32,
    /// Variables in one layer half, excluding the leading selector coordinate.
    pub layer_variables: usize,
    /// Original declared round degree, including vanishing masks.
    pub degree: usize,
    /// Actual producer terms, from the production term builder.
    pub terms: Vec<Term<K>>,
    /// Original factor order; no full-domain table is allocated here.
    pub factors: Vec<GkrFactor<'a, K>>,
}

/// An occurrence's small mask block and original full-domain coordinates.
pub struct GkrMask<'a> {
    /// M31 block values, in MSB-first coordinate order.
    pub values: Vec<M31>,
    /// Domain coordinates indexing the block.
    pub coordinates: &'a [usize],
    /// Coordinate of `kappa(t) = t(1-t)`.
    pub vanishing: usize,
}

/// A concatenated selector member; the first containing range owns a position.
pub struct GkrSelector<'a> {
    /// Range in the layer half, after member padding.
    pub range: Range<usize>,
    /// Original public values and half-domain coordinates; `None` means one.
    pub values: Option<(&'a [i64], &'a [usize])>,
}

/// One member of a compact tuple factor, in production member order.
pub struct GkrMember<'a, K> {
    /// Range in the layer half, after member padding.
    pub range: Range<usize>,
    /// Original field-valued column; no domain expansion or shift is applied.
    pub values: &'a [K],
    /// MSB-first column-index coordinates in the layer half.
    pub coordinates: &'a [usize],
    /// Integer shift applied after gathering the column.
    pub shift: i64,
    /// Small mask block, indexed by the lowest `log2(mask.len())` half bits.
    pub mask: Vec<M31>,
}

/// A factor's exact construction, before masking and folding.
/// Half-domain values repeat across the leading selector bit. Equality factors
/// instead occupy only their specified interval and are zero elsewhere.
pub enum GkrFactor<'a, K> {
    /// `scale * eq(point, index-offset)` on `offset..offset+2^point.len()`.
    Equality {
        /// Original challenge point, MSB first.
        point: &'a [K],
        /// Incoming kappa coefficient, or one for the head.
        scale: K,
        /// Starting index in the full domain.
        offset: usize,
    },
    /// Interpolate the block's two halves at `point`, then tile the period.
    Block {
        /// Both M31 halves, first `T=0`, then `T=1`.
        values: Vec<M31>,
        /// Actual line-fold challenge.
        point: K,
    },
    /// Gather a committed column over the full domain.
    Column {
        /// Original field-valued column, borrowed without cloning.
        values: &'a [K],
        /// MSB-first column-index coordinates in the full domain.
        coordinates: Vec<usize>,
        /// Occurrence mask.
        mask: GkrMask<'a>,
    },
    /// Gather `values[2*x+side][component]` in each half.
    Layer {
        /// Original child-layer numerator/denominator pairs.
        values: &'a [[K; 2]],
        /// Zero for the numerator, one for the denominator.
        component: usize,
        /// Zero or one, the child coordinate.
        side: usize,
        /// Child's half of its layer mask block.
        mask: GkrMask<'a>,
    },
    /// One when the half-domain index is below `2^variables`, else zero.
    Pad {
        /// Original multiplicity/table domain variables.
        variables: usize,
    },
    /// Concatenated public selector, zero off every member.
    Selector {
        /// Members in the original order, including padded ranges.
        members: Vec<GkrSelector<'a>>,
    },
    /// `alpha - sum(beta^i * row[i])` below `valid`; one on padding.
    Table {
        /// Original public rows; no compression or padding is materialized.
        rows: &'a [Vec<i64>],
        /// Valid row count, excluding padding.
        valid: usize,
        /// Actual table challenge.
        alpha: K,
        /// Actual tuple-compression challenge.
        beta: K,
    },
    /// Concatenated shifted column and mask, both zero off every member.
    /// Production writes column ranges first-to-last and mask owners last-to-first;
    /// validated member ranges are disjoint. No owner table is materialized.
    Combined {
        /// One entry per member for this tuple coordinate.
        members: Vec<GkrMember<'a, K>>,
        /// Shared vanishing coordinate in the full domain.
        vanishing: usize,
    },
}

#[allow(clippy::too_many_arguments)]
pub(in crate::zk::claims) fn inputs<'a, K: ChallengeField + CodeField>(
    plan: &'a Plan<K>,
    step: &'a GkrStep,
    run: &'a Run<K>,
    layers: &'a [Vec<[K; 2]>],
    data: &'a [Vec<K>],
    shared: &[M31],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
) -> Result<GkrConstruction<'a, K>, Error> {
    let lp = &plan.lookups[step.lookup];
    let compact = complex(step, lp);
    let mut factors = Vec::new();
    let mut members = Vec::new();
    let mut seen_mult = false;
    for input in &step.inputs {
        let factor = match input {
            Gin::Head => GkrFactor::Equality {
                point: &run.r,
                scale: K::from_i64(1),
                offset: 0,
            },
            Gin::Select(poly) => GkrFactor::Equality {
                point: &run.incoming[*poly].1,
                scale: run.incoming[*poly].0,
                offset: 1usize << step.k,
            },
            Gin::Block(poly) => GkrFactor::Block {
                values: block_entries(plan, shared, lp.block(step.k, *poly)),
                point: run.tstar,
            },
            Gin::Leaf(o) if compact && seen_mult => {
                members.push(o);
                continue;
            }
            Gin::Member(_) => continue,
            Gin::Top(o) | Gin::Leaf(o) => {
                seen_mult |= matches!(input, Gin::Leaf(_));
                GkrFactor::Column {
                    values: &data[o.column],
                    coordinates: o
                        .coords
                        .iter()
                        .map(|c| match c {
                            Coord::Var(q) => Ok(*q),
                            // A7 GKR columns have only domain coordinates; refuse an
                            // unsupported future plan instead of silently projecting.
                            _ => Err(Error::Statement),
                        })
                        .collect::<Result<_, _>>()?,
                    mask: GkrMask {
                        values: block_of(o),
                        coordinates: &o.u,
                        vanishing: o.v,
                    },
                }
            }
            Gin::Layer { poly, t, v, u } => {
                let block = block_entries(plan, shared, lp.block(step.k + 1, *poly));
                let half = block.len() / 2;
                GkrFactor::Layer {
                    values: &layers[step.k + 1],
                    component: *poly,
                    side: *t,
                    mask: GkrMask {
                        values: block[t * half..(t + 1) * half].to_vec(),
                        coordinates: u,
                        vanishing: *v,
                    },
                }
            }
            Gin::Pad => GkrFactor::Pad { variables: lp.k },
            Gin::Selector => GkrFactor::Selector {
                members: lp
                    .members
                    .iter()
                    .map(|m| GkrSelector {
                        range: m.offset..m.offset + (1usize << m.m),
                        values: m
                            .selector
                            .as_ref()
                            .map(|(v, c)| (v.as_slice(), c.as_slice())),
                    })
                    .collect(),
            },
            Gin::Table => {
                if compact {
                    let vanishing = members.first().ok_or(Error::Statement)?.v;
                    if members.len() != lp.members.len() * lp.c {
                        return Err(Error::Statement);
                    }
                    for i in 0..lp.c {
                        factors.push(GkrFactor::Combined {
                            members: lp
                                .members
                                .iter()
                                .enumerate()
                                .map(|(m, member)| {
                                    let (column, coords) = &member.tuple[i];
                                    GkrMember {
                                        range: member.offset..member.offset + (1usize << member.m),
                                        values: &data[*column],
                                        coordinates: coords,
                                        shift: member.shifts[i],
                                        mask: block_of(members[m * lp.c + i]),
                                    }
                                })
                                .collect(),
                            vanishing,
                        });
                    }
                }
                GkrFactor::Table {
                    rows: &lp.table,
                    valid: lp.valid,
                    alpha: run.alpha,
                    beta: run.beta,
                }
            }
        };
        factors.push(factor);
    }
    Ok(GkrConstruction {
        num_vars: step.num_vars,
        layer_variables: step.k,
        degree: step.degree,
        terms: if compact {
            compact_terms(step, lp, run.lambda, run.alpha, run.beta)
        } else {
            super::terms(step, lp, run.lambda, run.alpha, run.beta)
        },
        factors,
    })
}
