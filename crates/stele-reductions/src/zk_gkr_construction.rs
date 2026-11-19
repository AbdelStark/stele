//! RFC-0014 A3. Derive the field construction from real RFC-0008 A7 proof operands.
use super::{
    block_entries, compact_terms, complex, Coord, Error, Gin, GkrStep, Occurrence, Plan, Run,
};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::ChallengeField;
pub use stele_kernels::gkr::{GkrConstruction, GkrFactor, GkrMask, GkrMember, GkrSelector};
use stele_pcs::CodeField;

#[allow(clippy::too_many_arguments)]
pub(in crate::zk::claims) fn inputs<'a, K: ChallengeField + CodeField>(
    plan: &'a Plan<K>,
    step: &'a GkrStep,
    run: &'a Run<K>,
    layers: Option<&'a [Vec<[K; 2]>]>,
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
                let mask = GkrMask {
                    values: block[t * half..(t + 1) * half].to_vec(),
                    coordinates: u,
                    vanishing: *v,
                };
                match layers {
                    Some(host) => GkrFactor::Layer {
                        values: host.get(step.k + 1).ok_or(Error::Statement)?,
                        component: *poly,
                        side: *t,
                        mask,
                    },
                    None => GkrFactor::RetainedLayer {
                        layer: step.k + 1,
                        component: *poly,
                        side: *t,
                        mask,
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
        }
        .into_iter()
        .map(|term| stele_kernels::gkr::Term {
            coefficient: term.coefficient,
            factors: term.factors,
        })
        .collect(),
        factors,
    })
}
