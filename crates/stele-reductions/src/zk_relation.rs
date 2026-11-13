//! RFC-0026 A9 with RFC-0013 A5: any validated development [`Relation`] as one
//! dev-zk claims statement ([`super::claims`]), in QM31.
//!
//! Plan rules (dev-zk, E12-14):
//! - **Sources.** Source 0 holds every witness column in `ColumnId` order (the
//!   stacked source's role, RFC-0026 A4), then each check's multiplicity column.
//!   Source 1, present when the relation has weights, holds every weight column in
//!   `ColumnId` order; its root is the dev-zk model commitment, a public input.
//!   Public columns are never committed or masked; the verifier evaluates them.
//! - **Identities** (§4 step 4): one [`Relation::Combined`] per domain size,
//!   increasing, over that size's identities in relation order and then its
//!   `Compose` identities `column − Σ 2^shift·limb = 0`, as the development
//!   engine combines them. Each distinct `(column, vars)` is one operand.
//! - **Matmuls** (§4 step 6): one [`Relation::Contraction`] each, in relation order.
//! - **Lookups and ranges** (§4 step 5, A3): one check per table in order of first
//!   use by a lookup, then one per range width; a range is a member reading its
//!   column with shift `−width.min()` into `[0, 2^bits)`. Tables are padded to a
//!   power of two with zero rows past `valid`.
//!
//! Variable order: a development `Ref` reads domain bit `vars[j]` for column bit
//! `j` (LSB-first); a claims [`Read`] reads MSB-first, so column coordinate
//! `n − 1 − j` reads domain variable `m − 1 − vars[j]`. Column data is the same
//! array in both conventions.
use super::claims::{
    self, Column, Lifetime, Lookup, Member, ModelSecret, Operand, Proof, Public, Read, Statement,
    Verified,
};
use super::{Error, Seed};
use crate::relation::{digest, K};
use alloc::vec;
use alloc::vec::Vec;
use stele_field::{Field, M31};
use stele_hash::{AbsorbLabel, Transcript};
use stele_ir::relation::{ColumnId, Kind, Ref, Relation, Term as IrTerm, Values};
use stele_sumcheck::Term;

/// Source of the witness columns and multiplicities.
pub const WITNESS: usize = 0;
/// Source of the weight columns, when the relation has any.
pub const WEIGHTS: usize = 1;

/// One check's members as the multiplicity count needs them.
struct CountMember {
    vars: u32,
    tuple: Vec<(ColumnId, Vec<u8>, i64)>,
    selector: Option<Ref>,
}

/// The statement and the column map of a relation.
pub struct Layout {
    /// The verifier-derived claims statement.
    pub statement: Statement<K>,
    /// Statement column `i < committed.len()` is relation column `committed[i]`;
    /// the rest are multiplicities, check by check.
    committed: Vec<ColumnId>,
    counts: Vec<Vec<CountMember>>,
}

impl Layout {
    /// Whether the relation commits weights (source [`WEIGHTS`]).
    pub fn has_weights(&self) -> bool {
        self.statement.sources > WEIGHTS
    }
}

fn ceil_log2(n: usize) -> u32 {
    n.max(1).next_power_of_two().trailing_zeros()
}

/// A development `Ref` over an `m`-variable domain as MSB-first claims variables.
fn vars(r: &Ref, m: u32) -> Vec<u32> {
    r.vars
        .iter()
        .rev()
        .map(|v| match Ref::fixed(*v) {
            Some(0) => Read::FIXED_0,
            Some(_) => Read::FIXED_1,
            None => m - 1 - u32::from(*v),
        })
        .collect()
}

/// Derive the claims statement of a validated relation (verifier and prover).
pub fn layout(relation: &Relation) -> Result<Layout, Error> {
    relation.validate().map_err(|_| Error::Statement)?;
    let kind = |id: ColumnId| &relation.columns[id.0 as usize].kind;
    let witness: Vec<ColumnId> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| matches!(kind(*id), Kind::Witness(_)))
        .collect();
    let weights: Vec<ColumnId> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| matches!(kind(*id), Kind::Weight))
        .collect();
    let committed: Vec<ColumnId> = witness.iter().chain(&weights).copied().collect();
    let mut columns: Vec<Column> = committed
        .iter()
        .map(|id| Column {
            source: if matches!(kind(*id), Kind::Weight) {
                WEIGHTS
            } else {
                WITNESS
            },
            log_len: u32::from(relation.columns[id.0 as usize].log_len),
        })
        .collect();
    let index = |id: ColumnId| committed.iter().position(|c| *c == id);
    let operand = |r: &Ref, m: u32| -> Operand {
        match (kind(r.column), index(r.column)) {
            (Kind::Public(values), _) => Operand::Public(Public {
                values: values.clone(),
                vars: vars(r, m),
            }),
            (_, Some(column)) => Operand::Column(Read {
                column,
                vars: vars(r, m),
            }),
            _ => unreachable!("validated relation"),
        }
    };
    let mut relations = Vec::new();
    // Identities per domain size, increasing; composes after the identities.
    let mut sizes: Vec<u8> = relation.identities.iter().map(|i| i.vars).collect();
    sizes.extend(
        relation
            .composes
            .iter()
            .map(|c| relation.columns[c.column.0 as usize].log_len),
    );
    sizes.sort_unstable();
    sizes.dedup();
    for m in sizes {
        let mut parts: Vec<Vec<IrTerm>> = relation
            .identities
            .iter()
            .filter(|i| i.vars == m)
            .map(|i| i.terms.clone())
            .collect();
        for compose in &relation.composes {
            if relation.columns[compose.column.0 as usize].log_len != m {
                continue;
            }
            let read = |id| vec![Ref::identity(id, m)];
            let mut terms = vec![IrTerm {
                coeff: 1,
                factors: read(compose.column),
            }];
            for &(limb, shift) in &compose.limbs {
                terms.push(IrTerm {
                    coeff: -(1i64 << shift),
                    factors: read(limb),
                });
            }
            parts.push(terms);
        }
        let mut refs: Vec<Ref> = Vec::new();
        let (mut terms, mut owners) = (Vec::new(), Vec::new());
        for (p, part) in parts.iter().enumerate() {
            for term in part {
                let factors = term
                    .factors
                    .iter()
                    .map(|f| {
                        let at = refs.iter().position(|r| r == f).unwrap_or_else(|| {
                            refs.push(f.clone());
                            refs.len() - 1
                        });
                        at as u32
                    })
                    .collect();
                terms.push(Term {
                    coefficient: K::from_i64(term.coeff),
                    factors,
                });
                owners.push(p as u32);
            }
        }
        relations.push(claims::Relation::Combined {
            num_vars: u32::from(m),
            operands: refs.iter().map(|r| operand(r, u32::from(m))).collect(),
            terms,
            parts: owners,
            count: parts.len() as u32,
        });
    }
    for mm in &relation.matmuls {
        let m = u32::from(mm.free) + u32::from(mm.summed);
        relations.push(claims::Relation::Contraction {
            free: u32::from(mm.free),
            summed: u32::from(mm.summed),
            out: operand(&mm.out, m),
            lhs: operand(&mm.lhs, m),
            rhs: operand(&mm.rhs, m),
        });
    }
    // RFC-0026 A3 checks: tables in order of first use, then range widths.
    #[derive(PartialEq)]
    enum Target {
        Table(u32),
        Range(u8),
    }
    let mut targets: Vec<(Target, Vec<CountMember>)> = Vec::new();
    let mut add = |target: Target, member: CountMember| match targets
        .iter_mut()
        .find(|(t, _)| *t == target)
    {
        Some((_, members)) => members.push(member),
        None => targets.push((target, vec![member])),
    };
    for lookup in &relation.lookups {
        add(
            Target::Table(lookup.table.0),
            CountMember {
                vars: u32::from(lookup.vars),
                tuple: lookup
                    .tuple
                    .iter()
                    .map(|r| (r.column, r.vars.clone(), 0))
                    .collect(),
                selector: lookup.selector.clone(),
            },
        );
    }
    for range in &relation.ranges {
        let log_len = relation.columns[range.column.0 as usize].log_len;
        add(
            Target::Range(range.width.bits),
            CountMember {
                vars: u32::from(log_len),
                tuple: vec![(range.column, (0..log_len).collect(), -range.width.min())],
                selector: None,
            },
        );
    }
    let mut lookups = Vec::new();
    let mut counts = Vec::new();
    for (target, members) in targets {
        let rows: Vec<Vec<i64>> = match target {
            Target::Table(t) => relation.tables[t as usize].rows.clone(),
            Target::Range(bits) => (0..1i64 << bits).map(|v| vec![v]).collect(),
        };
        let c = rows.first().map_or(1, Vec::len);
        let k = ceil_log2(rows.len());
        let valid = rows.len();
        let mut table = rows;
        table.resize(1 << k, vec![0; c]);
        let mut spec = Vec::new();
        for member in &members {
            let mut tuple = Vec::new();
            for (column, v, _) in &member.tuple {
                // Virtual or public tuple columns are not admitted (RFC-0008 A6).
                let column = index(*column).ok_or(Error::Statement)?;
                let r = Ref {
                    column: committed[column],
                    vars: v.clone(),
                };
                tuple.push(Read {
                    column,
                    vars: vars(&r, member.vars),
                });
            }
            let selector = match &member.selector {
                None => None,
                Some(r) => match kind(r.column) {
                    Kind::Public(values) => Some(Public {
                        values: values.clone(),
                        vars: vars(r, member.vars),
                    }),
                    _ => return Err(Error::Statement),
                },
            };
            spec.push(Member {
                vars: member.vars,
                tuple,
                shifts: member.tuple.iter().map(|(_, _, s)| *s).collect(),
                selector,
            });
        }
        lookups.push(Lookup {
            members: spec,
            multiplicity: columns.len(),
            table,
            valid,
        });
        columns.push(Column {
            source: WITNESS,
            log_len: k,
        });
        counts.push(members);
    }
    Ok(Layout {
        statement: Statement {
            sources: if weights.is_empty() { 1 } else { 2 },
            columns,
            relations,
            lookups,
        },
        committed,
        counts,
    })
}

/// Column values of every statement column: the relation's committed columns,
/// then each check's multiplicities (each selected entry of a member padded by
/// `pad` variables counts `2^pad` times, RFC-0026 A9). An unmatched tuple is not
/// counted; the verifier rejects the proof.
pub fn columns(
    layout: &Layout,
    relation: &Relation,
    values: &Values,
) -> Result<Vec<Vec<M31>>, Error> {
    let column = |id: ColumnId| values.get(relation, id).ok_or(Error::Statement);
    let mut out = Vec::new();
    for id in &layout.committed {
        out.push(column(*id)?.iter().map(|v| M31::from_i64(*v)).collect());
    }
    let c_d = (<K as stele_pcs::CodeField>::DEGREE as u32).trailing_zeros();
    for (lookup, members) in layout.statement.lookups.iter().zip(&layout.counts) {
        let key =
            |row: &[i64]| -> Vec<u32> { row.iter().map(|v| M31::from_i64(*v).as_u32()).collect() };
        let mut index: Vec<(Vec<u32>, usize)> = lookup
            .table
            .iter()
            .take(lookup.valid)
            .enumerate()
            .map(|(i, row)| (key(row), i))
            .collect();
        index.sort_unstable();
        let mut mult = vec![0i64; lookup.table.len()];
        for member in members {
            let pad = 1i64 << member.vars.max(c_d + 1).saturating_sub(member.vars).min(62);
            let cols = member
                .tuple
                .iter()
                .map(|(id, _, _)| column(*id))
                .collect::<Result<Vec<_>, _>>()?;
            let selector = match &member.selector {
                None => None,
                Some(r) => Some((r, column(r.column)?)),
            };
            for x in 0..1u64 << member.vars {
                if selector.is_some_and(|(r, s)| s[r.index(x)] != 1) {
                    continue;
                }
                let row: Vec<i64> = member
                    .tuple
                    .iter()
                    .zip(&cols)
                    .map(|((_, v, shift), col)| {
                        let r = Ref {
                            column: ColumnId(0),
                            vars: v.clone(),
                        };
                        col[r.index(x)] + shift
                    })
                    .collect();
                if let Ok(p) = index.binary_search_by(|e| e.0.cmp(&key(&row))) {
                    mult[index[p].1] += pad;
                }
            }
        }
        out.push(mult.into_iter().map(M31::from_i64).collect());
    }
    Ok(out)
}

/// The dev-zk weight-source root that `seed` commits: the model commitment a
/// dev-zk public input carries. `None` without weights.
pub fn weight_root(
    relation: &Relation,
    values: &Values,
    seed: &Seed,
) -> Result<Option<[u8; 32]>, Error> {
    let layout = layout(relation)?;
    if !layout.has_weights() {
        return Ok(None);
    }
    let columns = columns(&layout, relation, values)?;
    claims::source_root(&layout.statement, &columns, WEIGHTS, seed).map(Some)
}

/// The per-proof claim-mask need `t` of each weight column, in column order: the
/// blocks a lifetime weight source reserves per proof (RFC-0013 A6).
pub fn weight_blocks(relation: &Relation) -> Result<Vec<usize>, Error> {
    let layout = layout(relation)?;
    let counts = claims::occurrence_counts(&layout.statement)?;
    Ok(layout
        .statement
        .columns
        .iter()
        .zip(counts)
        .filter(|(c, _)| c.source == WEIGHTS)
        .map(|(_, t)| t)
        .collect())
}

/// The lifetime weight source's root, committed once from `model` (RFC-0013 A6).
pub fn lifetime_root(
    relation: &Relation,
    values: &Values,
    lifetime: &Lifetime,
    model: &Seed,
) -> Result<[u8; 32], Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    claims::lifetime_root(&layout.statement, &columns, lifetime, &model.0)
}

/// [`prove`] against a lifetime weight source (RFC-0013 A6): proof
/// `lifetime.index` of at most `lifetime.proofs`. Returns the proof and the
/// opening's row-coefficient vector, for the model secret.
pub fn prove_lifetime(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    seed: Seed,
    lifetime: &Lifetime,
    model: ModelSecret<'_, K>,
) -> Result<(Proof<K>, Vec<K>), Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::prove_lifetime(&layout.statement, &columns, seed, t, lifetime, model)
}

/// [`verify`] against a lifetime weight source whose public root is `root`.
pub fn verify_lifetime(
    t: &mut Transcript<K>,
    relation: &Relation,
    root: [u8; 32],
    lifetime: &Lifetime,
    proof: &Proof<K>,
) -> Result<Verified<K>, Error> {
    let layout = layout(relation)?;
    let bound = proof
        .sources
        .get(WEIGHTS)
        .and_then(|bytes| stele_pcs::Source::<K>::from_bytes(bytes).ok())
        .is_some_and(|s| s.root() == root);
    if !layout.has_weights() || lifetime.source != WEIGHTS || !bound {
        return Err(Error::Pcs(stele_pcs::Error::Merkle(
            stele_hash::merkle::Error::RootMismatch,
        )));
    }
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::verify_lifetime(&layout.statement, Some(lifetime), proof, t)
}

/// Prove `relation` on `values` under dev-zk after the caller's statement frames:
/// `relation/statement` (the relation digest), then the claims proof.
pub fn prove(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    seed: Seed,
) -> Result<Proof<K>, Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::prove(&layout.statement, &columns, seed, t)
}

/// Controls only, never a verifier input: [`prove`] on a false witness with
/// claims relation `index` sent by `claims::forge_unchecked` (honest rounds, true
/// `μ`, no producer self-check). That relation's first-round check rejects it.
#[cfg(feature = "controls")]
pub fn forge(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    seed: Seed,
    index: usize,
) -> Result<Proof<K>, Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::forge_unchecked(&layout.statement, &columns, seed, t, index)
}

/// Controls only, never a verifier input: an honest proof of `used` (a relation
/// that differs from `relation` in one public column) under `relation`'s digest.
/// Every round is honest for `used`; only the verifier's own evaluation of that
/// public column's final rejects it (`ClaimMismatch`).
#[cfg(feature = "controls")]
pub fn forge_substituted(
    t: &mut Transcript<K>,
    relation: &Relation,
    used: &Relation,
    values: &Values,
    seed: Seed,
) -> Result<Proof<K>, Error> {
    let layout = layout(used)?;
    let columns = columns(&layout, used, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::prove(&layout.statement, &columns, seed, t)
}

/// The privacy tests' exact leak count on `relation` (`claims::leaks`), replaying
/// the verifier from the caller's transcript.
#[cfg(feature = "controls")]
pub fn leaks(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    proof: &Proof<K>,
) -> Result<claims::Leaks<K>, Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::leaks(&layout.statement, &columns, proof, t)
}

/// [`leaks`] of a dev-zk proof with its lifetime weight source (RFC-0013 A6), under
/// the lifetime's geometry (RFC-0013 A8).
#[cfg(feature = "controls")]
pub fn leaks_lifetime(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    lifetime: &Lifetime,
    proof: &Proof<K>,
) -> Result<claims::Leaks<K>, Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::leaks_lifetime(&layout.statement, Some(lifetime), &columns, proof, t)
}

/// The privacy tests' leak control: [`prove`] through `claims::prove_unmasked`.
#[cfg(feature = "controls")]
pub fn prove_unmasked(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    seed: Seed,
) -> Result<Proof<K>, Error> {
    let layout = layout(relation)?;
    let columns = columns(&layout, relation, values)?;
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::prove_unmasked(&layout.statement, &columns, seed, t)
}

/// The claims relation index of check `l`'s `Σ h = 0` (RFC-0008 A7 item 3).
pub fn check_sum(layout: &Layout, l: usize) -> usize {
    layout.statement.relations.len() + 2 * l + 1
}

/// Verify a dev-zk relation proof. `weights` is the public weight-source root;
/// the proof's weight source must carry it (`RootMismatch`).
pub fn verify(
    t: &mut Transcript<K>,
    relation: &Relation,
    weights: Option<[u8; 32]>,
    proof: &Proof<K>,
) -> Result<Verified<K>, Error> {
    let layout = layout(relation)?;
    let bound = match (layout.has_weights(), weights) {
        (false, None) => true,
        (true, Some(root)) => proof
            .sources
            .get(WEIGHTS)
            .and_then(|bytes| stele_pcs::Source::<K>::from_bytes(bytes).ok())
            .is_some_and(|s| s.root() == root),
        _ => false,
    };
    if !bound {
        return Err(Error::Pcs(stele_pcs::Error::Merkle(
            stele_hash::merkle::Error::RootMismatch,
        )));
    }
    t.absorb(AbsorbLabel::RelationStatement, &digest(relation))
        .map_err(|e| Error::Sumcheck(e.into()))?;
    claims::verify(&layout.statement, proof, t)
}
