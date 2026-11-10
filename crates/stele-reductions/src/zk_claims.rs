//! RFC-0013 A5 items 1–6 with RFC-0026 A9: masked claims, identity and matmul
//! zero-sums, the shared mask source and per-source batching (dev-zk components).
//!
//! Defined for no profile (A5 item 8); task E12-14 wires it into the development
//! prover and verifier. Order on the caller's transcript:
//!
//! 1. Every claim source (a hiding source of committed columns with their claim
//!    masks), then the shared mask source: bytes absorbed together (`FieldSources`),
//!    certificates on their own A9 transcripts.
//! 2. Each relation in plan order: its public draws (`ZeroWeight` for an identity's
//!    `τ`, `RelationPoint` for a matmul's free point), then one masked A1 sumcheck
//!    on the `V̇` of A5 item 2, its mask bound by the shared source.
//! 3. Each claim source with claims: `γ_a` (`BatchCoefficient`), the zero-weight
//!    batch of item 5 (mask in the shared source), one point opening.
//! 4. The shared source: `γ_j` over every `μ_j`, the item-5 batch with its own
//!    RFC-0013 A4 two-block mask source (item 5a), one point opening.
//!
//! Plan rules fixed here (not protocol choices of the RFC; E12-14 may replace them
//! with the development plan's): a claim source holds its columns in index order,
//! each followed by its `t_x` blocks of `D` entries, packed from data position 0,
//! with `R = 2D` rows and `C = 2^m ≥ 2^9` columns. The shared source holds each
//! masked instance's plain mask `g_j` (relations, then batches) as `n_j(δ_j + 1)`
//! consecutive columns, limb `d` in data row `d`. Ids: claim sources `0..S`, the
//! shared source `S`, relations `S + 1 + j`, batches after them, the shared batch
//! last; every mask stream is therefore used once per proof.
use super::{basis, prove_at, Error, Seed, BLOWUP, MIN_M};
use alloc::vec;
use alloc::vec::Vec;
use stele_field::{Inverse, Serialize, M31};
use stele_hash::mask::{MaskStream, SOURCE_MASK};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_point, CodeField, PreparedSource, Source, VerifiedCertificate,
};
use stele_sumcheck::masked::{self, Mask, MaskRecord};
use stele_sumcheck::{Dense, Instance, Reduction, Summand, Term};

/// A committed column of `2^log_len` M31 entries in claim source `source`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    /// Index of its claim source.
    pub source: usize,
    /// Log2 of its length.
    pub log_len: u32,
}

/// One masked occurrence of a column in an identity: column coordinate `j`
/// (MSB-first) reads domain variable `vars[j]`; other domain variables broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Read {
    /// Index into [`Statement::columns`].
    pub column: usize,
    /// Distinct domain variables, one per column coordinate.
    pub vars: Vec<u32>,
}

/// A relation instance in A1 form (RFC-0026 A9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Relation<K> {
    /// `Σ_x eq(τ, x)·Σ_k c_k·Π_{f ∈ k} V̇_f(x) = 0` over `num_vars` variables,
    /// padded to `c_D + 1`. Term factors index `reads` (at most three per term).
    Identity {
        /// Domain variables before padding.
        num_vars: u32,
        /// One masked occurrence each.
        reads: Vec<Read>,
        /// Terms over `reads`; `eq(τ, ·)` is prepended to each.
        terms: Vec<Term<K>>,
    },
    /// `out(i, j) = Σ_k lhs(i, k)·rhs(k, j)` as the zero-sum
    /// `Σ_y [V̇_lhs(ρ_i, y)·V̇_rhs(y, ρ_j) − 2^{−inner}·Ȯ(ρ, y)] = 0`, `y` padded to
    /// `c_D + 1` variables; `out~(ρ)` is never sent.
    Matmul {
        /// Column `(i ‖ k)`.
        lhs: usize,
        /// Column `(k ‖ j)`.
        rhs: usize,
        /// Column `(i ‖ j)`.
        out: usize,
        /// Bits of `i`, `k` and `j`.
        rows: u32,
        /// Bits of `k`.
        inner: u32,
        /// Bits of `j`.
        cols: u32,
    },
}

/// The public statement: claim sources, committed columns and relations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement<K> {
    /// Number of claim sources.
    pub sources: usize,
    /// Committed columns.
    pub columns: Vec<Column>,
    /// Relations in plan order.
    pub relations: Vec<Relation<K>>,
}

/// One linear claim `value = Σ weight·X[position]` on a source's data message
/// (row-major, `R × C`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim<K> {
    /// Sparse data weights.
    pub weights: Vec<(usize, K)>,
    /// The claimed value.
    pub value: K,
}

/// A batch of A5 item 5 on a plain-masked instance, with its point opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<K> {
    /// The masked A1 rounds of `Σ (1 − w)·W·M̃'`, finals `[W', M']` and `μ`.
    pub sumcheck: masked::Proof<K>,
    /// The A9 point opening of the source at the final point.
    pub opening: Vec<u8>,
}

/// A dev-zk claims proof (A5 items 1–6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// Claim sources' exact version-3 bytes, then the shared mask source's.
    pub sources: Vec<Vec<u8>>,
    /// Their A9 certificates, in the same order.
    pub certificates: Vec<Vec<u8>>,
    /// One masked sumcheck per relation, in plan order.
    pub relations: Vec<masked::Proof<K>>,
    /// One batch per claim source with claims, in source order.
    pub batches: Vec<Batch<K>>,
    /// The shared source's batch, with its A4 mask source.
    pub shared: super::Proof<K>,
    /// The shared source's point opening.
    pub shared_opening: Vec<u8>,
}

/// What an accepted proof leaves: every A1 reduction (relations, batches, shared
/// batch, in order) with its SC record, and one MASK record per masked instance.
/// Every claim is already discharged by its source's opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<K> {
    /// Reductions in transcript order; relation `j` is entry `j`.
    pub reductions: Vec<Reduction<K>>,
    /// MASK records in the same order.
    pub masks: Vec<MaskRecord>,
}

fn dim<K: CodeField>() -> usize {
    <K as CodeField>::DEGREE as usize
}

fn zero<K: ChallengeField>() -> K {
    K::from_i64(0)
}

fn kappa<K: ChallengeField>(t: K) -> K {
    t * (K::from_i64(1) - t)
}

fn ceil_log2(n: usize) -> u8 {
    n.max(1).next_power_of_two().trailing_zeros() as u8
}

fn element<K: ChallengeField>(x: M31) -> K {
    K::from_i64(i64::from(x.as_u32()))
}

fn limbs<K: ChallengeField + CodeField>(value: K) -> Result<Vec<M31>, Error> {
    let bytes = value.to_le_bytes();
    (0..dim::<K>())
        .map(|d| {
            let limb = bytes.as_ref()[4 * d..4 * d + 4]
                .try_into()
                .map_err(|_| Error::MaskSource)?;
            M31::from_le_bytes(limb).ok_or(Error::MaskSource)
        })
        .collect()
}

/// A column coordinate: a domain variable or a coordinate of the drawn point.
#[derive(Clone, Copy, Debug)]
enum Coord {
    Var(usize),
    Free(usize),
}

/// One masked occurrence: column, coordinates, vanishing variable `v`, mask
/// coordinates `u` and its block index in the column's claim mask.
#[derive(Clone, Debug)]
struct Occurrence {
    column: usize,
    coords: Vec<Coord>,
    v: usize,
    u: Vec<usize>,
    block: usize,
}

/// A relation's plan: its instance shape, draws and occurrences.
struct Step<K> {
    id: u64,
    num_vars: u32,
    /// Identity: `eq(τ, ·)` is input 0 and `τ` has `num_vars` draws.
    eq: bool,
    label: ChallengeLabel,
    draws: usize,
    occurrences: Vec<Occurrence>,
    terms: Vec<Term<K>>,
    degree: usize,
}

/// A claim source's layout: `R = 2^ell`, `C = 2^m`, each column's offset and its
/// first block's offset.
struct Layout {
    ell: u8,
    m: u8,
    offsets: Vec<(usize, usize)>,
}

struct Plan<K> {
    steps: Vec<Step<K>>,
    /// Per column: (offset, first block offset) in its source; per source: (ell, m).
    layouts: Vec<Layout>,
    /// Sources with at least one claim, in order.
    batched: Vec<usize>,
    /// Every masked instance's (id, num_vars, degree): relations, then batches.
    masks: Vec<(u64, u32, usize)>,
    /// Column offset of each mask in the shared source, and its `(ell, m)`.
    shared_offsets: Vec<usize>,
    shared: (u8, u8),
}

impl<K: ChallengeField + CodeField> Plan<K> {
    fn source_id(&self, s: usize) -> u64 {
        s as u64
    }
    fn shared_id(&self) -> u64 {
        self.layouts.len() as u64
    }
    fn shared_batch_id(&self) -> u64 {
        self.shared_id() + 1 + self.masks.len() as u64
    }
}

/// A5 item 2's default: `v` is the lowest-index variable not used as `v` by an
/// earlier occurrence sharing a term; `u` the `c_D` lowest-index others. The
/// degree is the per-variable maximum over terms (item 3).
fn assign<K>(
    num_vars: usize,
    occurrences: &mut [Occurrence],
    first: usize,
    terms: &[Term<K>],
    c: usize,
) -> usize {
    let shares = |a: usize, b: usize| {
        terms.iter().any(|t| {
            t.factors.contains(&((first + a) as u32)) && t.factors.contains(&((first + b) as u32))
        })
    };
    for a in 0..occurrences.len() {
        let used: Vec<usize> = (0..a)
            .filter(|&b| shares(a, b))
            .map(|b| occurrences[b].v)
            .collect();
        let v = (0..num_vars).find(|q| !used.contains(q)).unwrap_or(0);
        occurrences[a].v = v;
        occurrences[a].u = (0..num_vars).filter(|&q| q != v).take(c).collect();
    }
    terms
        .iter()
        .map(|t| {
            let extra = (0..num_vars)
                .map(|q| {
                    t.factors
                        .iter()
                        .filter(|&&f| {
                            (f as usize) >= first && occurrences[f as usize - first].v == q
                        })
                        .count()
                })
                .max()
                .unwrap_or(0);
            t.factors.len() + extra
        })
        .max()
        .unwrap_or(1)
        .max(1)
}

fn plan<K: ChallengeField + CodeField>(statement: &Statement<K>) -> Result<Plan<K>, Error> {
    let c = dim::<K>().trailing_zeros() as usize;
    let s = statement.sources;
    if s == 0
        || statement
            .columns
            .iter()
            .any(|x| x.source >= s || x.log_len > 24)
    {
        return Err(Error::Statement);
    }
    let column = |index: usize, len: u32| -> Result<usize, Error> {
        match statement.columns.get(index) {
            Some(x) if x.log_len == len => Ok(index),
            _ => Err(Error::Statement),
        }
    };
    let mut counts = vec![0usize; statement.columns.len()];
    let mut steps = Vec::new();
    for (j, relation) in statement.relations.iter().enumerate() {
        let id = (s + 1 + j) as u64;
        let (num_vars, eq, label, draws, mut occurrences, terms, first) = match relation {
            Relation::Identity {
                num_vars,
                reads,
                terms,
            } => {
                let n = (*num_vars as usize).max(c + 1);
                let mut occurrences = Vec::new();
                for read in reads {
                    let len = read.vars.len() as u32;
                    if read
                        .vars
                        .iter()
                        .enumerate()
                        .any(|(k, q)| *q >= *num_vars || read.vars[..k].contains(q))
                    {
                        return Err(Error::Statement);
                    }
                    occurrences.push(Occurrence {
                        column: column(read.column, len)?,
                        coords: read.vars.iter().map(|q| Coord::Var(*q as usize)).collect(),
                        v: 0,
                        u: Vec::new(),
                        block: 0,
                    });
                }
                if terms.iter().any(|t| {
                    t.factors.len() > 3 || t.factors.iter().any(|f| *f as usize >= reads.len())
                }) {
                    return Err(Error::Statement);
                }
                // eq(τ, ·) is input 0 of every term.
                let terms = terms
                    .iter()
                    .map(|t| Term {
                        coefficient: t.coefficient,
                        factors: core::iter::once(0)
                            .chain(t.factors.iter().map(|f| f + 1))
                            .collect(),
                    })
                    .collect();
                (
                    n,
                    true,
                    ChallengeLabel::ZeroWeight,
                    n,
                    occurrences,
                    terms,
                    1,
                )
            }
            Relation::Matmul {
                lhs,
                rhs,
                out,
                rows,
                inner,
                cols,
            } => {
                let (a, k, b) = (*rows as usize, *inner as usize, *cols as usize);
                let n = k.max(c + 1);
                let free = |range: core::ops::Range<usize>| range.map(Coord::Free);
                let vars = || (0..k).map(Coord::Var);
                let occurrences = vec![
                    Occurrence {
                        column: column(*lhs, rows + inner)?,
                        coords: free(0..a).chain(vars()).collect(),
                        v: 0,
                        u: Vec::new(),
                        block: 0,
                    },
                    Occurrence {
                        column: column(*rhs, inner + cols)?,
                        coords: vars().chain(free(a..a + b)).collect(),
                        v: 0,
                        u: Vec::new(),
                        block: 0,
                    },
                    Occurrence {
                        column: column(*out, rows + cols)?,
                        coords: free(0..a + b).collect(),
                        v: 0,
                        u: Vec::new(),
                        block: 0,
                    },
                ];
                // Σ_y lhs·rhs counts out 2^pad times and Σ_y Ȯ counts it 2^n
                // times, so −2^{−inner} balances them (RFC-0026 A9).
                let half = K::from_i64(2).inverse().ok_or(Error::Statement)?;
                let scale = (0..k).fold(K::from_i64(1), |p, _| p * half);
                let terms = vec![
                    Term {
                        coefficient: K::from_i64(1),
                        factors: vec![0, 1],
                    },
                    Term {
                        coefficient: zero::<K>() - scale,
                        factors: vec![2],
                    },
                ];
                (
                    n,
                    false,
                    ChallengeLabel::RelationPoint,
                    a + b,
                    occurrences,
                    terms,
                    0,
                )
            }
        };
        if num_vars > 24 {
            return Err(Error::Statement);
        }
        let degree = assign(num_vars, &mut occurrences, first, &terms, c);
        for occurrence in &mut occurrences {
            occurrence.block = counts[occurrence.column];
            counts[occurrence.column] += 1;
        }
        steps.push(Step {
            id,
            num_vars: num_vars as u32,
            eq,
            label,
            draws,
            occurrences,
            terms,
            degree,
        });
    }
    // Claim sources: columns in index order, each followed by its blocks.
    let rows = 2 * dim::<K>();
    let ell = ceil_log2(rows);
    let mut cursors = vec![0usize; s];
    let mut offsets = Vec::new();
    for (index, x) in statement.columns.iter().enumerate() {
        let at = cursors[x.source];
        let blocks = at + (1usize << x.log_len);
        cursors[x.source] = blocks + counts[index] * dim::<K>();
        offsets.push((at, blocks));
    }
    let mut layouts = Vec::new();
    for cursor in &cursors {
        let m = MIN_M.max(ceil_log2(cursor.div_ceil(rows)));
        if m >= 30 {
            return Err(Error::Statement);
        }
        layouts.push(Layout {
            ell,
            m,
            offsets: Vec::new(),
        });
    }
    for (x, offset) in statement.columns.iter().zip(offsets) {
        layouts[x.source].offsets.push(offset);
    }
    let batched: Vec<usize> = (0..s)
        .filter(|&source| {
            statement
                .columns
                .iter()
                .zip(&counts)
                .any(|(x, n)| x.source == source && *n > 0)
        })
        .collect();
    let mut masks: Vec<(u64, u32, usize)> = steps
        .iter()
        .map(|st| (st.id, st.num_vars, st.degree))
        .collect();
    for (b, source) in batched.iter().enumerate() {
        let layout = &layouts[*source];
        let id = (s + 1 + steps.len() + b) as u64;
        masks.push((id, u32::from(layout.ell + 1 + layout.m), 2));
    }
    let mut shared_offsets = Vec::new();
    let mut width = 0usize;
    for (_, n, degree) in &masks {
        shared_offsets.push(width);
        width += *n as usize * (degree + 1);
    }
    let m = MIN_M.max(ceil_log2(width));
    if m >= 30 {
        return Err(Error::Statement);
    }
    Ok(Plan {
        steps,
        layouts,
        batched,
        masks,
        shared_offsets,
        shared: (ell, m),
    })
}

/// Index of `(column, block)` among the statement's columns per source: the
/// column's position within its source's `offsets`.
fn slot<K>(statement: &Statement<K>, column: usize) -> usize {
    let source = statement.columns[column].source;
    statement.columns[..column]
        .iter()
        .filter(|x| x.source == source)
        .count()
}

/// A column point: its `Var` coordinates at `ρ`, its `Free` ones at `free`.
fn column_point<K: Copy>(coords: &[Coord], point: &[K], free: &[K]) -> Vec<K> {
    coords
        .iter()
        .map(|c| match c {
            Coord::Var(q) => point[*q],
            Coord::Free(i) => free[*i],
        })
        .collect()
}

/// The linear claim of one occurrence on its source:
/// `c_a = x̃(ρ|coords) + κ(ρ_v)·r̃_x(a, ρ_u)` (A5 item 2).
fn occurrence_claim<K: ChallengeField + CodeField>(
    statement: &Statement<K>,
    plan: &Plan<K>,
    occurrence: &Occurrence,
    point: &[K],
    free: &[K],
    value: K,
) -> Result<(usize, Claim<K>), Error> {
    let source = statement.columns[occurrence.column].source;
    let (at, blocks) = plan.layouts[source].offsets[slot(statement, occurrence.column)];
    let x = stele_poly::eq_table(&column_point(&occurrence.coords, point, free))
        .map_err(|_| Error::Statement)?;
    let u: Vec<K> = occurrence.u.iter().map(|q| point[*q]).collect();
    let r = stele_poly::eq_table(&u).map_err(|_| Error::Statement)?;
    let k = kappa(point[occurrence.v]);
    let first = blocks + occurrence.block * dim::<K>();
    let weights = x
        .into_iter()
        .enumerate()
        .map(|(p, w)| (at + p, w))
        .chain(r.into_iter().enumerate().map(|(p, w)| (first + p, k * w)))
        .collect();
    Ok((source, Claim { weights, value }))
}

/// `μ_j` as a linear claim on the shared source: `Σ_{d,c} e_d·b_c·X[d][o_j + c]`
/// with `b` the plain mask's column weights at `ρ_j`.
fn mask_claim<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    index: usize,
    point: &[K],
    value: K,
) -> Result<Claim<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (_, n, degree) = plan.masks[index];
    let b = masked::column_weights(n, degree, point, true).map_err(Error::Sumcheck)?;
    let columns = 1usize << plan.shared.1;
    let offset = plan.shared_offsets[index];
    let mut weights = Vec::new();
    for d in 0..dim::<K>() {
        let e = basis::<K>(d)?;
        weights.extend(
            b.iter()
                .enumerate()
                .map(|(c, w)| (d * columns + offset + c, e * *w)),
        );
    }
    Ok(Claim { weights, value })
}

/// A5 item 4's claim-block rank: the `D` M31 coordinates of `eq(ρ_u, ·)` must have
/// rank `D`. Public; the producer aborts otherwise.
fn block_rank<K: ChallengeField + CodeField>(u: &[K]) -> Result<bool, Error> {
    let eq = stele_poly::eq_table(u).map_err(|_| Error::Statement)?;
    let columns: Vec<Vec<M31>> = eq.into_iter().map(limbs).collect::<Result<_, _>>()?;
    let d = dim::<K>();
    let mut rows: Vec<Vec<M31>> = (0..d)
        .map(|limb| columns.iter().map(|c| c[limb]).collect())
        .collect();
    let mut rank = 0;
    for column in 0..d {
        let Some(pivot) = (rank..d).find(|&i| rows[i][column] != M31::ZERO) else {
            continue;
        };
        rows.swap(rank, pivot);
        let inverse = rows[rank][column].inverse().unwrap_or(M31::ZERO);
        let head = rows[rank].clone();
        for row in rows.iter_mut().skip(rank + 1) {
            let factor = row[column] * inverse;
            for (value, p) in row.iter_mut().zip(&head) {
                *value = *value - factor * *p;
            }
        }
        rank += 1;
    }
    Ok(rank == d)
}

/// `γ_a` for a batch, one per claim (`BatchCoefficient`).
pub fn coefficients<K: ChallengeField>(
    t: &mut Transcript<K>,
    count: usize,
) -> Result<Vec<K>, Error> {
    (0..count)
        .map(|_| {
            t.challenge(ChallengeLabel::BatchCoefficient)
                .map_err(|e| Error::Sumcheck(e.into()))
        })
        .collect()
}

/// A5 item 5's weight `(1 − w)·W` over `(w, row, col)` of a hiding source's data
/// face `Y = 0`: `W = Σ_a γ_a·w_a` on the data rows (`w = 0`), zero on `w = 1`.
pub fn weight_table<K: ChallengeField>(
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Result<Vec<K>, Error> {
    let half = (source.rows() / 2) * (source.columns() / 2);
    if claims.len() != gammas.len() {
        return Err(Error::Statement);
    }
    let mut table = vec![zero::<K>(); 2 * half];
    for (claim, gamma) in claims.iter().zip(gammas) {
        for (position, weight) in &claim.weights {
            let entry = table[..half].get_mut(*position).ok_or(Error::Statement)?;
            *entry = *entry + *gamma * *weight;
        }
    }
    Ok(table)
}

/// The batch instance: `Σ_{w,row,col} W'·M̃'` over `ell + 1 + m` variables, with
/// the public claimed sum `Σ_a γ_a·c_a`.
fn batch_instance<K: ChallengeField>(
    id: u64,
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Instance<K> {
    let num_vars = source.rows().trailing_zeros() + source.columns().trailing_zeros() - 1;
    Instance {
        id,
        num_vars,
        inputs: vec![0, 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: claims
            .iter()
            .zip(gammas)
            .fold(zero::<K>(), |s, (c, g)| s + *g * c.value),
    }
}

/// `M̃'` on the face `Y = 0`, over `(w, row, col)`.
fn face<K: ChallengeField>(prepared: &PreparedSource<'_, K>) -> Vec<K> {
    let columns = prepared.source().columns();
    prepared
        .message()
        .chunks_exact(columns)
        .flat_map(|row| row[..columns / 2].iter().map(|x| element::<K>(*x)))
        .collect()
}

/// The opening point `(w*, row*, 0, col*)` of the batch point `(w*, row*, col*)`.
fn opening_point<K: ChallengeField>(point: &[K], ell: usize) -> Vec<K> {
    let mut full = point.to_vec();
    full.insert(ell + 1, zero::<K>());
    full
}

/// The verifier's `W'(ρ) = (1 − w*)·W̃(row*, col*)`, zero weight on `w = 1`.
// shortcut: O(R·C) dense evaluation; a succinct eq-sum per claim when sources grow.
fn expected_weight<K: ChallengeField>(
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
    point: &[K],
) -> Result<K, Error> {
    let table = weight_table(source, claims, gammas)?;
    let eq = stele_poly::eq_table(&point[1..]).map_err(|_| Error::Statement)?;
    let data = eq
        .iter()
        .zip(&table)
        .fold(zero::<K>(), |s, (e, w)| s + *e * *w);
    Ok((K::from_i64(1) - point[0]) * data)
}

/// Prove one A5 item-5 batch of `claims` on a hiding source, with its plain mask
/// bound by `binding`; returns the batch and its point.
pub fn prove_batch<K: ChallengeField + CodeField + Eq>(
    id: u64,
    prepared: &PreparedSource<'_, K>,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(Batch<K>, Vec<K>), Error> {
    let gammas = coefficients(t, claims.len())?;
    let weights = weight_table(prepared.source(), claims, &gammas)?;
    prove_weighted(
        id, prepared, verified, claims, &gammas, weights, mask, binding, t,
    )
}

/// [`prove_batch`] after the `γ_a` draws, on a caller-supplied weight table over
/// `(w, row, col)`. An honest caller passes [`weight_table`]'s, which is zero on
/// `w = 1`; NC-0915 passes one that is not.
#[allow(clippy::too_many_arguments)]
pub fn prove_weighted<K: ChallengeField + CodeField + Eq>(
    id: u64,
    prepared: &PreparedSource<'_, K>,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    gammas: &[K],
    weights: Vec<K>,
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(Batch<K>, Vec<K>), Error> {
    let i = batch_instance(id, prepared.source(), claims, gammas);
    let dense = Dense::new(&i, vec![weights, face(prepared)]).map_err(Error::Sumcheck)?;
    let (sumcheck, point) = masked::prove(&i, dense, mask, binding, t).map_err(Error::Sumcheck)?;
    // A5 item 4: w* = 0 leaves the opening without mask-row weight.
    if point[0] == zero::<K>() {
        return Err(Error::BatchPoint);
    }
    let ell = prepared.source().rows().trailing_zeros() as usize - 1;
    let opening = prepared
        .opening_point(
            t,
            verified,
            id,
            &opening_point(&point, ell),
            sumcheck.final_values[1],
        )
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((Batch { sumcheck, opening }, point))
}

/// Verify one batch: the masked rounds at degree 2, the weight final against the
/// verifier's own `(1 − w*)·W̃` (NC-0915), and the point opening. Returns the
/// reduction and `μ`, a claim on the shared mask source.
pub fn verify_batch<K: ChallengeField + CodeField + Eq>(
    id: u64,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    batch: &Batch<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<masked::Reduction<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let source = verified.record().source();
    let gammas = coefficients(t, claims.len())?;
    let i = batch_instance(id, source, claims, &gammas);
    let result =
        masked::verify_degree(&i, 2, &batch.sumcheck, binding, t).map_err(Error::Sumcheck)?;
    let point = &result.reduction.point;
    if result.reduction.claims[0].1 != expected_weight(source, claims, &gammas, point)? {
        return Err(Error::Sumcheck(
            stele_sumcheck::Error::FinalEvaluationMismatch,
        ));
    }
    let ell = source.rows().trailing_zeros() as usize - 1;
    verify_point(
        t,
        verified,
        id,
        &opening_point(point, ell),
        result.reduction.claims[1].1,
        &batch.opening,
    )
    .map_err(|f| Error::Pcs(f.cause))?;
    Ok(result)
}

/// One masked factor `V̇ = x + κ(X_v)·r` over the remaining variables, or a public
/// factor (`r` empty, no `v`). After `v` is bound, `x` holds `x + κ(ρ_v)·r`.
struct Factor<K> {
    x: Vec<K>,
    r: Vec<K>,
    v: Option<usize>,
}

/// The A5 item 2 prover strategy: before its vanishing variable is bound a mask
/// term is zero on the cube; in that round it contributes `κ(t)·r`, after it
/// `κ(ρ_v)·r`.
struct Occurrences<K> {
    factors: Vec<Factor<K>>,
    terms: Vec<Term<K>>,
    degree: usize,
    num_vars: u32,
    bound: usize,
}

impl<K: ChallengeField> Summand<K> for Occurrences<K> {
    fn shape(&self) -> (u32, usize) {
        (self.num_vars - self.bound as u32, self.factors.len())
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        let half = self.factors[0].x.len() / 2;
        let mut out = vec![zero::<K>(); self.degree + 1];
        let mut values = vec![zero::<K>(); self.factors.len()];
        for column in 0..half {
            for (node, result) in out.iter_mut().enumerate() {
                let t = K::from_i64(node as i64);
                for (value, f) in values.iter_mut().zip(&self.factors) {
                    let at =
                        |table: &[K]| table[column] + t * (table[column + half] - table[column]);
                    *value = at(&f.x);
                    if f.v == Some(self.bound) {
                        *value = *value + kappa(t) * at(&f.r);
                    }
                }
                *result = *result
                    + self.terms.iter().fold(zero::<K>(), |s, term| {
                        s + term
                            .factors
                            .iter()
                            .fold(term.coefficient, |p, f| p * values[*f as usize])
                    });
            }
        }
        Ok(out)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        for f in &mut self.factors {
            stele_sumcheck::parallel::fold(&mut f.x, challenge);
            if !f.r.is_empty() {
                stele_sumcheck::parallel::fold(&mut f.r, challenge);
            }
            if f.v == Some(self.bound) {
                let k = kappa(challenge);
                for (x, r) in f.x.iter_mut().zip(&f.r) {
                    *x = *x + k * *r;
                }
                f.r.clear();
            }
        }
        self.bound += 1;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        Ok(self.factors.iter().map(|f| f.x[0]).collect())
    }
}

fn bit(index: usize, var: usize, n: usize) -> usize {
    (index >> (n - 1 - var)) & 1
}

/// `x̂` over the domain: the column at its `Free` coordinates, broadcast over the
/// variables it does not read.
fn domain_table<K: ChallengeField>(
    column: &[M31],
    coords: &[Coord],
    free: &[K],
    n: usize,
) -> Vec<K> {
    let len = coords.len();
    let mut partial = vec![zero::<K>(); 1 << n];
    let mut read = 0usize;
    for c in coords {
        if let Coord::Var(q) = c {
            read |= 1 << (n - 1 - q);
        }
    }
    for (index, value) in column.iter().enumerate() {
        let mut weight = K::from_i64(1);
        let mut target = 0usize;
        for (j, c) in coords.iter().enumerate() {
            let b = bit(index, j, len);
            match c {
                Coord::Var(q) => target |= b << (n - 1 - q),
                Coord::Free(i) => {
                    weight = weight
                        * if b == 1 {
                            free[*i]
                        } else {
                            K::from_i64(1) - free[*i]
                        }
                }
            }
        }
        partial[target] = partial[target] + weight * element::<K>(*value);
    }
    (0..1usize << n)
        .map(|index| partial[index & read])
        .collect()
}

/// `r̂(X) = r̃_x(a, X_u)` over the domain.
fn block_table<K: ChallengeField>(block: &[M31], u: &[usize], n: usize) -> Vec<K> {
    (0..1usize << n)
        .map(|index| {
            let entry = u
                .iter()
                .enumerate()
                .fold(0, |e, (k, q)| e | bit(index, *q, n) << (u.len() - 1 - k));
            element::<K>(block[entry])
        })
        .collect()
}

/// Read data position `p` of a hiding message `M'` (`2R × 2C`).
fn data(message: &[M31], columns: usize, p: usize) -> M31 {
    message[(p / columns) * 2 * columns + p % columns]
}

fn draws<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: ChallengeLabel,
    count: usize,
) -> Result<Vec<K>, Error> {
    (0..count)
        .map(|_| t.challenge(label).map_err(|e| Error::Sumcheck(e.into())))
        .collect()
}

fn step_instance<K: ChallengeField>(step: &Step<K>) -> Instance<K> {
    let inputs = usize::from(step.eq) + step.occurrences.len();
    Instance {
        id: step.id,
        num_vars: step.num_vars,
        inputs: (0..inputs as u64).collect(),
        terms: step.terms.clone(),
        claimed_sum: zero::<K>(),
    }
}

/// A claim source's message `M'` (A2 item 1): columns and claim masks as data,
/// the masks drawn from the `zk/source-mask` stream after the data masks (A5
/// item 1). `claim_masks = false` leaves the blocks zero (privacy-test control).
fn source_message<K: ChallengeField + CodeField>(
    statement: &Statement<K>,
    plan: &Plan<K>,
    source: usize,
    columns: &[Vec<M31>],
    seed: &[u8; 32],
    claim_masks: bool,
) -> Result<Vec<M31>, Error> {
    let layout = &plan.layouts[source];
    let (rows, width) = (1usize << layout.ell, 1usize << layout.m);
    let mut x = vec![M31::ZERO; rows * width];
    let mut stream = MaskStream::new(seed, SOURCE_MASK, plan.source_id(source));
    // shortcut: replays the 3RC data-mask draws of `hiding_message`; share its stream if this shows in a profile.
    for _ in 0..3 * rows * width {
        stream.m31();
    }
    let members = statement
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.source == source);
    for ((index, _), (at, blocks)) in members.zip(&layout.offsets) {
        x[*at..*at + columns[index].len()].copy_from_slice(&columns[index]);
        let end = plan
            .steps
            .iter()
            .flat_map(|s| &s.occurrences)
            .filter(|o| o.column == index)
            .count()
            * dim::<K>();
        for value in &mut x[*blocks..*blocks + end] {
            let drawn = stream.m31();
            if claim_masks {
                *value = drawn;
            }
        }
    }
    stele_pcs::hiding_message(plan.source_id(source), layout.ell, layout.m, &x, seed)
        .map_err(Error::Pcs)
}

/// The shared mask source's data: each plain mask's values as `D` limb rows.
fn shared_message<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    masks: &[Mask<K>],
    seed: &[u8; 32],
) -> Result<Vec<M31>, Error> {
    let (ell, m) = plan.shared;
    let width = 1usize << m;
    let mut x = vec![M31::ZERO; (1usize << ell) * width];
    for (mask, offset) in masks.iter().zip(&plan.shared_offsets) {
        for (c, value) in mask.columns(0).enumerate() {
            for (d, limb) in limbs(value)?.into_iter().enumerate() {
                x[d * width + offset + c] = limb;
            }
        }
    }
    stele_pcs::hiding_message(plan.shared_id(), ell, m, &x, seed).map_err(Error::Pcs)
}

fn certify<K: ChallengeField + CodeField>(
    prepared: &PreparedSource<'_, K>,
) -> Result<(Vec<u8>, VerifiedCertificate<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let certificate = prepared.certificate().map_err(|f| Error::Pcs(f.cause))?.0;
    let verified = verify_certificate(*prepared.source(), &certificate)
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((certificate, verified))
}

/// Prove `statement` on `columns` (one M31 table per column) from one fresh
/// secret seed (A5 items 1–6). Aborts (`ClaimRank`, `Vanishing`, `BatchPoint`,
/// A2's `MaskRank`, `MaskWeight`, A4's `MaskPoint`) are public events.
///
/// # Security
///
/// As [`super::prove`]: a seed serves one proof. After an abort, retry with a
/// fresh seed only if nothing from the attempt was published.
pub fn prove<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(statement, columns, &seed.0, t, true)
}

fn prove_with<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: &[u8; 32],
    t: &mut Transcript<K>,
    claim_masks: bool,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan(statement)?;
    if columns.len() != statement.columns.len()
        || columns
            .iter()
            .zip(&statement.columns)
            .any(|(c, x)| c.len() != 1usize << x.log_len)
    {
        return Err(Error::Statement);
    }
    let messages = (0..statement.sources)
        .map(|s| source_message(statement, &plan, s, columns, seed, claim_masks))
        .collect::<Result<Vec<_>, _>>()?;
    let masks = plan
        .masks
        .iter()
        .map(|(id, n, degree)| Mask::plain(seed, *id, *n, *degree).map_err(Error::Sumcheck))
        .collect::<Result<Vec<_>, _>>()?;
    let shared_message = shared_message(&plan, &masks, seed)?;
    let hiding = |id: u64, (ell, m): (u8, u8), message| {
        PreparedSource::<K>::hiding(id, ell, m, BLOWUP, message, seed, &mut HashUsage::default())
            .map_err(Error::Pcs)
    };
    let mut prepared = Vec::new();
    for (s, message) in messages.iter().enumerate() {
        let layout = &plan.layouts[s];
        prepared.push(hiding(plan.source_id(s), (layout.ell, layout.m), message)?);
    }
    prepared.push(hiding(plan.shared_id(), plan.shared, &shared_message)?);
    let mut sources = Vec::new();
    let mut certificates = Vec::new();
    let mut verified = Vec::new();
    for p in &prepared {
        let (certificate, v) = certify(p)?;
        sources.push(p.source().bytes().to_vec());
        certificates.push(certificate);
        verified.push(v);
    }
    t.absorb(AbsorbLabel::FieldSources, &sources.concat())
        .map_err(|e| Error::Sumcheck(e.into()))?;
    let binding = sources[statement.sources].clone();
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); statement.sources];
    let mut mus = Vec::new();
    let mut relations = Vec::new();
    for (j, step) in plan.steps.iter().enumerate() {
        let free = draws(t, step.label, step.draws)?;
        let n = step.num_vars as usize;
        let mut factors = Vec::new();
        if step.eq {
            factors.push(Factor {
                x: stele_poly::eq_table(&free).map_err(|_| Error::Statement)?,
                r: Vec::new(),
                v: None,
            });
        }
        for o in &step.occurrences {
            let source = statement.columns[o.column].source;
            let (_, blocks) = plan.layouts[source].offsets[slot(statement, o.column)];
            let width = 1usize << plan.layouts[source].m;
            let first = blocks + o.block * dim::<K>();
            let block: Vec<M31> = (first..first + dim::<K>())
                .map(|p| data(&messages[source], width, p))
                .collect();
            factors.push(Factor {
                x: domain_table(&columns[o.column], &o.coords, &free, n),
                r: block_table(&block, &o.u, n),
                v: Some(o.v),
            });
        }
        let i = step_instance(step);
        let summand = Occurrences {
            factors,
            terms: step.terms.clone(),
            degree: step.degree,
            num_vars: step.num_vars,
            bound: 0,
        };
        let (proof, point) =
            masked::prove(&i, summand, &masks[j], &binding, t).map_err(Error::Sumcheck)?;
        let first = usize::from(step.eq);
        for (k, o) in step.occurrences.iter().enumerate() {
            // A5 item 4: public aborts before the claim leaves the producer.
            if kappa(point[o.v]) == zero::<K>() {
                return Err(Error::Vanishing);
            }
            let u: Vec<K> = o.u.iter().map(|q| point[*q]).collect();
            if !block_rank(&u)? {
                return Err(Error::ClaimRank);
            }
            let value = proof.final_values[first + k];
            let (source, claim) = occurrence_claim(statement, &plan, o, &point, &free, value)?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, &point, proof.mask_final)?);
        relations.push(proof);
    }
    let mut batches = Vec::new();
    for (b, source) in plan.batched.iter().enumerate() {
        let index = plan.steps.len() + b;
        let (batch, point) = prove_batch(
            plan.masks[index].0,
            &prepared[*source],
            &verified[*source],
            &claims[*source],
            &masks[index],
            &binding,
            t,
        )?;
        mus.push(mask_claim(&plan, index, &point, batch.sumcheck.mask_final)?);
        batches.push(batch);
    }
    let shared = &prepared[statement.sources];
    let gammas = coefficients(t, mus.len())?;
    let weights = weight_table(shared.source(), &mus, &gammas)?;
    let i = batch_instance(plan.shared_batch_id(), shared.source(), &mus, &gammas);
    let dense = Dense::new(&i, vec![weights, face(shared)]).map_err(Error::Sumcheck)?;
    let (proof, point) = prove_at(&i, dense, seed, t)?;
    if point[0] == zero::<K>() {
        return Err(Error::BatchPoint);
    }
    let shared_opening = shared
        .opening_point(
            t,
            &verified[statement.sources],
            plan.shared_batch_id(),
            &opening_point(&point, plan.shared.0 as usize),
            proof.sumcheck.final_values[1],
        )
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok(Proof {
        sources,
        certificates,
        relations,
        batches,
        shared: proof,
        shared_opening,
    })
}

/// Verify a dev-zk claims proof against the verifier-owned statement. Every claim
/// is discharged by its source's batch and opening; returns the SC and MASK
/// records of every masked instance.
pub fn verify<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<Verified<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan(statement)?;
    let shape = Error::Sumcheck(stele_sumcheck::Error::ProofShape);
    if proof.sources.len() != statement.sources + 1
        || proof.certificates.len() != proof.sources.len()
        || proof.relations.len() != plan.steps.len()
        || proof.batches.len() != plan.batched.len()
    {
        return Err(shape);
    }
    let mut verified = Vec::new();
    for (s, (bytes, certificate)) in proof.sources.iter().zip(&proof.certificates).enumerate() {
        let (id, (ell, m)) = if s < statement.sources {
            (plan.source_id(s), (plan.layouts[s].ell, plan.layouts[s].m))
        } else {
            (plan.shared_id(), plan.shared)
        };
        let source = Source::<K>::from_bytes(bytes).map_err(Error::Pcs)?;
        let expected =
            Source::<K>::hiding(id, ell, m, BLOWUP, source.root()).map_err(Error::Pcs)?;
        if expected.bytes() != source.bytes() {
            return Err(Error::MaskSource);
        }
        verified.push(
            verify_certificate(expected, certificate)
                .map_err(|f| Error::Pcs(f.cause))?
                .0,
        );
    }
    t.absorb(AbsorbLabel::FieldSources, &proof.sources.concat())
        .map_err(|e| Error::Sumcheck(e.into()))?;
    let binding = &proof.sources[statement.sources];
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); statement.sources];
    let mut mus = Vec::new();
    let mut reductions = Vec::new();
    let mut records = Vec::new();
    for (j, (step, relation)) in plan.steps.iter().zip(&proof.relations).enumerate() {
        let free = draws(t, step.label, step.draws)?;
        let i = step_instance(step);
        let result = masked::verify_degree(&i, step.degree, relation, binding, t)
            .map_err(Error::Sumcheck)?;
        let point = &result.reduction.point;
        let finals = &relation.final_values;
        if step.eq
            && finals[0] != stele_poly::eq_evaluate(&free, point).map_err(|_| Error::Statement)?
        {
            return Err(Error::Sumcheck(stele_sumcheck::Error::ClaimMismatch));
        }
        let first = usize::from(step.eq);
        for (k, o) in step.occurrences.iter().enumerate() {
            let (source, claim) =
                occurrence_claim(statement, &plan, o, point, &free, finals[first + k])?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, point, result.mask_final)?);
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    for (b, (source, batch)) in plan.batched.iter().zip(&proof.batches).enumerate() {
        let index = plan.steps.len() + b;
        let result = verify_batch(
            plan.masks[index].0,
            &verified[*source],
            &claims[*source],
            batch,
            binding,
            t,
        )?;
        mus.push(mask_claim(
            &plan,
            index,
            &result.reduction.point,
            result.mask_final,
        )?);
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    let shared = &verified[statement.sources];
    let source = shared.record().source();
    let gammas = coefficients(t, mus.len())?;
    let i = batch_instance(plan.shared_batch_id(), source, &mus, &gammas);
    let (reduction, record) = super::verify(&i, &proof.shared, t)?;
    let point = &reduction.point;
    if reduction.claims[0].1 != expected_weight(source, &mus, &gammas, point)? {
        return Err(Error::Sumcheck(
            stele_sumcheck::Error::FinalEvaluationMismatch,
        ));
    }
    verify_point(
        t,
        shared,
        plan.shared_batch_id(),
        &opening_point(point, plan.shared.0 as usize),
        reduction.claims[1].1,
        &proof.shared_opening,
    )
    .map_err(|f| Error::Pcs(f.cause))?;
    reductions.push(reduction);
    records.push(record);
    Ok(Verified {
        reductions,
        masks: records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    /// Leak control for the privacy test of `tests/zk_claims.rs`: with the claim
    /// masks removed the proof still verifies (no verifier sees masks), but the
    /// claim on `a` is exactly `ã(ρ)` for every seed, so the uniformity test of its
    /// masked part fails. With masks the masked part is never zero.
    #[test]
    fn rejects_unmasked_claims_in_privacy_test() {
        let read = |column| Read {
            column,
            vars: vec![0, 1, 2],
        };
        let term = |coefficient, factors| Term {
            coefficient: QM31::from_i64(coefficient),
            factors,
        };
        let statement = Statement::<QM31> {
            sources: 1,
            columns: (0..3)
                .map(|_| Column {
                    source: 0,
                    log_len: 3,
                })
                .collect(),
            relations: vec![Relation::Identity {
                num_vars: 3,
                reads: (0..3).map(read).collect(),
                terms: vec![term(1, vec![0, 1]), term(-1, vec![2])],
            }],
        };
        let a: Vec<M31> = (0..8).map(|n| M31::from_i64(n + 2)).collect();
        let b: Vec<M31> = (0..8).map(|n| M31::from_i64(5 - n)).collect();
        let c = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
        let columns = vec![a.clone(), b, c];
        for masks in [true, false] {
            for n in 0..8u8 {
                let t = || Transcript::<QM31>::new(b"leak").expect("transcript");
                let proof =
                    prove_with(&statement, &columns, &[n; 32], &mut t(), masks).expect("proof");
                let verified = verify(&statement, &proof, &mut t()).expect("accepted");
                let eq = stele_poly::eq_table(&verified.reductions[0].point).expect("eq");
                let exact = a
                    .iter()
                    .zip(&eq)
                    .fold(QM31::from_i64(0), |s, (x, e)| s + *e * element::<QM31>(*x));
                let residual = proof.relations[0].final_values[1] - exact;
                assert_eq!(residual == QM31::from_i64(0), !masks);
            }
        }
    }
}
