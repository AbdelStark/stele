//! RFC-0013 A5 items 1–6 with RFC-0026 A9: masked claims, identity and matmul
//! zero-sums, the shared mask source and per-source batching (dev-zk components).
//!
//! Defined for no profile (A5 item 8); task E12-14 wires it into the development
//! prover and verifier. Order on the caller's transcript:
//!
//! 1. Every claim source (a hiding source of committed columns with their claim
//!    masks, multiplicities included): bytes absorbed (`FieldSources`),
//!    certificates on their own A9 transcripts.
//! 2. Each lookup's `β, α` (`LookupBeta`, `LookupAlpha`), then the top source
//!    (every lookup's committed top layer, RFC-0008 A7 item 3) and the shared mask
//!    source: bytes absorbed together (`FieldSources`).
//! 3. Each relation in plan order (the statement's, then each lookup's
//!    `h·q − p = 0` and `Σ h = 0`): its public draws (`ZeroWeight` for an identity's
//!    `τ`, `RelationPoint` for a matmul's free point), then one masked A1 sumcheck
//!    on the `V̇` of A5 item 2, its mask bound by the shared source.
//! 4. Each lookup's masked GKR steps ([`lookup`], RFC-0008 A7 item 4).
//! 5. Each claim source with claims: `γ_a` (`BatchCoefficient`), the zero-weight
//!    batch of item 5 (mask in the shared source), one point opening.
//! 6. The shared source: `γ_j` over every `μ_j` and layer-block claim, the item-5
//!    batch with its own RFC-0013 A4 two-block mask source (item 5a), one opening.
//!
//! Plan rules fixed here (not protocol choices of the RFC; E12-14 may replace them
//! with the development plan's): a claim source holds its columns in index order,
//! each followed by its `t_x` blocks of `D` entries, packed from data position 0,
//! with `R = 2D` rows and `C = 2^m ≥ 2^9` columns; a `K`-valued top column is `D`
//! limb columns, limb-major. The shared source holds each masked instance's plain
//! mask `g_j` (relations, GKR steps, then batches) as `n_j(δ_j + 1)` consecutive
//! columns, limb `d` in data row `d`, and the layer blocks from data row `D` on.
//! Ids: claim sources `0..S` (the top source last), the shared source next, then
//! relations, GKR steps, batches and the shared batch; every mask stream is
//! therefore used once per proof.
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

#[path = "zk_lookup.rs"]
mod lookup;

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
    /// Lookups proven by ZK-GKR (RFC-0008 A7), after the relations.
    pub lookups: Vec<Lookup>,
}

/// One lookup of `c` tuple columns into a public table, over `n ≥ c_D + 1`
/// variables (RFC-0008 A7, a single unselected member): every tuple
/// `(x_0(i), …, x_{c−1}(i))` must be a valid table row, and `multiplicity(j)`
/// counts the lookups of row `j`. The lookup and table leaves form one tree,
/// leaf `(x, 0)` the lookup `1/(α − Σ β^i x_i)` and leaf `(x, 1)` the negated table
/// term `−m/(α − Σ β^i T_i)`; padded rows are `0/1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    /// Tuple columns, each of `2^n` entries.
    pub columns: Vec<usize>,
    /// The committed multiplicity column, `2^n` entries.
    pub multiplicity: usize,
    /// Public table: `2^n` rows of `c` values; rows from `valid` on are padding.
    pub table: Vec<Vec<i64>>,
    /// Number of valid table rows.
    pub valid: usize,
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
    /// One masked sumcheck per GKR step, lookups in order, top layer first.
    pub gkr: Vec<masked::Proof<K>>,
    /// One batch per claim source with claims, in source order.
    pub batches: Vec<Batch<K>>,
    /// The shared source's batch, with its A4 mask source.
    pub shared: super::Proof<K>,
    /// The shared source's point opening.
    pub shared_opening: Vec<u8>,
}

/// What an accepted proof leaves: every A1 reduction (relations, GKR steps,
/// batches, shared batch, in order) with its SC record, and one MASK record per
/// masked instance. Every claim is already discharged by its source's opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<K> {
    /// Reductions in transcript order; relation `j` is entry `j`.
    pub reductions: Vec<Reduction<K>>,
    /// MASK records in the same order.
    pub masks: Vec<MaskRecord>,
    /// Each lookup's public `(β, α)`.
    pub lookups: Vec<[K; 2]>,
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

/// A committed column of the plan: the statement's, then each lookup's top `p, q,
/// h` (`K`-valued, `limbs = D`).
#[derive(Clone, Copy, Debug)]
struct PlanColumn {
    source: usize,
    log_len: u32,
    limbs: usize,
}

/// A claim source's layout: `R = 2^ell`, `C = 2^m`, each column's offset and its
/// first block's offset.
struct Layout {
    ell: u8,
    m: u8,
    offsets: Vec<(usize, usize)>,
}

struct Plan<K> {
    columns: Vec<PlanColumn>,
    steps: Vec<Step<K>>,
    lookups: Vec<lookup::LookupPlan>,
    gkr: Vec<lookup::GkrStep>,
    /// Per column: (offset, first block offset) in its source; per source: (ell, m).
    layouts: Vec<Layout>,
    /// Sources with at least one claim, in order.
    batched: Vec<usize>,
    /// Every masked instance's (id, num_vars, degree): relations, GKR steps, batches.
    masks: Vec<(u64, u32, usize)>,
    /// Column offset of each mask in the shared source, and its `(ell, m)`.
    shared_offsets: Vec<usize>,
    shared: (u8, u8),
    /// Layer blocks of `4D` entries in the shared source, from data row `D`.
    blocks: usize,
    /// Masked occurrences (claim-mask blocks) per column.
    counts: Vec<usize>,
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
    /// Sources committed before the lookup draws: all but the top source.
    fn early(&self) -> usize {
        self.layouts.len() - usize::from(!self.lookups.is_empty())
    }
}

/// A5 item 2's default over one instance's inputs: each `free` input takes as `v`
/// the lowest-index variable not used as `v` by an earlier masked input sharing a
/// term, and as `u` the `c_D` lowest-index others. A statement that leaves an
/// occurrence no fresh variable is outside item 2 and refused.
fn vanish<K>(
    num_vars: usize,
    c: usize,
    terms: &[Term<K>],
    masked: &mut [Option<(usize, Vec<usize>)>],
    free: &[bool],
) -> Result<(), Error> {
    let shares = |a: usize, b: usize| {
        terms
            .iter()
            .any(|t| t.factors.contains(&(a as u32)) && t.factors.contains(&(b as u32)))
    };
    for a in 0..masked.len() {
        if !free[a] {
            continue;
        }
        let used: Vec<usize> = (0..a)
            .filter(|&b| shares(a, b))
            .filter_map(|b| masked[b].as_ref().map(|m| m.0))
            .collect();
        let v = (0..num_vars)
            .find(|q| !used.contains(q))
            .ok_or(Error::Statement)?;
        masked[a] = Some((v, (0..num_vars).filter(|&q| q != v).take(c).collect()));
    }
    Ok(())
}

/// A5 item 3: the per-variable maximum over terms, where a masked input has degree
/// `2 + [v ∈ u]` in its vanishing variable `v` and every input degree 1 elsewhere.
fn degree<K>(num_vars: usize, terms: &[Term<K>], masked: &[Option<(usize, Vec<usize>)>]) -> usize {
    terms
        .iter()
        .flat_map(|t| {
            (0..num_vars).map(move |q| {
                t.factors
                    .iter()
                    .map(|f| match &masked[*f as usize] {
                        Some((v, u)) if *v == q => 2 + usize::from(u.contains(&q)),
                        _ => 1,
                    })
                    .sum::<usize>()
            })
        })
        .max()
        .unwrap_or(1)
        .max(1)
}

/// [`vanish`] and [`degree`] for a relation whose inputs `first..` are its
/// occurrences.
fn assign<K>(
    num_vars: usize,
    occurrences: &mut [Occurrence],
    first: usize,
    terms: &[Term<K>],
    c: usize,
) -> Result<usize, Error> {
    let mut masked = vec![None; first + occurrences.len()];
    let free: Vec<bool> = (0..masked.len()).map(|i| i >= first).collect();
    vanish(num_vars, c, terms, &mut masked, &free)?;
    for (o, m) in occurrences.iter_mut().zip(&masked[first..]) {
        if let Some((v, u)) = m {
            o.v = *v;
            o.u = u.clone();
        }
    }
    Ok(degree(num_vars, terms, &masked))
}

/// An identity step `Σ_x eq(τ, x)·Σ_k c_k·Π V̇ = 0` over `reads` (A5, RFC-0026 A9).
fn identity_step<K: ChallengeField>(
    id: u64,
    num_vars: usize,
    reads: Vec<(usize, Vec<usize>)>,
    terms: &[Term<K>],
    c: usize,
    eq: bool,
) -> Result<Step<K>, Error> {
    let mut occurrences: Vec<Occurrence> = reads
        .into_iter()
        .map(|(column, vars)| Occurrence {
            column,
            coords: vars.into_iter().map(Coord::Var).collect(),
            v: 0,
            u: Vec::new(),
            block: 0,
        })
        .collect();
    let first = usize::from(eq);
    // eq(τ, ·) is input 0 of every term.
    let terms: Vec<Term<K>> = terms
        .iter()
        .map(|t| Term {
            coefficient: t.coefficient,
            factors: eq
                .then_some(0)
                .into_iter()
                .chain(t.factors.iter().map(|f| f + first as u32))
                .collect(),
        })
        .collect();
    let degree = assign(num_vars, &mut occurrences, first, &terms, c)?;
    Ok(Step {
        id,
        num_vars: num_vars as u32,
        eq,
        label: ChallengeLabel::ZeroWeight,
        draws: if eq { num_vars } else { 0 },
        occurrences,
        terms,
        degree,
    })
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
    let lookups = !statement.lookups.is_empty();
    let sources = s + usize::from(lookups);
    let mut columns: Vec<PlanColumn> = statement
        .columns
        .iter()
        .map(|x| PlanColumn {
            source: x.source,
            log_len: x.log_len,
            limbs: 1,
        })
        .collect();
    let column = |index: usize, len: u32| -> Result<usize, Error> {
        match statement.columns.get(index) {
            Some(x) if x.log_len == len => Ok(index),
            _ => Err(Error::Statement),
        }
    };
    let mut steps = Vec::new();
    let id = |j: usize| (sources + 1 + j) as u64;
    for (j, relation) in statement.relations.iter().enumerate() {
        let step = match relation {
            Relation::Identity {
                num_vars,
                reads,
                terms,
            } => {
                let mut checked = Vec::new();
                for read in reads {
                    if read
                        .vars
                        .iter()
                        .enumerate()
                        .any(|(k, q)| *q >= *num_vars || read.vars[..k].contains(q))
                    {
                        return Err(Error::Statement);
                    }
                    let vars = read.vars.iter().map(|q| *q as usize).collect();
                    checked.push((column(read.column, read.vars.len() as u32)?, vars));
                }
                if terms.iter().any(|t| {
                    t.factors.len() > 3 || t.factors.iter().any(|f| *f as usize >= reads.len())
                }) {
                    return Err(Error::Statement);
                }
                let n = (*num_vars as usize).max(c + 1);
                if n > 24 {
                    return Err(Error::Statement);
                }
                identity_step(id(j), n, checked, terms, c, true)?
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
                if n > 24 {
                    return Err(Error::Statement);
                }
                let free = |range: core::ops::Range<usize>| range.map(Coord::Free);
                let vars = || (0..k).map(Coord::Var);
                let occurrence = |column, coords| Occurrence {
                    column,
                    coords,
                    v: 0,
                    u: Vec::new(),
                    block: 0,
                };
                let mut occurrences = vec![
                    occurrence(
                        column(*lhs, rows + inner)?,
                        free(0..a).chain(vars()).collect(),
                    ),
                    occurrence(
                        column(*rhs, inner + cols)?,
                        vars().chain(free(a..a + b)).collect(),
                    ),
                    occurrence(column(*out, rows + cols)?, free(0..a + b).collect()),
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
                let degree = assign(n, &mut occurrences, 0, &terms, c)?;
                Step {
                    id: id(j),
                    num_vars: n as u32,
                    eq: false,
                    label: ChallengeLabel::RelationPoint,
                    draws: a + b,
                    occurrences,
                    terms,
                    degree,
                }
            }
        };
        steps.push(step);
    }
    // RFC-0008 A7 item 3: each lookup's top p, q, h in the top source, proven by
    // `h·q − p = 0` and `Σ h = 0`; then its masked GKR steps (item 4).
    let mut lookup_plans = Vec::new();
    let mut gkr = Vec::new();
    let mut blocks = 0;
    for (l, spec) in statement.lookups.iter().enumerate() {
        let top = columns.len();
        let k0 = c + 1;
        for _ in 0..3 {
            columns.push(PlanColumn {
                source: s,
                log_len: k0 as u32,
                limbs: dim::<K>(),
            });
        }
        let vars: Vec<usize> = (0..k0).collect();
        let reads = vec![
            (top + 2, vars.clone()),
            (top + 1, vars.clone()),
            (top, vars.clone()),
        ];
        let one = |factors: Vec<u32>, coefficient: i64| Term {
            coefficient: K::from_i64(coefficient),
            factors,
        };
        let terms = [one(vec![0, 1], 1), one(vec![2], -1)];
        steps.push(identity_step(id(steps.len()), k0, reads, &terms, c, true)?);
        let sum = [one(vec![0], 1)];
        steps.push(identity_step(
            id(steps.len()),
            k0,
            vec![(top + 2, vars)],
            &sum,
            c,
            false,
        )?);
        let (lp, steps_l) =
            lookup::plan_lookup::<K>(statement, l, spec, [top, top + 1, top + 2], blocks, c)?;
        blocks += lp.block_count();
        lookup_plans.push(lp);
        gkr.extend(steps_l);
    }
    for (g, step) in gkr.iter_mut().enumerate() {
        step.id = id(steps.len() + g);
    }
    // Block indices in plan order: relations, then GKR steps.
    let mut counts = vec![0usize; columns.len()];
    for occurrence in steps
        .iter_mut()
        .flat_map(|st| st.occurrences.iter_mut())
        .chain(gkr.iter_mut().flat_map(|g| g.occurrences_mut()))
    {
        occurrence.block = counts[occurrence.column];
        counts[occurrence.column] += 1;
    }
    // Claim sources: columns in index order, each followed by its blocks.
    let rows = 2 * dim::<K>();
    let ell = ceil_log2(rows);
    let mut cursors = vec![0usize; sources];
    let mut offsets = Vec::new();
    for (index, x) in columns.iter().enumerate() {
        let at = cursors[x.source];
        let blocks = at + (x.limbs << x.log_len);
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
    for (x, offset) in columns.iter().zip(offsets) {
        layouts[x.source].offsets.push(offset);
    }
    let batched: Vec<usize> = (0..sources)
        .filter(|&source| {
            columns
                .iter()
                .zip(&counts)
                .any(|(x, n)| x.source == source && *n > 0)
        })
        .collect();
    let mut masks: Vec<(u64, u32, usize)> = steps
        .iter()
        .map(|st| (st.id, st.num_vars, st.degree))
        .chain(gkr.iter().map(|g| (g.id, g.num_vars, g.degree)))
        .collect();
    for source in &batched {
        let layout = &layouts[*source];
        masks.push((id(masks.len()), u32::from(layout.ell + 1 + layout.m), 2));
    }
    let mut shared_offsets = Vec::new();
    let mut width = 0usize;
    for (_, n, degree) in &masks {
        shared_offsets.push(width);
        width += *n as usize * (degree + 1);
    }
    // Blocks fill data rows D..2D: C ≥ 4·blocks.
    let m = MIN_M.max(ceil_log2(width)).max(ceil_log2(4 * blocks));
    if m >= 30 {
        return Err(Error::Statement);
    }
    Ok(Plan {
        columns,
        steps,
        lookups: lookup_plans,
        gkr,
        layouts,
        batched,
        masks,
        shared_offsets,
        shared: (ell, m),
        blocks,
        counts,
    })
}

/// The column's position within its source's `offsets`.
fn slot<K>(plan: &Plan<K>, column: usize) -> usize {
    let source = plan.columns[column].source;
    plan.columns[..column]
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
/// `c_a = x̃(ρ|coords) + κ(ρ_v)·r̃_x(a, ρ_u)` (A5 item 2). A `K`-valued column
/// weighs limb `d` by `e_d`.
fn occurrence_claim<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    occurrence: &Occurrence,
    point: &[K],
    free: &[K],
    value: K,
) -> Result<(usize, Claim<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let column = plan.columns[occurrence.column];
    let (at, blocks) = plan.layouts[column.source].offsets[slot(plan, occurrence.column)];
    let x = stele_poly::eq_table(&column_point(&occurrence.coords, point, free))
        .map_err(|_| Error::Statement)?;
    let u: Vec<K> = occurrence.u.iter().map(|q| point[*q]).collect();
    let r = stele_poly::eq_table(&u).map_err(|_| Error::Statement)?;
    let k = kappa(point[occurrence.v]);
    let first = blocks + occurrence.block * dim::<K>();
    let len = 1usize << column.log_len;
    let mut weights = Vec::new();
    for d in 0..column.limbs {
        let e = if column.limbs == 1 {
            K::from_i64(1)
        } else {
            basis::<K>(d)?
        };
        weights.extend(
            x.iter()
                .enumerate()
                .map(|(p, w)| (at + d * len + p, e * *w)),
        );
    }
    weights.extend(r.into_iter().enumerate().map(|(p, w)| (first + p, k * w)));
    Ok((column.source, Claim { weights, value }))
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
    full_rank(&[eq])
}

/// Whether the M31 coordinates of the `K`-valued functionals (each over the same
/// block entries) are independent: `D` per functional. Public data only.
fn full_rank<K: ChallengeField + CodeField>(functionals: &[Vec<K>]) -> Result<bool, Error> {
    let mut rows: Vec<Vec<M31>> = Vec::new();
    for f in functionals {
        let columns: Vec<Vec<M31>> = f.iter().map(|v| limbs(*v)).collect::<Result<_, _>>()?;
        rows.extend((0..dim::<K>()).map(|limb| columns.iter().map(|c| c[limb]).collect()));
    }
    let (height, width) = (rows.len(), rows.first().map_or(0, Vec::len));
    let mut rank = 0;
    for column in 0..width {
        let Some(pivot) = (rank..height).find(|&i| rows[i][column] != M31::ZERO) else {
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
    Ok(rank == height)
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
fn domain_table<K: ChallengeField>(column: &[K], coords: &[Coord], free: &[K], n: usize) -> Vec<K> {
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
        partial[target] = partial[target] + weight * *value;
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

impl<K: ChallengeField + CodeField> Plan<K> {
    /// An occurrence's claim-mask block, read from its source's message.
    fn block(&self, messages: &[&[M31]], o: &Occurrence) -> Vec<M31> {
        let source = self.columns[o.column].source;
        let (_, blocks) = self.layouts[source].offsets[slot(self, o.column)];
        let width = 1usize << self.layouts[source].m;
        let first = blocks + o.block * dim::<K>();
        (first..first + dim::<K>())
            .map(|p| data(messages[source], width, p))
            .collect()
    }
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

fn instance<K: ChallengeField>(
    id: u64,
    num_vars: u32,
    terms: Vec<Term<K>>,
    claimed: K,
) -> Instance<K> {
    let inputs = terms
        .iter()
        .flat_map(|t| t.factors.iter())
        .max()
        .map_or(0, |m| *m as u64 + 1);
    Instance {
        id,
        num_vars,
        inputs: (0..inputs).collect(),
        terms,
        claimed_sum: claimed,
    }
}

fn step_instance<K: ChallengeField>(step: &Step<K>) -> Instance<K> {
    let mut i = instance(step.id, step.num_vars, step.terms.clone(), zero::<K>());
    i.inputs = (0..(usize::from(step.eq) + step.occurrences.len()) as u64).collect();
    i
}

/// Draw `count` uniform M31 values after the source's `3RC` data masks (A5 item 1).
// shortcut: replays the 3RC data-mask draws of `hiding_message`; share its stream if this shows in a profile.
fn after_masks(seed: &[u8; 32], id: u64, rows: usize, width: usize) -> MaskStream {
    let mut stream = MaskStream::new(seed, SOURCE_MASK, id);
    for _ in 0..3 * rows * width {
        stream.m31();
    }
    stream
}

/// A claim source's message `M'` (A2 item 1): columns and claim masks as data,
/// the masks drawn from the `zk/source-mask` stream after the data masks (A5
/// item 1). `claim_masks = false` leaves the blocks zero (privacy-test control).
fn source_message<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    source: usize,
    columns: &[Vec<K>],
    seed: &[u8; 32],
    claim_masks: bool,
) -> Result<Vec<M31>, Error> {
    let layout = &plan.layouts[source];
    let (rows, width) = (1usize << layout.ell, 1usize << layout.m);
    let mut x = vec![M31::ZERO; rows * width];
    let mut stream = after_masks(seed, plan.source_id(source), rows, width);
    let members = plan
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.source == source);
    for ((index, column), (at, blocks)) in members.zip(&layout.offsets) {
        let len = 1usize << column.log_len;
        for (p, value) in columns[index].iter().enumerate() {
            for (d, limb) in limbs(*value)?.into_iter().take(column.limbs).enumerate() {
                x[at + d * len + p] = limb;
            }
        }
        for value in &mut x[*blocks..*blocks + plan.counts[index] * dim::<K>()] {
            let drawn = stream.m31();
            if claim_masks {
                *value = drawn;
            }
        }
    }
    stele_pcs::hiding_message(plan.source_id(source), layout.ell, layout.m, &x, seed)
        .map_err(Error::Pcs)
}

/// The shared mask source's data: each plain mask's values as `D` limb rows, then
/// the layer blocks from data row `D`, drawn after the data masks.
fn shared_message<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    masks: &[Mask<K>],
    seed: &[u8; 32],
    claim_masks: bool,
) -> Result<Vec<M31>, Error> {
    let (ell, m) = plan.shared;
    let (rows, width) = (1usize << ell, 1usize << m);
    let mut x = vec![M31::ZERO; rows * width];
    for (mask, offset) in masks.iter().zip(&plan.shared_offsets) {
        for (c, value) in mask.columns(0).enumerate() {
            for (d, limb) in limbs(value)?.into_iter().enumerate() {
                x[d * width + offset + c] = limb;
            }
        }
    }
    let mut stream = after_masks(seed, plan.shared_id(), rows, width);
    let start = dim::<K>() * width;
    for value in &mut x[start..start + 4 * dim::<K>() * plan.blocks] {
        let drawn = stream.m31();
        if claim_masks {
            *value = drawn;
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
/// secret seed (A5 items 1–6, RFC-0008 A7). Aborts (`ClaimRank`, `Vanishing`,
/// `BatchPoint`, `DenominatorZero`, A2's `MaskRank`, `MaskWeight`, A4's
/// `MaskPoint`) are public events.
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
    prove_with(statement, columns, &seed.0, t, true, None)
}

/// Which instance an adversary forges (controls only).
#[derive(Clone, Copy, PartialEq)]
enum Forgery {
    /// NC-0916: relation `j`, free rounds and `μ` solved last.
    Relation(usize),
    /// NC-0913: GKR step `g`, free rounds, its first layer child plus one, `μ`
    /// solved last.
    Layer(usize),
    /// GKR step `g` (not the first): honest rounds, its two block finals moved so
    /// that `P(finals)` and `μ` are unchanged.
    Block(usize),
}

/// The block-claim adversary's strategy: honest rounds, then `B_p + 1` and
/// `B_q − S_p/(λ·S_q)`, which leaves `S_p·B_p + λ·S_q·B_q` (and so the final
/// check) unchanged. Inputs 1..=4 of a later GKR step are `S_p, B_p, S_q, B_q`.
struct Perturb<K> {
    inner: Occurrences<K>,
    lambda: K,
}

impl<K: ChallengeField> Perturb<K> {
    fn shift(finals: &[K], lambda: K) -> Result<K, Error> {
        let inverse = (lambda * finals[3]).inverse().ok_or(Error::Statement)?;
        Ok(finals[1] * inverse)
    }
}

impl<K: ChallengeField> Summand<K> for Perturb<K> {
    fn shape(&self) -> (u32, usize) {
        self.inner.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.inner.round(i)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        self.inner.fold(challenge)
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        let mut finals = self.inner.final_values()?;
        let shift = Self::shift(&finals, self.lambda)
            .map_err(|_| stele_sumcheck::Error::InvalidInstance)?;
        finals[2] = finals[2] + K::from_i64(1);
        finals[4] = finals[4] - shift;
        Ok(finals)
    }
}

/// The block-claim adversary, never a verifier input: the honest prover, except
/// that later GKR step `step` reveals two wrong block finals with the step's final
/// check intact. Only the block claims in the shared batch reject it.
#[doc(hidden)]
pub fn forge_block<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    step: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(
        statement,
        columns,
        &seed.0,
        t,
        true,
        Some(Forgery::Block(step)),
    )
}

/// NC-0916's adversary, never a verifier input: the honest prover, except that
/// relation `relation` runs A4's NC-0908 attack. The sources are honest, the rounds
/// are free (`[running, 0, …]`), and `μ` is solved last so the relation's final
/// check passes. The finals are the true `V̇` values at the forged point, so every
/// source batch passes. Only binding each relation's `μ_j` to the committed `g_j`
/// in the shared batch rejects it.
#[doc(hidden)]
pub fn forge<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    relation: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let forgery = Some(Forgery::Relation(relation));
    prove_with(statement, columns, &seed.0, t, true, forgery)
}

/// NC-0913's adversary, never a verifier input: the honest prover, except that GKR
/// step `step` reveals its first masked layer value plus one, with free rounds and
/// `μ` solved last so the step itself passes. The prover continues from the true
/// value, so only the next step's claimed sum rejects it.
#[doc(hidden)]
pub fn forge_layer<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    step: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(
        statement,
        columns,
        &seed.0,
        t,
        true,
        Some(Forgery::Layer(step)),
    )
}

fn evaluate<K: ChallengeField>(terms: &[Term<K>], values: &[K]) -> K {
    terms.iter().fold(zero::<K>(), |s, term| {
        s + term
            .factors
            .iter()
            .fold(term.coefficient, |p, f| p * values[*f as usize])
    })
}

/// The masked sumcheck's messages (A4 order) with free rounds and `μ` solved last.
/// `tweak` adds one to that final before `μ` is solved. Returns the proof, the
/// point and the true finals.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn forged<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    degree: usize,
    mut summand: Occurrences<K>,
    mask: &Mask<K>,
    binding: &[u8],
    tweak: Option<usize>,
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>, Vec<K>), Error> {
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    let sumcheck = Error::Sumcheck;
    let mask_sum = mask.sum();
    t.absorb(
        AbsorbLabel::Instance,
        &i.encode_degree(degree).map_err(sumcheck)?,
    )
    .map_err(fail)?;
    t.absorb(AbsorbLabel::FieldSources, binding).map_err(fail)?;
    let bytes = stele_sumcheck::message_bytes(i.id, 0, &[mask_sum]).map_err(sumcheck)?;
    t.absorb(AbsorbLabel::ZkMaskSum, &bytes).map_err(fail)?;
    let alpha = t.challenge(ChallengeLabel::ZkMaskWeight).map_err(fail)?;
    let mut running = i.claimed_sum + alpha * mask_sum;
    let (mut rounds, mut point) = (Vec::new(), Vec::new());
    for index in 0..i.num_vars {
        let mut values = vec![zero::<K>(); degree + 1];
        values[0] = running;
        let bytes = stele_sumcheck::message_bytes(i.id, index, &values).map_err(sumcheck)?;
        t.absorb(AbsorbLabel::Round, &bytes).map_err(fail)?;
        let c = t.challenge(ChallengeLabel::Sumcheck).map_err(fail)?;
        // The polynomial with value `running` at 0 and 0 at 1..δ, at `c`.
        for k in 1..=degree as i64 {
            let inverse = K::from_i64(-k).inverse().ok_or(Error::Statement)?;
            running = running * (c - K::from_i64(k)) * inverse;
        }
        summand.fold(c).map_err(sumcheck)?;
        rounds.push(values);
        point.push(c);
    }
    let truth = summand.final_values().map_err(sumcheck)?;
    let mut finals = truth.clone();
    if let Some(index) = tweak {
        finals[index] = finals[index] + K::from_i64(1);
    }
    let inverse = alpha.inverse().ok_or(Error::Statement)?;
    let mask_final = (running - evaluate(&i.terms, &finals)) * inverse;
    let mut values = finals.clone();
    values.push(mask_final);
    let bytes =
        stele_sumcheck::message_bytes(i.id, finals.len() as u32 + 1, &values).map_err(sumcheck)?;
    t.absorb(AbsorbLabel::Final, &bytes).map_err(fail)?;
    Ok((
        masked::Proof {
            mask_sum,
            rounds,
            final_values: finals,
            mask_final,
        },
        point,
        truth,
    ))
}

/// One masked instance: honest, or forged under `forgery`. Returns the proof, the
/// point, the true finals and the `μ` the shared batch receives (the true `g(ρ)`
/// when forged).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn masked_instance<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    degree: usize,
    summand: Occurrences<K>,
    mask: &Mask<K>,
    binding: &[u8],
    forged_here: bool,
    tweak: Option<usize>,
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>, Vec<K>, K), Error> {
    if forged_here {
        let (proof, point, truth) = forged(i, degree, summand, mask, binding, tweak, t)?;
        let mu = mask.evaluate(&point).map_err(Error::Sumcheck)?;
        Ok((proof, point, truth, mu))
    } else {
        let (proof, point) =
            masked::prove(i, summand, mask, binding, t).map_err(Error::Sumcheck)?;
        let (truth, mu) = (proof.final_values.clone(), proof.mask_final);
        Ok((proof, point, truth, mu))
    }
}

fn prove_with<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: &[u8; 32],
    t: &mut Transcript<K>,
    claim_masks: bool,
    forgery: Option<Forgery>,
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
    let mut data: Vec<Vec<K>> = columns
        .iter()
        .map(|column| column.iter().map(|x| element::<K>(*x)).collect())
        .collect();
    let early = plan.early();
    let messages = (0..early)
        .map(|s| source_message(&plan, s, &data, seed, claim_masks))
        .collect::<Result<Vec<_>, _>>()?;
    let masks = plan
        .masks
        .iter()
        .map(|(id, n, degree)| Mask::plain(seed, *id, *n, *degree).map_err(Error::Sumcheck))
        .collect::<Result<Vec<_>, _>>()?;
    let hiding = |id: u64, (ell, m): (u8, u8), message| {
        PreparedSource::<K>::hiding(id, ell, m, BLOWUP, message, seed, &mut HashUsage::default())
            .map_err(Error::Pcs)
    };
    let mut prepared = Vec::new();
    for (s, message) in messages.iter().enumerate() {
        let layout = &plan.layouts[s];
        prepared.push(hiding(plan.source_id(s), (layout.ell, layout.m), message)?);
    }
    let mut sources = Vec::new();
    let mut certificates = Vec::new();
    let mut verified = Vec::new();
    for p in &prepared {
        let (certificate, v) = certify(p)?;
        sources.push(p.source().bytes().to_vec());
        certificates.push(certificate);
        verified.push(v);
    }
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    t.absorb(AbsorbLabel::FieldSources, &sources.concat())
        .map_err(fail)?;
    // RFC-0008 A7 items 1–3: β and α after the multiplicities, then the top.
    let mut runs = Vec::new();
    let mut trees = Vec::new();
    for lp in &plan.lookups {
        let beta = t.challenge(ChallengeLabel::LookupBeta).map_err(fail)?;
        let alpha = t.challenge(ChallengeLabel::LookupAlpha).map_err(fail)?;
        let layers = lookup::tree(lp, &data, beta, alpha);
        data.extend(lookup::top(lp, &layers)?);
        trees.push(layers);
        runs.push(lookup::Run::new(beta, alpha));
    }
    let top_message = if plan.lookups.is_empty() {
        Vec::new()
    } else {
        source_message(&plan, early, &data, seed, claim_masks)?
    };
    let shared_message = self::shared_message(&plan, &masks, seed, claim_masks)?;
    if !plan.lookups.is_empty() {
        let layout = &plan.layouts[early];
        prepared.push(hiding(
            plan.source_id(early),
            (layout.ell, layout.m),
            &top_message,
        )?);
    }
    prepared.push(hiding(plan.shared_id(), plan.shared, &shared_message)?);
    for p in &prepared[early..] {
        let (certificate, v) = certify(p)?;
        sources.push(p.source().bytes().to_vec());
        certificates.push(certificate);
        verified.push(v);
    }
    t.absorb(AbsorbLabel::FieldSources, &sources[early..].concat())
        .map_err(fail)?;
    let shared_index = plan.layouts.len();
    let binding = sources[shared_index].clone();
    let mut all: Vec<&[M31]> = messages.iter().map(Vec::as_slice).collect();
    all.push(&top_message);
    let block_of = |o: &Occurrence| plan.block(&all, o);
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); plan.layouts.len()];
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
            factors.push(Factor {
                x: domain_table(&data[o.column], &o.coords, &free, n),
                r: block_table(&block_of(o), &o.u, n),
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
        let here = forgery == Some(Forgery::Relation(j));
        let (proof, point, truth, mu) =
            masked_instance(&i, step.degree, summand, &masks[j], &binding, here, None, t)?;
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
            let (source, claim) = occurrence_claim(&plan, o, &point, &free, truth[first + k])?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, &point, mu)?);
        relations.push(proof);
    }
    let mut gkr = Vec::new();
    for (g, step) in plan.gkr.iter().enumerate() {
        let index = plan.steps.len() + g;
        let run = &mut runs[step.lookup_index()];
        let (terms, claimed) = lookup::start(step, run, t, c_width(&plan, step))?;
        let i = instance(step.id, step.num_vars, terms, claimed);
        let factors = lookup::factors(
            &plan,
            step,
            run,
            &trees[step.lookup_index()],
            &data,
            &shared_message,
            &block_of,
        )?;
        let summand = Occurrences {
            factors,
            terms: i.terms.clone(),
            degree: step.degree,
            num_vars: step.num_vars,
            bound: 0,
        };
        let here = forgery == Some(Forgery::Layer(g));
        let tweak = if here {
            lookup::first_layer(step)
        } else {
            None
        };
        let (proof, point, truth, mu) = if forgery == Some(Forgery::Block(g)) {
            let lambda = i.terms[1].coefficient;
            let summand = Perturb {
                inner: summand,
                lambda,
            };
            let (proof, point) =
                masked::prove(&i, summand, &masks[index], &binding, t).map_err(Error::Sumcheck)?;
            let mut truth = proof.final_values.clone();
            let shift = Perturb::<K>::shift(&truth, lambda)?;
            truth[2] = truth[2] - K::from_i64(1);
            truth[4] = truth[4] + shift;
            let mu = proof.mask_final;
            (proof, point, truth, mu)
        } else {
            masked_instance(
                &i,
                step.degree,
                summand,
                &masks[index],
                &binding,
                here,
                tweak,
                t,
            )?
        };
        lookup::aborts(step, run, &point)?;
        let finals = lookup::finals(&plan, step, run, &point, &truth)?;
        for (source, claim) in finals.claims.iter().cloned() {
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, index, &point, mu)?);
        mus.extend(finals.blocks.iter().cloned());
        lookup::advance(step, run, &point, &finals, t)?;
        gkr.push(proof);
    }
    let mut batches = Vec::new();
    for (b, source) in plan.batched.iter().enumerate() {
        let index = plan.steps.len() + plan.gkr.len() + b;
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
    let shared = &prepared[shared_index];
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
            &verified[shared_index],
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
        gkr,
        batches,
        shared: proof,
        shared_opening,
    })
}

/// The tuple width of a GKR step's lookup.
fn c_width<K>(plan: &Plan<K>, step: &lookup::GkrStep) -> usize {
    plan.lookups[step.lookup_index()].width()
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
    let shared_index = plan.layouts.len();
    if proof.sources.len() != shared_index + 1
        || proof.certificates.len() != proof.sources.len()
        || proof.relations.len() != plan.steps.len()
        || proof.gkr.len() != plan.gkr.len()
        || proof.batches.len() != plan.batched.len()
    {
        return Err(shape);
    }
    let mut verified = Vec::new();
    for (s, (bytes, certificate)) in proof.sources.iter().zip(&proof.certificates).enumerate() {
        let (id, (ell, m)) = if s < shared_index {
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
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    let early = plan.early();
    t.absorb(AbsorbLabel::FieldSources, &proof.sources[..early].concat())
        .map_err(fail)?;
    let mut runs = Vec::new();
    for _ in &plan.lookups {
        let beta = t.challenge(ChallengeLabel::LookupBeta).map_err(fail)?;
        let alpha = t.challenge(ChallengeLabel::LookupAlpha).map_err(fail)?;
        runs.push(lookup::Run::new(beta, alpha));
    }
    t.absorb(AbsorbLabel::FieldSources, &proof.sources[early..].concat())
        .map_err(fail)?;
    let binding = &proof.sources[shared_index];
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); plan.layouts.len()];
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
            let (source, claim) = occurrence_claim(&plan, o, point, &free, finals[first + k])?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, point, result.mask_final)?);
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    for (g, (step, sumcheck)) in plan.gkr.iter().zip(&proof.gkr).enumerate() {
        let index = plan.steps.len() + g;
        let run = &mut runs[step.lookup_index()];
        let (terms, claimed) = lookup::start(step, run, t, c_width(&plan, step))?;
        let i = instance(step.id, step.num_vars, terms, claimed);
        let result = masked::verify_degree(&i, step.degree, sumcheck, binding, t)
            .map_err(Error::Sumcheck)?;
        let point = &result.reduction.point;
        let finals = lookup::finals(&plan, step, run, point, &sumcheck.final_values)?;
        for (source, claim) in finals.claims.iter().cloned() {
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, index, point, result.mask_final)?);
        mus.extend(finals.blocks.iter().cloned());
        lookup::advance(step, run, point, &finals, t)?;
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    for (b, (source, batch)) in plan.batched.iter().zip(&proof.batches).enumerate() {
        let index = plan.steps.len() + plan.gkr.len() + b;
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
    let shared = &verified[shared_index];
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
        lookups: runs.iter().map(|r| [r.beta, r.alpha]).collect(),
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
            lookups: Vec::new(),
        };
        let a: Vec<M31> = (0..8).map(|n| M31::from_i64(n + 2)).collect();
        let b: Vec<M31> = (0..8).map(|n| M31::from_i64(5 - n)).collect();
        let c = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
        let columns = vec![a.clone(), b, c];
        for masks in [true, false] {
            for n in 0..8u8 {
                let t = || Transcript::<QM31>::new(b"leak").expect("transcript");
                let proof = prove_with(&statement, &columns, &[n; 32], &mut t(), masks, None)
                    .expect("proof");
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

    /// A lookup of `x` (16 entries) into the table `3j + 1`, 12 valid rows.
    fn lookup_case() -> (Statement<QM31>, Vec<Vec<M31>>) {
        let statement = Statement::<QM31> {
            sources: 1,
            columns: (0..2)
                .map(|_| Column {
                    source: 0,
                    log_len: 4,
                })
                .collect(),
            relations: Vec::new(),
            lookups: vec![Lookup {
                columns: vec![0],
                multiplicity: 1,
                table: (0..16).map(|j| vec![3 * j + 1]).collect(),
                valid: 12,
            }],
        };
        let mut counts = vec![0i64; 16];
        let x = (0..16)
            .map(|i| {
                let j = (5 * i + 2) % 12;
                counts[j] += 1;
                M31::from_i64(3 * j as i64 + 1)
            })
            .collect();
        (
            statement,
            vec![x, counts.into_iter().map(M31::from_i64).collect()],
        )
    }

    /// Leak control for `accepts_uniform_layer_values` (check_gkr.py's no-mask
    /// variant): with the layer blocks removed, the first step's revealed `p(x*, 0)`
    /// is exactly the tree's layer value; with them it never is.
    #[test]
    fn rejects_unmasked_layers_in_privacy_test() {
        let (statement, columns) = lookup_case();
        let plan = plan(&statement).expect("plan");
        let data: Vec<Vec<QM31>> = columns
            .iter()
            .map(|c| c.iter().map(|x| element::<QM31>(*x)).collect())
            .collect();
        for masks in [true, false] {
            for n in 0..6u8 {
                let t = || Transcript::<QM31>::new(b"leak").expect("transcript");
                let proof = prove_with(&statement, &columns, &[n; 32], &mut t(), masks, None)
                    .expect("proof");
                let verified = verify(&statement, &proof, &mut t()).expect("accepted");
                let [beta, alpha] = verified.lookups[0];
                let layers = lookup::tree(&plan.lookups[0], &data, beta, alpha);
                let mut at = verified.reductions[2].point.clone();
                at.push(QM31::from_i64(0));
                let eq = stele_poly::eq_table(&at).expect("eq");
                let exact = layers[4]
                    .iter()
                    .zip(&eq)
                    .fold(QM31::from_i64(0), |s, (v, e)| s + v[0] * *e);
                let residual = proof.gkr[0].final_values[3] - exact;
                assert_eq!(residual == QM31::from_i64(0), !masks);
            }
        }
    }

    /// RFC-0008 A7 item 3: a zero denominator in the committed top aborts.
    #[test]
    fn rejects_zero_top_denominator() {
        let (statement, _) = lookup_case();
        let plan = plan(&statement).expect("plan");
        let mut layers = vec![Vec::new(); 6];
        layers[3] = vec![[QM31::from_i64(1), QM31::from_i64(2)]; 8];
        assert!(lookup::top(&plan.lookups[0], &layers).is_ok());
        layers[3][5][1] = QM31::from_i64(0);
        assert_eq!(
            lookup::top(&plan.lookups[0], &layers).err(),
            Some(Error::DenominatorZero)
        );
    }
}
