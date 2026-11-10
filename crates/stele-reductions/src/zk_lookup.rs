//! RFC-0008 A7: ZK-GKR over one lookup's A5 fraction tree (dev-zk components).
//!
//! The lookup and table leaves form one tree over `m = n + 1` variables, leaf
//! `(x, h)` with `h` last: `(1, α − Σ β^i x_i(x))` for `h = 0` and
//! `(−mult(x), α − Σ β^i T_i(x))` (padded rows `(0, 1)`) for `h = 1`. A parent is
//! `(p0·q1 + p1·q0, q0·q1)` of its children `(·, 0)` and `(·, 1)`. Its sum is zero
//! exactly when every tuple is a table row counted by `mult` (A5, error `e`).
//!
//! - **Top** (item 3): layer `k0 = c_D + 1` is committed as `p, q, h = p/q`, proven
//!   by `h·q − p = 0` and `Σ h = 0`. No root is revealed. A zero `q` aborts
//!   (`DenominatorZero`).
//! - **Steps** (item 4): one masked A1 sumcheck per layer `k = k0..m−1`. The first
//!   step is the zero-sum `Σ_x eq(r, x)·[F_λ(children) − V̇_p(x) − λ·V̇_q(x)] = 0`
//!   on masked occurrences of the top columns. Each later step proves
//!   `Σ_{s,x} (1 − s)·eq(r, x)·F_λ(children) + s·Σ_P λ^P·κ_P·eq(u_P, y)·[x̄ = 0]·r̃_P(t*, y)
//!   = c_p + λ·c_q`, whose `s = 1` half carries the incoming claims' mask terms;
//!   `y` is the last `c_D + 1` variables of `x` and `x̄` the others. Its block
//!   finals `r̃_P(t*, y*)` are claims on the shared mask source.
//! - **Layers** below the top have `V̇(x, T) = Ṽ(x, T) + κ(x_v)·r̃(T, x_u)` with a
//!   `4D`-entry block on `(T, y)` in the shared source: `v` is `x`'s first (for `p`)
//!   or second (for `q`) variable and `u = y`. Each block reveals three functionals
//!   (at `T = 0, 1` and its `s = 1` claim); rank `< 3D` aborts (`ClaimRank`).
//! - **Leaves** (item 5): the last step's children are masked occurrences of the
//!   committed `mult` and tuple columns and the public table.
//!
//! Challenges: `β, α` (`LookupBeta`, `LookupAlpha`), `r` for the first step
//! (`ZeroWeight`), `λ` per step (`FractionGamma`), the line challenge `t*` after
//! each non-leaf step (`FractionFold`). No new label.
use super::{
    dim, domain_table, full_rank, kappa, occurrence_claim, zero, Claim, Coord, Error, Factor,
    Lookup, Occurrence, Plan, Statement,
};
use alloc::vec;
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_pcs::CodeField;
use stele_sumcheck::Term;

/// One lookup's plan.
pub(super) struct LookupPlan {
    n: usize,
    k0: usize,
    columns: Vec<usize>,
    multiplicity: usize,
    table: Vec<Vec<i64>>,
    valid: usize,
    first_block: usize,
}

impl LookupPlan {
    /// Masked layers `k0 + 1..=n`, two blocks (`p`, `q`) each.
    pub(super) fn block_count(&self) -> usize {
        2 * (self.n - self.k0)
    }
    fn block(&self, layer: usize, poly: usize) -> usize {
        self.first_block + 2 * (layer - self.k0 - 1) + poly
    }
    /// The tuple width `c`.
    pub(super) fn width(&self) -> usize {
        self.columns.len()
    }
}

/// One input of a GKR step.
enum Gin {
    /// `eq(r, x)` (first step) or `(1 − s)·eq(r, x)`.
    Head,
    /// `s·κ_P·eq(u_P, y)·[x̄ = 0]`, public.
    Select(usize),
    /// `r̃_P(t*, y)` of the incoming layer's block; its final is a block claim.
    Block(usize),
    /// A masked occurrence of a committed top column (first step).
    Top(Occurrence),
    /// A masked layer child `V̇_P(x, t)`.
    Layer {
        poly: usize,
        t: usize,
        v: usize,
        u: Vec<usize>,
    },
    /// A masked occurrence of `mult` or a tuple column (leaf step).
    Leaf(Occurrence),
    /// The public table denominator `α − Σ β^i T_i(x)` (1 on padding).
    Table,
}

/// One GKR step: the layer `k` of its incoming claims and its instance shape.
pub(super) struct GkrStep {
    pub(super) id: u64,
    lookup: usize,
    k: usize,
    first: bool,
    leaf: bool,
    pub(super) num_vars: u32,
    inputs: Vec<Gin>,
    pub(super) degree: usize,
    /// Domain indices of `y`, and of `x`'s first variable.
    y: Vec<usize>,
    xo: usize,
}

impl GkrStep {
    pub(super) fn lookup_index(&self) -> usize {
        self.lookup
    }
    pub(super) fn occurrences_mut(&mut self) -> impl Iterator<Item = &mut Occurrence> {
        self.inputs.iter_mut().filter_map(|i| match i {
            Gin::Top(o) | Gin::Leaf(o) => Some(o),
            _ => None,
        })
    }
}

fn term<K: ChallengeField>(coefficient: K, factors: &[u32]) -> Term<K> {
    Term {
        coefficient,
        factors: factors.to_vec(),
    }
}

/// The step's terms at `λ, α, β` (input 0 is the head).
fn terms<K: ChallengeField>(
    step: &GkrStep,
    lambda: K,
    alpha: K,
    beta: K,
    c: usize,
) -> Vec<Term<K>> {
    let one = K::from_i64(1);
    let mut out = Vec::new();
    let base = if step.first {
        out.push(term(zero::<K>() - one, &[0, 1]));
        out.push(term(zero::<K>() - lambda, &[0, 2]));
        3
    } else {
        out.push(term(one, &[1, 2]));
        out.push(term(lambda, &[3, 4]));
        5
    };
    if step.leaf {
        // p0 = 1, p1 = −V̇_mult, q0 = α − Σ β^i V̇_{x_i}, q1 = T:
        // F = T − α·M + Σ β^i·M·X_i + λα·T − λ·Σ β^i·X_i·T.
        let (m, table) = (base, base + 1 + c as u32);
        out.push(term(one + lambda * alpha, &[0, table]));
        out.push(term(zero::<K>() - alpha, &[0, m]));
        let mut power = one;
        for i in 0..c as u32 {
            out.push(term(power, &[0, m, m + 1 + i]));
            out.push(term(zero::<K>() - lambda * power, &[0, m + 1 + i, table]));
            power = power * beta;
        }
    } else {
        let (p0, p1, q0, q1) = (base, base + 1, base + 2, base + 3);
        out.push(term(one, &[0, p0, q1]));
        out.push(term(one, &[0, p1, q0]));
        out.push(term(lambda, &[0, q0, q1]));
    }
    out
}

/// The lookup's GKR steps, top first (RFC-0008 A7 item 4).
pub(super) fn plan_lookup<K: ChallengeField + CodeField>(
    statement: &Statement<K>,
    lookup: usize,
    spec: &Lookup,
    top: [usize; 3],
    first_block: usize,
    c: usize,
) -> Result<(LookupPlan, Vec<GkrStep>), Error> {
    let k0 = c + 1;
    let width = spec.columns.len();
    let n = statement
        .columns
        .get(spec.multiplicity)
        .ok_or(Error::Statement)?
        .log_len as usize;
    if width == 0
        || !(k0..=20).contains(&n)
        || spec.columns.iter().any(|x| {
            statement
                .columns
                .get(*x)
                .is_none_or(|col| col.log_len as usize != n)
        })
        || spec.table.len() != 1 << n
        || spec.table.iter().any(|row| row.len() != width)
        || spec.valid > 1 << n
    {
        return Err(Error::Statement);
    }
    let lp = LookupPlan {
        n,
        k0,
        columns: spec.columns.clone(),
        multiplicity: spec.multiplicity,
        table: spec.table.clone(),
        valid: spec.valid,
        first_block,
    };
    let occurrence = |column: usize, coords: Vec<Coord>| Occurrence {
        column,
        coords,
        v: 0,
        u: Vec::new(),
        block: 0,
    };
    let mut steps = Vec::new();
    for k in k0..=n {
        let (first, leaf) = (k == k0, k == n);
        let xo = usize::from(!first);
        let y: Vec<usize> = (xo + k - k0..xo + k).collect();
        let vars = |count: usize| (0..count).map(|j| Coord::Var(xo + j)).collect::<Vec<_>>();
        let mut inputs = vec![Gin::Head];
        if first {
            inputs.push(Gin::Top(occurrence(top[0], vars(k))));
            inputs.push(Gin::Top(occurrence(top[1], vars(k))));
        } else {
            for poly in 0..2 {
                inputs.push(Gin::Select(poly));
                inputs.push(Gin::Block(poly));
            }
        }
        if leaf {
            inputs.push(Gin::Leaf(occurrence(spec.multiplicity, vars(n))));
            for x in &spec.columns {
                inputs.push(Gin::Leaf(occurrence(*x, vars(n))));
            }
            inputs.push(Gin::Table);
        } else {
            for poly in 0..2 {
                for t in 0..2 {
                    inputs.push(Gin::Layer {
                        poly,
                        t,
                        v: xo + poly,
                        u: y.clone(),
                    });
                }
            }
        }
        let num_vars = k + xo;
        let mut step = GkrStep {
            id: 0,
            lookup,
            k,
            first,
            leaf,
            num_vars: num_vars as u32,
            inputs,
            degree: 0,
            y,
            xo,
        };
        let one = K::from_i64(1);
        let shape = terms(&step, one, one, one, width);
        let mut masked: Vec<Option<(usize, Vec<usize>)>> = step
            .inputs
            .iter()
            .map(|i| match i {
                Gin::Layer { v, u, .. } => Some((*v, u.clone())),
                _ => None,
            })
            .collect();
        let free: Vec<bool> = step
            .inputs
            .iter()
            .map(|i| matches!(i, Gin::Top(_) | Gin::Leaf(_)))
            .collect();
        super::vanish(num_vars, c, &shape, &mut masked, &free)?;
        for (input, m) in step.inputs.iter_mut().zip(&masked) {
            if let (Gin::Top(o) | Gin::Leaf(o), Some((v, u))) = (input, m) {
                o.v = *v;
                o.u = u.clone();
            }
        }
        step.degree = super::degree(num_vars, &shape, &masked);
        if step.degree > 60 {
            return Err(Error::Statement);
        }
        steps.push(step);
    }
    Ok((lp, steps))
}

fn compress<K: ChallengeField>(row: impl Iterator<Item = K>, beta: K) -> K {
    let mut power = K::from_i64(1);
    let mut total = zero::<K>();
    for x in row {
        total = total + power * x;
        power = power * beta;
    }
    total
}

/// The public table denominators `α − Σ β^i T_i(x)`, 1 on padding.
fn table<K: ChallengeField>(lp: &LookupPlan, beta: K, alpha: K) -> Vec<K> {
    lp.table
        .iter()
        .enumerate()
        .map(|(x, row)| {
            if x < lp.valid {
                alpha - compress(row.iter().map(|v| K::from_i64(*v)), beta)
            } else {
                K::from_i64(1)
            }
        })
        .collect()
}

/// The prover's tree, `layers[k]` over `k` variables for `k ≤ m` (A5, A7 item 2).
pub(super) fn tree<K: ChallengeField>(
    lp: &LookupPlan,
    data: &[Vec<K>],
    beta: K,
    alpha: K,
) -> Vec<Vec<[K; 2]>> {
    let q = table(lp, beta, alpha);
    let mut leaves = Vec::new();
    for (x, qx) in q.iter().enumerate() {
        let tuple = compress(lp.columns.iter().map(|c| data[*c][x]), beta);
        leaves.push([K::from_i64(1), alpha - tuple]);
        leaves.push([zero::<K>() - data[lp.multiplicity][x], *qx]);
    }
    let mut layers = vec![leaves];
    while layers[layers.len() - 1].len() > 1 {
        let children = &layers[layers.len() - 1];
        let parents = children
            .chunks_exact(2)
            .map(|pair| {
                let ([p0, q0], [p1, q1]) = (pair[0], pair[1]);
                [p0 * q1 + p1 * q0, q0 * q1]
            })
            .collect();
        layers.push(parents);
    }
    layers.reverse();
    layers
}

/// The committed top `p, q, h = p/q` (A7 item 3); a zero `q` aborts.
pub(super) fn top<K: ChallengeField>(
    lp: &LookupPlan,
    layers: &[Vec<[K; 2]>],
) -> Result<[Vec<K>; 3], Error> {
    let layer = &layers[lp.k0];
    let mut h = Vec::new();
    for [p, q] in layer {
        h.push(*p * q.inverse().ok_or(Error::DenominatorZero)?);
    }
    Ok([
        layer.iter().map(|v| v[0]).collect(),
        layer.iter().map(|v| v[1]).collect(),
        h,
    ])
}

/// Each lookup's running state: challenges, the incoming claims and point, and the
/// incoming blocks' first two functionals (for the producer's rank check).
pub(super) struct Run<K> {
    pub(super) beta: K,
    pub(super) alpha: K,
    r: Vec<K>,
    claims: [K; 2],
    incoming: [(K, Vec<K>); 2],
    tstar: K,
    pending: [Vec<Vec<K>>; 2],
}

impl<K: ChallengeField> Run<K> {
    pub(super) fn new(beta: K, alpha: K) -> Self {
        Self {
            beta,
            alpha,
            r: Vec::new(),
            claims: [zero::<K>(); 2],
            incoming: [(zero::<K>(), Vec::new()), (zero::<K>(), Vec::new())],
            tstar: zero::<K>(),
            pending: [Vec::new(), Vec::new()],
        }
    }
}

fn draw<K: ChallengeField>(t: &mut Transcript<K>, label: ChallengeLabel) -> Result<K, Error> {
    t.challenge(label).map_err(|e| Error::Sumcheck(e.into()))
}

/// Draw the step's challenges and return its terms and claimed sum.
pub(super) fn start<K: ChallengeField>(
    step: &GkrStep,
    run: &mut Run<K>,
    t: &mut Transcript<K>,
    c: usize,
) -> Result<(Vec<Term<K>>, K), Error> {
    if step.first {
        run.r = (0..step.k)
            .map(|_| draw(t, ChallengeLabel::ZeroWeight))
            .collect::<Result<_, _>>()?;
    }
    let lambda = draw(t, ChallengeLabel::FractionGamma)?;
    let claimed = if step.first {
        zero::<K>()
    } else {
        run.claims[0] + lambda * run.claims[1]
    };
    Ok((terms(step, lambda, run.alpha, run.beta, c), claimed))
}

/// The `4D` entries of a layer block in the shared source's data message.
fn block_entries<K: CodeField>(plan: &Plan<K>, shared: &[M31], index: usize) -> Vec<M31> {
    let width = 1usize << plan.shared.1;
    let start = dim::<K>() * width + 4 * dim::<K>() * index;
    (start..start + 4 * dim::<K>())
        .map(|p| shared[(p / width) * 2 * width + p % width])
        .collect()
}

fn element<K: ChallengeField>(x: M31) -> K {
    K::from_i64(i64::from(x.as_u32()))
}

/// The prover's input tables over the step's domain (MSB-first, `s` first).
#[allow(clippy::too_many_arguments)]
pub(super) fn factors<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    step: &GkrStep,
    run: &Run<K>,
    layers: &[Vec<[K; 2]>],
    data: &[Vec<K>],
    shared: &[M31],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
) -> Result<Vec<Factor<K>>, Error> {
    let lp = &plan.lookups[step.lookup];
    let n = step.num_vars as usize;
    let half = 1usize << step.k;
    let both = |table: Vec<K>| -> Vec<K> {
        if step.first {
            table
        } else {
            table.iter().chain(&table).copied().collect()
        }
    };
    let public = |x: Vec<K>| Factor {
        x,
        r: Vec::new(),
        v: None,
    };
    let mut out = Vec::new();
    for input in &step.inputs {
        out.push(match input {
            Gin::Head => {
                let eq = stele_poly::eq_table(&run.r).map_err(|_| Error::Statement)?;
                if step.first {
                    public(eq)
                } else {
                    public(eq.into_iter().chain(vec![zero::<K>(); half]).collect())
                }
            }
            Gin::Select(poly) => {
                let (k, u) = &run.incoming[*poly];
                let eq = stele_poly::eq_table(u).map_err(|_| Error::Statement)?;
                let mut x = vec![zero::<K>(); 2 * half];
                for (y, w) in eq.into_iter().enumerate() {
                    x[half + y] = *k * w;
                }
                public(x)
            }
            Gin::Block(poly) => {
                let block = block_entries(plan, shared, lp.block(step.k, *poly));
                let two = block.len() / 2;
                let one = K::from_i64(1);
                let x = (0..half)
                    .map(|xi| {
                        let y = xi & (two - 1);
                        (one - run.tstar) * element::<K>(block[y])
                            + run.tstar * element::<K>(block[two + y])
                    })
                    .collect();
                public(both(x))
            }
            Gin::Top(o) | Gin::Leaf(o) => Factor {
                x: domain_table(&data[o.column], &o.coords, &[], n),
                r: super::block_table(&block_of(o), &o.u, n),
                v: Some(o.v),
            },
            Gin::Layer { poly, t, v, u } => {
                let values = &layers[step.k + 1];
                let x = (0..half).map(|xi| values[(xi << 1) | t][*poly]).collect();
                let block = block_entries(plan, shared, lp.block(step.k + 1, *poly));
                let two = block.len() / 2;
                Factor {
                    x: both(x),
                    r: super::block_table(&block[t * two..(t + 1) * two], u, n),
                    v: Some(*v),
                }
            }
            Gin::Table => public(both(table(lp, run.beta, run.alpha))),
        });
    }
    Ok(out)
}

/// What a step's finals leave: claims on claim sources, block claims on the shared
/// source, and the layer values `[[p(0), p(1)], [q(0), q(1)]]`. Public finals are
/// checked (`ClaimMismatch`).
pub(super) struct Finals<K> {
    pub(super) claims: Vec<(usize, Claim<K>)>,
    pub(super) blocks: Vec<Claim<K>>,
    layers: [[K; 2]; 2],
}

/// Check the public finals and route every other final.
pub(super) fn finals<K: ChallengeField + CodeField + Eq>(
    plan: &Plan<K>,
    step: &GkrStep,
    run: &Run<K>,
    point: &[K],
    finals: &[K],
) -> Result<Finals<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let lp = &plan.lookups[step.lookup];
    let mismatch = Error::Sumcheck(stele_sumcheck::Error::ClaimMismatch);
    let one = K::from_i64(1);
    let x = &point[step.xo..];
    let y: Vec<K> = step.y.iter().map(|j| point[*j]).collect();
    let eq = |a: &[K], b: &[K]| stele_poly::eq_evaluate(a, b).map_err(|_| Error::Statement);
    let mut out = Finals {
        claims: Vec::new(),
        blocks: Vec::new(),
        layers: [[zero::<K>(); 2]; 2],
    };
    for (input, value) in step.inputs.iter().zip(finals) {
        match input {
            Gin::Head => {
                let head = eq(&run.r, x)? * if step.first { one } else { one - point[0] };
                if *value != head {
                    return Err(mismatch);
                }
            }
            Gin::Select(poly) => {
                let (k, u) = &run.incoming[*poly];
                let rest = point[step.xo..step.y[0]]
                    .iter()
                    .fold(one, |p, z| p * (one - *z));
                if *value != point[0] * *k * eq(u, &y)? * rest {
                    return Err(mismatch);
                }
            }
            Gin::Block(poly) => {
                let width = 1usize << plan.shared.1;
                let start = dim::<K>() * width + 4 * dim::<K>() * lp.block(step.k, *poly);
                let at = core::iter::once(run.tstar)
                    .chain(y.iter().copied())
                    .collect::<Vec<_>>();
                let w = stele_poly::eq_table(&at).map_err(|_| Error::Statement)?;
                out.blocks.push(Claim {
                    weights: w
                        .into_iter()
                        .enumerate()
                        .map(|(e, w)| (start + e, w))
                        .collect(),
                    value: *value,
                });
            }
            Gin::Top(o) | Gin::Leaf(o) => {
                out.claims
                    .push(occurrence_claim(plan, o, point, &[], *value)?);
            }
            Gin::Layer { poly, t, .. } => out.layers[*poly][*t] = *value,
            Gin::Table => {
                let q = table(lp, run.beta, run.alpha);
                let w = stele_poly::eq_table(x).map_err(|_| Error::Statement)?;
                let expected = q.iter().zip(&w).fold(zero::<K>(), |s, (a, b)| s + *a * *b);
                if *value != expected {
                    return Err(mismatch);
                }
            }
        }
    }
    Ok(out)
}

/// The producer's public aborts for a step (A5 item 4, A7 item 4): every masked
/// occurrence's `κ` and claim-block rank, every layer child's `κ`, and each
/// incoming block's rank over its three functionals.
pub(super) fn aborts<K: ChallengeField + CodeField + Eq>(
    step: &GkrStep,
    run: &Run<K>,
    point: &[K],
) -> Result<(), Error> {
    for input in &step.inputs {
        match input {
            Gin::Top(o) | Gin::Leaf(o) => {
                if kappa(point[o.v]) == zero::<K>() {
                    return Err(Error::Vanishing);
                }
                let u: Vec<K> = o.u.iter().map(|q| point[*q]).collect();
                if !super::block_rank(&u)? {
                    return Err(Error::ClaimRank);
                }
            }
            Gin::Layer { v, .. } => {
                if kappa(point[*v]) == zero::<K>() {
                    return Err(Error::Vanishing);
                }
            }
            Gin::Block(poly) => {
                let at: Vec<K> = core::iter::once(run.tstar)
                    .chain(step.y.iter().map(|j| point[*j]))
                    .collect();
                let mut functionals = run.pending[*poly].clone();
                functionals.push(stele_poly::eq_table(&at).map_err(|_| Error::Statement)?);
                if !full_rank(&functionals)? {
                    return Err(Error::ClaimRank);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// After a non-leaf step: the line challenge `t*` folds each child pair into the
/// next claim, at `r = (x*, t*)` (A3 `FractionFold`).
pub(super) fn advance<K: ChallengeField + CodeField>(
    step: &GkrStep,
    run: &mut Run<K>,
    point: &[K],
    layers: &Finals<K>,
    t: &mut Transcript<K>,
) -> Result<(), Error> {
    if step.leaf {
        return Ok(());
    }
    let tstar = draw(t, ChallengeLabel::FractionFold)?;
    let u: Vec<K> = step.y.iter().map(|j| point[*j]).collect();
    for poly in 0..2 {
        let [a, b] = layers.layers[poly];
        run.claims[poly] = a + tstar * (b - a);
        let k = kappa(point[step.xo + poly]);
        run.incoming[poly] = (k, u.clone());
        run.pending[poly] = (0..2)
            .map(|bit| {
                let at: Vec<K> = core::iter::once(K::from_i64(bit))
                    .chain(u.iter().copied())
                    .collect();
                stele_poly::eq_table(&at)
                    .map(|w| w.into_iter().map(|e| k * e).collect())
                    .map_err(|_| Error::Statement)
            })
            .collect::<Result<_, _>>()?;
    }
    run.r = point[step.xo..].iter().copied().chain([tstar]).collect();
    run.tstar = tstar;
    Ok(())
}

/// The input index of the step's `p(·, 0)` layer child (NC-0913's target).
pub(super) fn first_layer(step: &GkrStep) -> Option<usize> {
    step.inputs
        .iter()
        .position(|i| matches!(i, Gin::Layer { .. }))
}
