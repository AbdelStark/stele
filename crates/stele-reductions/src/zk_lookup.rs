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
//! - **Checks** (E12-14, RFC-0026 A3 and A9): the lookup half concatenates the
//!   check's members largest first, each padded to `c_D + 1` variables. Its leaf is
//!   `(S, α − Σ β^i·S·X_i)` with `S` the public concatenated selector and
//!   `X_i = Σ_m B_m·(V̇_{m,i} + shift_{m,i})`, `B_m` the public indicator of member
//!   `m`'s block. The table half reads `Z·mult` with `Z = [x_high = 0]` when the
//!   table is shorter than the tree. With several members, the instance's inputs
//!   are `B_m` and each member's masked occurrence (so every claim is a final);
//!   the producer folds one combined factor per tuple entry, all members sharing
//!   one vanishing variable and mask coordinates `u` = the last `c_D` variables,
//!   which lie in every member's block.
//! - **Statement message** (A5): before each check's `β`, `LookupStatement`
//!   absorbs its derived dimensions and members, and `LookupUnits` its (empty,
//!   `b = m`) unit list.
//!
//! Challenges: `β, α` (`LookupBeta`, `LookupAlpha`), `r` for the first step
//! (`ZeroWeight`), `λ` per step (`FractionGamma`), the line challenge `t*` after
//! each non-leaf step (`FractionFold`). No new label.
use super::{
    bit, column_point, dim, domain_table, full_rank, kappa, occurrence_claim, zero, Claim, Coord,
    Error, Factor, Lookup, Occurrence, Plan, Statement,
};
use alloc::vec;
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_pcs::CodeField;
use stele_sumcheck::Term;

/// One member as planned: its padded variables, block offset in the lookup half,
/// tuple reads as x-coordinates (MSB-first index into `x`), shifts and selector.
struct MemberPlan {
    m: usize,
    vars: usize,
    offset: usize,
    tuple: Vec<(usize, Vec<usize>)>,
    shifts: Vec<i64>,
    selector: Option<(Vec<i64>, Vec<usize>)>,
}

impl MemberPlan {
    /// A column's index at lookup position `x` through x-coordinates `coords`.
    fn index(coords: &[usize], x: usize, n: usize) -> usize {
        coords
            .iter()
            .fold(0, |index, q| (index << 1) | bit(x, *q, n))
    }
    fn selected(&self, x: usize, n: usize) -> i64 {
        self.selector
            .as_ref()
            .map_or(1, |(values, coords)| values[Self::index(coords, x, n)])
    }
}

/// One lookup's plan.
pub(super) struct LookupPlan {
    n: usize,
    k: usize,
    k0: usize,
    c: usize,
    members: Vec<MemberPlan>,
    multiplicity: usize,
    table: Vec<Vec<i64>>,
    valid: usize,
    first_block: usize,
    /// Leaf inputs: `B_m` and per-member occurrences (several members or padding).
    expand: bool,
    /// Leaf input `S` (a selector, or positions off the members).
    select: bool,
    /// Leaf input `Z` (the table is shorter than the tree).
    pad: bool,
    /// Plan index of the top identity `h·q − p = 0` (NC-0919's adversary forges it).
    pub(super) identity: Option<usize>,
}

impl LookupPlan {
    /// The `(β, α)` round's numerators over `|K|` (E12-26): LU `c·(N + t) − 1`
    /// (RFC-0012 A17 item 3, `formal/fs-composition.md` Lemma 4; the recorded
    /// `h + N + c·t − 1` of A8/A11 holds only for `c = 1`), with `N = 2^n` and `t` the
    /// padded table rows, and RFC-0008 A7's ZD `2^{n+1}·c`.
    pub(super) fn lu(&self) -> (u64, u64) {
        let (n, c) = (1u64 << self.n, self.c as u64);
        (c * (n + self.table.len() as u64) - 1, 2 * n * c)
    }
    /// Masked layers `k0 + 1..=n`, two blocks (`p`, `q`) each.
    pub(super) fn block_count(&self) -> usize {
        2 * (self.n - self.k0)
    }
    fn block(&self, layer: usize, poly: usize) -> usize {
        self.first_block + 2 * (layer - self.k0 - 1) + poly
    }
    /// The concatenated selector `S` over the lookup half: at position `x`, the
    /// selector of the first member containing `x`, else 0.
    fn selector(&self) -> Vec<i64> {
        // Each member fills its own range, last to first, so the first member
        // containing a position wins (E16-24: no scan of every member per position).
        let len = 1usize << self.n;
        let mut out = vec![0; len];
        for m in self.members.iter().rev() {
            let end = (m.offset + (1 << m.m)).min(len);
            for (x, value) in (m.offset..end).zip(out.get_mut(m.offset..end).unwrap_or(&mut [])) {
                *value = m.selected(x, self.n);
            }
        }
        out
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
    /// A masked occurrence of `mult` or a member's tuple column (leaf step).
    Leaf(Occurrence),
    /// `Z = [x_high = 0]`, public (leaf step).
    Pad,
    /// The concatenated selector `S`, public (leaf step).
    Selector,
    /// `B_m`, member `m`'s block indicator, public (leaf step).
    Member(usize),
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
    /// The leaf step reads no tree layer: its inputs are leaf occurrences and tables.
    pub(super) fn is_leaf(&self) -> bool {
        self.leaf
    }
    /// Public draws besides the sumcheck's (E12-26): the first step's `r` (`k`,
    /// `ZeroWeight`), and every step's `λ` and, below the leaf, `t*`.
    pub(super) fn draws(&self) -> (u64, u64) {
        let r = if self.first { self.k as u64 } else { 0 };
        (r, 1 + u64::from(!self.leaf))
    }
    pub(super) fn occurrences_mut(&mut self) -> impl Iterator<Item = &mut Occurrence> {
        self.inputs.iter_mut().filter_map(|i| match i {
            Gin::Top(o) | Gin::Leaf(o) => Some(o),
            _ => None,
        })
    }
    fn position(&self, f: impl Fn(&Gin) -> bool) -> Option<u32> {
        self.inputs.iter().position(f).map(|p| p as u32)
    }
}

fn term<K: ChallengeField>(coefficient: K, factors: &[u32]) -> Term<K> {
    Term {
        coefficient,
        factors: factors.to_vec(),
    }
}

/// Input indices of a leaf: the lead `h` of the `mult` terms (`eq` or `eq·Z`),
/// an optional separate `Z` (compact form only), `mult`, the selector `S` of the
/// `p0·q1` term, per tuple entry the parts `(w?, X?, coefficient)` of `S·X_i`, and
/// the table.
/// One part `(w?, X?, coefficient)` of a tuple entry's `S·X_i`.
type Part<K> = (Option<u32>, Option<u32>, K);

struct LeafIx<K> {
    h: u32,
    z: Option<u32>,
    m: u32,
    s: Option<u32>,
    xs: Vec<Vec<Part<K>>>,
    table: u32,
}

/// `F = p0·q1 + p1·q0 + λ·q0·q1` of a leaf, `p0 = S`, `q0 = α − Σ β^i·S·X_i`,
/// `p1 = −Z·M`, `q1 = T`, at most four factors per term (RFC-0006 instances).
fn leaf_terms<K: ChallengeField>(
    out: &mut Vec<Term<K>>,
    lambda: K,
    alpha: K,
    beta: K,
    ix: &LeafIx<K>,
) {
    let one = K::from_i64(1);
    let flat = |f: &[Option<u32>]| -> Vec<u32> { f.iter().flatten().copied().collect() };
    match ix.s {
        Some(s) => {
            out.push(term(one, &[0, s, ix.table]));
            out.push(term(lambda * alpha, &[0, ix.table]));
        }
        None => out.push(term(one + lambda * alpha, &[0, ix.table])),
    }
    out.push(term(
        zero::<K>() - alpha,
        &flat(&[Some(ix.h), ix.z, Some(ix.m)]),
    ));
    let mut power = one;
    for parts in &ix.xs {
        for (w, x, coefficient) in parts {
            let c = power * *coefficient;
            out.push(term(c, &flat(&[Some(ix.h), ix.z, Some(ix.m), *w, *x])));
            out.push(term(
                zero::<K>() - lambda * c,
                &flat(&[Some(0), *w, *x, Some(ix.table)]),
            ));
        }
        power = power * beta;
    }
}

/// Whether a leaf has a selector, padding or several members: its instance inputs
/// then differ from the producer's compact factors (module docs).
fn complex(step: &GkrStep, lp: &LookupPlan) -> bool {
    step.leaf && (lp.expand || lp.select || lp.pad)
}

/// The step's instance terms at `λ, α, β` (input 0 is the head).
fn terms<K: ChallengeField>(
    step: &GkrStep,
    lp: &LookupPlan,
    lambda: K,
    alpha: K,
    beta: K,
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
        let at = |f: &dyn Fn(&Gin) -> bool| step.position(f);
        let s = at(&|g| matches!(g, Gin::Selector));
        let mut xs = vec![Vec::new(); lp.c];
        let mut cursor = base as usize + 1 + usize::from(lp.pad) + usize::from(lp.select);
        for member in &lp.members {
            let w = if lp.expand {
                cursor += 1;
                Some(cursor as u32 - 1)
            } else {
                s
            };
            for (i, parts) in xs.iter_mut().enumerate() {
                parts.push((w, Some(cursor as u32), one));
                cursor += 1;
                if member.shifts[i] != 0 {
                    parts.push((w, None, K::from_i64(member.shifts[i])));
                }
            }
        }
        let ix = LeafIx {
            h: at(&|g| matches!(g, Gin::Pad)).unwrap_or(0),
            z: None,
            m: base,
            s,
            xs,
            table: at(&|g| matches!(g, Gin::Table)).unwrap_or(0),
        };
        leaf_terms(&mut out, lambda, alpha, beta, &ix);
    } else {
        let (p0, p1, q0, q1) = (base, base + 1, base + 2, base + 3);
        out.push(term(one, &[0, p0, q1]));
        out.push(term(one, &[0, p1, q0]));
        out.push(term(lambda, &[0, q0, q1]));
    }
    out
}

/// NC-0931's adversary: the compact factor index of a padded leaf's `Z` (after the
/// head, the `s = 1` inputs and `mult`).
pub(super) fn pad_factor(step: &GkrStep, lp: &LookupPlan) -> Option<usize> {
    (step.leaf && lp.pad).then_some(if step.first { 4 } else { 6 })
}

/// A complex leaf's compact factors: head, the `s = 1` inputs, `mult`, `Z?`, `S?`,
/// one combined `X_i` per tuple entry (shift included), the table.
fn compact_terms<K: ChallengeField>(
    step: &GkrStep,
    lp: &LookupPlan,
    lambda: K,
    alpha: K,
    beta: K,
) -> Vec<Term<K>> {
    let mut out = terms(step, lp, lambda, alpha, beta);
    out.truncate(2);
    let base = if step.first { 3 } else { 5 };
    let z = lp.pad.then_some(base + 1);
    let s = lp.select.then_some(base + 1 + u32::from(lp.pad));
    let x0 = base + 1 + u32::from(lp.pad) + u32::from(lp.select);
    let ix = LeafIx {
        h: 0,
        z,
        m: base,
        s,
        xs: (0..lp.c as u32)
            .map(|i| vec![(s, Some(x0 + i), K::from_i64(1))])
            .collect(),
        table: x0 + lp.c as u32,
    };
    leaf_terms(&mut out, lambda, alpha, beta, &ix);
    out
}

fn ceil_log2(n: usize) -> usize {
    n.max(1).next_power_of_two().trailing_zeros() as usize
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
    let width = spec.members.first().map_or(0, |m| m.tuple.len());
    let k = ceil_log2(spec.table.len());
    let log_len = |x: usize| statement.columns.get(x).map(|col| col.log_len as usize);
    if width == 0
        || spec.table.len() != 1 << k
        || log_len(spec.multiplicity) != Some(k)
        || spec.table.iter().any(|row| row.len() != width)
        || spec.valid > spec.table.len()
    {
        return Err(Error::Statement);
    }
    // Members largest (padded) first, ties in relation order, each aligned.
    let mut order: Vec<usize> = (0..spec.members.len()).collect();
    let padded = |i: usize| (spec.members[i].vars as usize).max(k0);
    order.sort_by_key(|i| core::cmp::Reverse(padded(*i)));
    let total: usize = order.iter().map(|i| 1usize << padded(*i).min(40)).sum();
    let n = k0.max(k).max(ceil_log2(total));
    if n > 30 {
        return Err(Error::Statement);
    }
    let mut members = Vec::new();
    let mut offset = 0;
    for i in order {
        let spec_m = &spec.members[i];
        let vars = spec_m.vars as usize;
        let at = |read: &[u32]| -> Result<Vec<usize>, Error> {
            super::distinct(read)?;
            read.iter()
                .map(|q| match *q as usize {
                    q if q < vars => Ok(n - vars + q),
                    _ => Err(Error::Statement),
                })
                .collect()
        };
        if spec_m.tuple.len() != width || spec_m.shifts.len() != width {
            return Err(Error::Statement);
        }
        let mut tuple = Vec::new();
        for read in &spec_m.tuple {
            if log_len(read.column) != Some(read.vars.len()) {
                return Err(Error::Statement);
            }
            tuple.push((read.column, at(&read.vars)?));
        }
        let selector = match &spec_m.selector {
            None => None,
            Some(p) => {
                if p.values.len() != 1usize << p.vars.len()
                    || p.values.iter().any(|v| !(0..=1).contains(v))
                {
                    return Err(Error::Statement);
                }
                Some((p.values.clone(), at(&p.vars)?))
            }
        };
        let m = padded(i);
        members.push(MemberPlan {
            m,
            vars,
            offset,
            tuple,
            shifts: spec_m.shifts.clone(),
            selector,
        });
        offset += 1 << m;
    }
    let expand = members.len() != 1 || members[0].m != n;
    let lp = LookupPlan {
        n,
        k,
        k0,
        c: width,
        select: offset < 1 << n || members.iter().any(|m| m.selector.is_some()),
        pad: k < n,
        expand,
        members,
        multiplicity: spec.multiplicity,
        table: spec.table.clone(),
        valid: spec.valid,
        first_block,
        identity: None,
    };
    let occurrence = |column: usize, coords: Vec<Coord>| Occurrence {
        column,
        coords,
        v: 0,
        u: Vec::new(),
        block: 0,
    };
    let mut steps = Vec::new();
    for layer in k0..=n {
        let (first, leaf) = (layer == k0, layer == n);
        let xo = usize::from(!first);
        let y: Vec<usize> = (xo + layer - k0..xo + layer).collect();
        let vars = |count: usize| (0..count).map(|j| Coord::Var(xo + j)).collect::<Vec<_>>();
        let mut inputs = vec![Gin::Head];
        if first {
            inputs.push(Gin::Top(occurrence(top[0], vars(layer))));
            inputs.push(Gin::Top(occurrence(top[1], vars(layer))));
        } else {
            for poly in 0..2 {
                inputs.push(Gin::Select(poly));
                inputs.push(Gin::Block(poly));
            }
        }
        if leaf {
            // `mult` reads the low `k` variables of `x`.
            let low = (n - k..n).map(|j| Coord::Var(xo + j)).collect();
            inputs.push(Gin::Leaf(occurrence(lp.multiplicity, low)));
            if lp.pad {
                inputs.push(Gin::Pad);
            }
            if lp.select {
                inputs.push(Gin::Selector);
            }
            for (index, member) in lp.members.iter().enumerate() {
                if lp.expand {
                    inputs.push(Gin::Member(index));
                }
                for (column, coords) in &member.tuple {
                    let coords = coords.iter().map(|q| Coord::Var(xo + q)).collect();
                    inputs.push(Gin::Leaf(occurrence(*column, coords)));
                }
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
        let num_vars = layer + xo;
        let mut step = GkrStep {
            id: 0,
            lookup,
            k: layer,
            first,
            leaf,
            num_vars: num_vars as u32,
            inputs,
            degree: 0,
            y,
            xo,
        };
        let one = K::from_i64(1);
        let shape = terms(&step, &lp, one, one, one);
        let mut masked: Vec<Option<(usize, Vec<usize>)>> = step
            .inputs
            .iter()
            .map(|i| match i {
                Gin::Layer { v, u, .. } => Some((*v, u.clone())),
                _ => None,
            })
            .collect();
        let compact = complex(&step, &lp);
        let mut compact_masked = Vec::new();
        if compact {
            // The top occurrences of a one-step tree share no term with the leaf.
            let tops: Vec<bool> = step
                .inputs
                .iter()
                .map(|i| matches!(i, Gin::Top(_)))
                .collect();
            super::vanish(num_vars, c, &shape, &mut masked, &tops)?;
            // `mult` takes item 2's default; every member occurrence shares one
            // `v ≠ v_mult` and `u` = the last `c_D` variables (inside every block).
            let mult = step.position(|g| matches!(g, Gin::Leaf(_))).unwrap_or(0) as usize;
            let v_mult = 0;
            let u_mult: Vec<usize> = (1..=c).collect();
            let u: Vec<usize> = (num_vars - c..num_vars).collect();
            let v = (0..num_vars)
                .rev()
                .find(|q| *q != v_mult && !u.contains(q))
                .or_else(|| (0..num_vars).rev().find(|q| *q != v_mult))
                .ok_or(Error::Statement)?;
            for (index, (input, m)) in step.inputs.iter().zip(masked.iter_mut()).enumerate() {
                if let Gin::Leaf(_) = input {
                    *m = Some(if index == mult {
                        (v_mult, u_mult.clone())
                    } else {
                        (v, u.clone())
                    });
                }
            }
            // The compact factors: `mult` at its index, then `Z?`, `S?` and one
            // combined factor per tuple entry, all public but these.
            compact_masked = vec![None; mult + 1 + usize::from(lp.pad) + usize::from(lp.select)];
            compact_masked[mult] = Some((v_mult, u_mult.clone()));
            compact_masked.extend((0..lp.c).map(|_| Some((v, u.clone()))));
            compact_masked.push(None);
        } else {
            let free: Vec<bool> = step
                .inputs
                .iter()
                .map(|i| matches!(i, Gin::Top(_) | Gin::Leaf(_)))
                .collect();
            super::vanish(num_vars, c, &shape, &mut masked, &free)?;
        }
        for (input, m) in step.inputs.iter_mut().zip(&masked) {
            if let (Gin::Top(o) | Gin::Leaf(o), Some((v, u))) = (input, m) {
                o.v = *v;
                o.u = u.clone();
            }
        }
        step.degree = super::degree(num_vars, &shape, &masked);
        if compact {
            let terms = compact_terms(&step, &lp, one, one, one);
            step.degree = step
                .degree
                .max(super::degree(num_vars, &terms, &compact_masked));
        }
        if step.degree > 60 {
            return Err(Error::Statement);
        }
        steps.push(step);
    }
    Ok((lp, steps))
}

/// A5's statement and unit messages for check `l`, before its `β` (RFC-0008 A7
/// item 1): derived dimensions, then each member's padded size and offset.
pub(super) fn messages<K: ChallengeField>(
    lp: &LookupPlan,
    l: usize,
    t: &mut Transcript<K>,
) -> Result<(), Error> {
    let mut out = Vec::new();
    out.extend_from_slice(&(l as u64).to_le_bytes());
    for x in [lp.n, lp.k, lp.c, lp.valid, lp.members.len()] {
        out.extend_from_slice(&(x as u32).to_le_bytes());
    }
    for m in &lp.members {
        out.extend_from_slice(&(m.m as u32).to_le_bytes());
        out.extend_from_slice(&(m.vars as u32).to_le_bytes());
        out.extend_from_slice(&(m.offset as u64).to_le_bytes());
    }
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    t.absorb(AbsorbLabel::LookupStatement, &out).map_err(fail)?;
    // `b = m`: no units (RFC-0026 A3), so the unit list is empty.
    let mut units = (l as u64).to_le_bytes().to_vec();
    units.push(0);
    t.absorb(AbsorbLabel::LookupUnits, &units).map_err(fail)
}

/// `1, β, β², …`, `count` powers: a tuple compresses to `Σ β^i·x_i`.
fn powers<K: ChallengeField>(beta: K, count: usize) -> Vec<K> {
    let mut out = Vec::with_capacity(count);
    let mut power = K::from_i64(1);
    for _ in 0..count {
        out.push(power);
        power = power * beta;
    }
    out
}

/// The public table denominators `α − Σ β^i T_i(x)` over `2^n`, 1 on padding.
/// Entries are independent: filled over the pool, with the powers of β once (E16-24).
fn table<K: ChallengeField>(lp: &LookupPlan, beta: K, alpha: K) -> Vec<K> {
    let width = lp.table.iter().map(Vec::len).max().unwrap_or(0);
    let weights = powers(beta, width);
    let mut out = vec![K::from_i64(1); 1usize << lp.n];
    stele_sumcheck::parallel::for_each_chunk(&mut out, |start, chunk| {
        for (x, value) in (start..).zip(chunk) {
            if let Some(row) = lp.table.get(x).filter(|_| x < lp.valid) {
                *value = alpha
                    - row.iter().zip(&weights).fold(zero::<K>(), |s, (v, w)| {
                        s + w.mul_m31(<M31 as stele_field::Field>::from_i64(*v))
                    });
            }
        }
    });
    out
}

/// The concatenated shifted tuple `X_i` over the lookup half (0 off the members).
fn tuple<K: ChallengeField>(lp: &LookupPlan, data: &[Vec<K>]) -> Vec<Vec<K>> {
    let mut out = vec![vec![zero::<K>(); 1 << lp.n]; lp.c];
    for m in &lp.members {
        for (i, ((column, coords), shift)) in m.tuple.iter().zip(&m.shifts).enumerate() {
            for x in m.offset..m.offset + (1 << m.m) {
                out[i][x] = data[*column][MemberPlan::index(coords, x, lp.n)] + K::from_i64(*shift);
            }
        }
    }
    out
}

/// The prover's tree, `layers[k]` over `k` variables for `k ≤ n + 1` (A5, A7 item 2).
pub(super) fn tree<K: ChallengeField>(
    lp: &LookupPlan,
    data: &[Vec<K>],
    beta: K,
    alpha: K,
) -> Vec<Vec<[K; 2]>> {
    let q = table(lp, beta, alpha);
    let s = lp.selector();
    let xs = tuple(lp, data);
    let mult = &data[lp.multiplicity];
    let weights = powers(beta, xs.len());
    // Leaves and each level's parents are independent: filled over the pool (E16-24).
    let mut leaves = vec![[zero::<K>(); 2]; 2 * q.len()];
    stele_sumcheck::parallel::for_each_chunk(&mut leaves, |start, chunk| {
        for (i, leaf) in (start..).zip(chunk) {
            let x = i / 2;
            *leaf = if i % 2 == 0 {
                let selected = K::from_i64(s[x]);
                let compressed = xs
                    .iter()
                    .zip(&weights)
                    .fold(zero::<K>(), |t, (col, w)| t + *w * col[x]);
                [selected, alpha - selected * compressed]
            } else {
                let count = mult.get(x).copied().unwrap_or_else(zero::<K>);
                [zero::<K>() - count, q[x]]
            };
        }
    });
    let mut layers = vec![leaves];
    while layers[layers.len() - 1].len() > 1 {
        let children = &layers[layers.len() - 1];
        let mut parents = vec![[zero::<K>(); 2]; children.len() / 2];
        stele_sumcheck::parallel::for_each_chunk(&mut parents, |start, chunk| {
            for (j, parent) in (start..).zip(chunk) {
                let ([p0, q0], [p1, q1]) = (children[2 * j], children[2 * j + 1]);
                *parent = [p0 * q1 + p1 * q0, q0 * q1];
            }
        });
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
    lambda: K,
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
            lambda: zero::<K>(),
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
    lp: &LookupPlan,
    run: &mut Run<K>,
    t: &mut Transcript<K>,
) -> Result<(Vec<Term<K>>, K), Error> {
    if step.first {
        run.r = (0..step.k)
            .map(|_| draw(t, ChallengeLabel::ZeroWeight))
            .collect::<Result<_, _>>()?;
    }
    let lambda = draw(t, ChallengeLabel::FractionGamma)?;
    run.lambda = lambda;
    let claimed = if step.first {
        zero::<K>()
    } else {
        run.claims[0] + lambda * run.claims[1]
    };
    Ok((terms(step, lp, lambda, run.alpha, run.beta), claimed))
}

/// The `4D` entries of a layer block in the shared source's data message.
fn block_entries<K: CodeField>(plan: &Plan<K>, shared: &[M31], index: usize) -> Vec<M31> {
    let width = 1usize << plan.shared.1;
    let start = dim::<K>() * plan.stride + 4 * dim::<K>() * index;
    (start..start + 4 * dim::<K>())
        .map(|p| shared[(p / width) * 2 * width + p % width])
        .collect()
}

fn element<K: ChallengeField>(x: M31) -> K {
    K::from_i64(i64::from(x.as_u32()))
}

/// How an expanded leaf input's final is produced from the compact fold.
enum Expanded<K> {
    /// A compact factor's final.
    Compact(usize),
    /// A product of compact finals and, when `bits` is not empty, `B_m`: `eq` of
    /// the block bits on the leading x-coordinates. `ghost` adds `δ·B_g` (NC-0930's
    /// adversary only).
    Product {
        factors: Vec<usize>,
        bits: Vec<u8>,
        ghost: Option<(Vec<u8>, K)>,
        xo: usize,
    },
    /// A member occurrence's masked value, from its column and block.
    Claim {
        column: Vec<K>,
        coords: Vec<Coord>,
        block: Vec<M31>,
        v: usize,
        u: Vec<usize>,
    },
}

/// The expanded finals of a leaf with several members (module docs).
pub(super) struct Expand<K> {
    map: Vec<Expanded<K>>,
    point: Vec<K>,
}

impl<K: ChallengeField> Expand<K> {
    pub(super) fn inputs(&self) -> usize {
        self.map.len()
    }
    pub(super) fn record(&mut self, challenge: K) {
        self.point.push(challenge);
    }
    pub(super) fn finals(&self, compact: &[K]) -> Result<Vec<K>, Error> {
        self.map
            .iter()
            .map(|e| match e {
                Expanded::Compact(i) => Ok(compact[*i]),
                Expanded::Product {
                    factors,
                    bits,
                    ghost,
                    xo,
                } => {
                    let x = &self.point[*xo..];
                    let b = ghost.as_ref().map_or(weight(bits, x), |(g, d)| {
                        weight(bits, x) + *d * weight(g, x)
                    });
                    Ok(factors.iter().fold(b, |p, i| p * compact[*i]))
                }
                Expanded::Claim {
                    column,
                    coords,
                    block,
                    v,
                    u,
                } => {
                    let x =
                        stele_sumcheck::parallel::eq_table(&column_point(coords, &self.point, &[]))
                            .map_err(|_| Error::Statement)?;
                    let at: Vec<K> = u.iter().map(|q| self.point[*q]).collect();
                    let r =
                        stele_sumcheck::parallel::eq_table(&at).map_err(|_| Error::Statement)?;
                    let data = column
                        .iter()
                        .zip(&x)
                        .fold(zero::<K>(), |s, (a, b)| s + *a * *b);
                    let mask = block
                        .iter()
                        .zip(&r)
                        .fold(zero::<K>(), |s, (a, b)| s + element::<K>(*a) * *b);
                    Ok(data + kappa(self.point[*v]) * mask)
                }
            })
            .collect()
    }
}

/// `Π_j eq(x_j, bit_j)` over the leading coordinates of `x`.
fn weight<K: ChallengeField>(bits: &[u8], x: &[K]) -> K {
    let one = K::from_i64(1);
    bits.iter()
        .zip(x)
        .fold(one, |w, (b, z)| w * if *b == 1 { *z } else { one - *z })
}

/// Member `m`'s block bits: its index on the leading `n − m` x-coordinates.
fn block_bits(lp: &LookupPlan, member: &MemberPlan) -> Vec<u8> {
    let high = lp.n - member.m;
    let index = member.offset >> member.m;
    (0..high)
        .map(|j| ((index >> (high - 1 - j)) & 1) as u8)
        .collect()
}

/// NC-0930's substitution (controls only): member `member`'s weight becomes
/// `(B_m + δ·B_g)·S`, with `B_g` the indicator of the aligned `2^{m'}` block at
/// `offset`. The block must lie off every member (`S = 0` there), so the leaf's sum
/// over the cube is unchanged.
#[derive(Clone, Copy)]
pub(super) struct Ghost {
    pub(super) member: usize,
    pub(super) offset: usize,
    pub(super) delta: i64,
}

/// The prover's input tables over the step's domain (MSB-first, `s` first), and
/// for a several-member leaf its compact terms and expansion. `ghost` is NC-0930's
/// adversary; honest provers pass `None`.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) fn factors<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    step: &GkrStep,
    run: &Run<K>,
    layers: &[Vec<[K; 2]>],
    data: &[Vec<K>],
    shared: &[M31],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
    ghost: Option<Ghost>,
) -> Result<(Vec<Factor<K>>, Option<Vec<Term<K>>>, Option<Expand<K>>), Error> {
    let lp = &plan.lookups[step.lookup];
    let ghost = match ghost {
        Some(g) if step.leaf && lp.expand => Some((g, ghost_bits(lp, g)?)),
        Some(_) => return Err(Error::Statement),
        None => None,
    };
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
    let compact = complex(step, lp);
    let mut out = Vec::new();
    let mut map = Vec::new();
    let mut members = Vec::new();
    let mut seen_mult = false;
    let mut s_index = None;
    for input in &step.inputs {
        let factor = match input {
            Gin::Head => {
                let eq =
                    stele_sumcheck::parallel::eq_table(&run.r).map_err(|_| Error::Statement)?;
                if step.first {
                    public(eq)
                } else {
                    public(eq.into_iter().chain(vec![zero::<K>(); half]).collect())
                }
            }
            Gin::Select(poly) => {
                let (k, u) = &run.incoming[*poly];
                let eq = stele_sumcheck::parallel::eq_table(u).map_err(|_| Error::Statement)?;
                let mut x = vec![zero::<K>(); 2 * half];
                for (y, w) in eq.into_iter().enumerate() {
                    x[half + y] = *k * w;
                }
                public(x)
            }
            Gin::Block(poly) => {
                let block = block_entries(plan, shared, lp.block(step.k, *poly));
                let two = block.len() / 2;
                // `(1 − t*)·a + t*·b` depends on `xi` only through `xi & (two − 1)`:
                // `two` values, tiled (E16-24).
                let period: Vec<K> = (0..two)
                    .map(|y| {
                        let (a, b) = (element::<K>(block[y]), element::<K>(block[two + y]));
                        a + run.tstar * (b - a)
                    })
                    .collect();
                let x = (0..half).map(|xi| period[xi & (two - 1)]).collect();
                public(both(x))
            }
            Gin::Leaf(o) if compact && seen_mult => {
                map.push(Expanded::Claim {
                    column: data[o.column].clone(),
                    coords: o.coords.clone(),
                    block: block_of(o),
                    v: o.v,
                    u: o.u.clone(),
                });
                members.push(o);
                continue;
            }
            Gin::Member(m) => {
                map.push(Expanded::Product {
                    factors: s_index.into_iter().collect(),
                    bits: block_bits(lp, &lp.members[*m]),
                    ghost: ghost
                        .as_ref()
                        .filter(|(g, _)| g.member == *m)
                        .map(|(g, bits)| (bits.clone(), K::from_i64(g.delta))),
                    xo: step.xo,
                });
                continue;
            }
            Gin::Top(o) | Gin::Leaf(o) => {
                seen_mult |= matches!(input, Gin::Leaf(_));
                Factor {
                    x: domain_table(&data[o.column], &o.coords, &[], n),
                    r: super::block_table(&block_of(o), &o.u, n),
                    v: Some(o.v),
                }
            }
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
            Gin::Pad => {
                // The instance input is `eq·Z`; the producer folds `Z` alone.
                map.push(Expanded::Product {
                    factors: vec![0, out.len()],
                    bits: Vec::new(),
                    ghost: None,
                    xo: step.xo,
                });
                out.push(public(both(
                    (0..half)
                        .map(|x| K::from_i64(i64::from(x >> lp.k == 0)))
                        .collect(),
                )));
                continue;
            }
            Gin::Selector => {
                s_index = Some(out.len());
                public(both(lp.selector().into_iter().map(K::from_i64).collect()))
            }
            Gin::Table => {
                if compact {
                    out.extend(combined(
                        step,
                        lp,
                        data,
                        &members,
                        block_of,
                        ghost.as_ref().map(|g| g.0),
                    )?);
                }
                public(both(table(lp, run.beta, run.alpha)))
            }
        };
        map.push(Expanded::Compact(out.len()));
        out.push(factor);
    }
    if !compact {
        return Ok((out, None, None));
    }
    let terms = compact_terms(step, lp, run.lambda, run.alpha, run.beta);
    Ok((
        out,
        Some(terms),
        Some(Expand {
            map,
            point: Vec::new(),
        }),
    ))
}

/// NC-0930's ghost block bits on the leading `n − m'` x-coordinates. The block is
/// aligned, inside the lookup half and off every member, so `S = 0` on it.
fn ghost_bits(lp: &LookupPlan, g: Ghost) -> Result<Vec<u8>, Error> {
    let member = lp.members.get(g.member).ok_or(Error::Statement)?;
    let size = 1usize << member.m;
    let off = |x: usize| {
        lp.members
            .iter()
            .all(|m| x < m.offset || x >= m.offset + (1 << m.m))
    };
    if !g.offset.is_multiple_of(size)
        || g.offset + size > 1usize << lp.n
        || !(g.offset..g.offset + size).all(off)
    {
        return Err(Error::Statement);
    }
    let ghost = MemberPlan {
        offset: g.offset,
        tuple: Vec::new(),
        shifts: Vec::new(),
        selector: None,
        ..*member
    };
    Ok(block_bits(lp, &ghost))
}

/// The combined factors `X_i = Σ_m B_m·(x̂_m + shift)` with masks `Σ_m B_m·r̂_m`
/// over the step's domain; `members` are the member occurrences in input order
/// (member-major), all with one `v` and `u` = the last `c_D` variables. `ghost`
/// adds `δ·B_g·(x̂_m + shift)` and `δ·B_g·r̂_m` (NC-0930's adversary only).
fn combined<K: ChallengeField + CodeField>(
    step: &GkrStep,
    lp: &LookupPlan,
    data: &[Vec<K>],
    members: &[&Occurrence],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
    ghost: Option<Ghost>,
) -> Result<Vec<Factor<K>>, Error> {
    let n = step.num_vars as usize;
    let v = members.first().map(|o| o.v).ok_or(Error::Statement)?;
    if members.len() != lp.members.len() * lp.c {
        return Err(Error::Statement);
    }
    let mask = (1usize << lp.n) - 1;
    // The first member containing each position: member ranges filled last to first
    // (E16-24: no scan of every member per position).
    let mut owner: Vec<Option<usize>> = vec![None; 1usize << lp.n];
    for (index, m) in lp.members.iter().enumerate().rev() {
        let end = (m.offset + (1 << m.m)).min(owner.len());
        for slot in owner.get_mut(m.offset..end).unwrap_or(&mut []) {
            *slot = Some(index);
        }
    }
    // NC-0930's ghost block (off every member): `(member, range, δ)`.
    let ghost = ghost.map(|g| {
        let size = 1usize << lp.members[g.member].m;
        (g.member, g.offset..g.offset + size, K::from_i64(g.delta))
    });
    let mut out = Vec::new();
    for (i, mut x) in tuple(lp, data).into_iter().enumerate() {
        let blocks: Vec<Vec<M31>> = (0..lp.members.len())
            .map(|m| block_of(members[m * lp.c + i]))
            .collect();
        let entries = dim::<K>();
        if let Some((m, range, delta)) = &ghost {
            let member = &lp.members[*m];
            let (column, coords) = &member.tuple[i];
            for at in range.clone() {
                let value = data[*column][MemberPlan::index(coords, at, lp.n)];
                x[at] = *delta * (value + K::from_i64(member.shifts[i]));
            }
        }
        let r = (0..1usize << n)
            .map(|index| {
                let position = index & mask;
                match &ghost {
                    Some((m, range, delta)) if range.contains(&position) => {
                        *delta * element::<K>(blocks[*m][position & (entries - 1)])
                    }
                    _ => owner[position].map_or(zero::<K>(), |m| {
                        element::<K>(blocks[m][position & (entries - 1)])
                    }),
                }
            })
            .collect();
        let table = if step.first {
            x
        } else {
            x.iter().chain(&x).copied().collect()
        };
        out.push(Factor {
            x: table,
            r,
            v: Some(v),
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
    let mle = |values: Vec<K>| -> Result<K, Error> {
        let w = stele_poly::eq_table(x).map_err(|_| Error::Statement)?;
        Ok(values
            .iter()
            .zip(&w)
            .fold(zero::<K>(), |s, (a, b)| s + *a * *b))
    };
    let mut out = Finals {
        claims: Vec::new(),
        blocks: Vec::new(),
        layers: [[zero::<K>(); 2]; 2],
    };
    // `S(x*)`, evaluated once when the leaf has a selector.
    let selector = match step.leaf && lp.select {
        true => mle(lp.selector().into_iter().map(K::from_i64).collect()),
        false => Ok(zero::<K>()),
    };
    if finals.len() != step.inputs.len() {
        return Err(Error::Sumcheck(stele_sumcheck::Error::ProofShape));
    }
    for (input, value) in step.inputs.iter().zip(finals) {
        let expected = match input {
            Gin::Head => eq(&run.r, x)? * if step.first { one } else { one - point[0] },
            Gin::Select(poly) => {
                let (k, u) = &run.incoming[*poly];
                let rest = point[step.xo..step.y[0]]
                    .iter()
                    .fold(one, |p, z| p * (one - *z));
                point[0] * *k * eq(u, &y)? * rest
            }
            Gin::Block(poly) => {
                let start = dim::<K>() * plan.stride + 4 * dim::<K>() * lp.block(step.k, *poly);
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
                continue;
            }
            Gin::Top(o) | Gin::Leaf(o) => {
                out.claims
                    .push(occurrence_claim(plan, o, point, &[], *value)?);
                continue;
            }
            Gin::Layer { poly, t, .. } => {
                out.layers[*poly][*t] = *value;
                continue;
            }
            Gin::Pad => {
                let head = eq(&run.r, x)? * if step.first { one } else { one - point[0] };
                head * x[..lp.n - lp.k].iter().fold(one, |p, z| p * (one - *z))
            }
            Gin::Selector => selector?,
            Gin::Member(m) => {
                let s = if lp.select { selector? } else { one };
                weight(&block_bits(lp, &lp.members[*m]), x) * s
            }
            Gin::Table => mle(table(lp, run.beta, run.alpha))?,
        };
        if *value != expected {
            return Err(mismatch);
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

/// Every masked occurrence of a step with its input index (privacy tests).
#[cfg(feature = "controls")]
pub(super) fn occurrences(step: &GkrStep) -> impl Iterator<Item = (usize, &Occurrence)> {
    step.inputs.iter().enumerate().filter_map(|(i, g)| match g {
        Gin::Top(o) | Gin::Leaf(o) => Some((i, o)),
        _ => None,
    })
}

/// Each masked layer child's input index and its bare value `Ṽ_P(x*, t)` from the
/// prover's tree (privacy tests).
#[cfg(feature = "controls")]
pub(super) fn layer_values<K: ChallengeField>(
    step: &GkrStep,
    layers: &[Vec<[K; 2]>],
    point: &[K],
) -> Result<Vec<(usize, K)>, Error> {
    let w = stele_poly::eq_table(&point[step.xo..]).map_err(|_| Error::Statement)?;
    let values = &layers[step.k + 1];
    Ok(step
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, g)| match g {
            Gin::Layer { poly, t, .. } => Some((
                i,
                w.iter().enumerate().fold(zero::<K>(), |s, (x, e)| {
                    s + *e * values[(x << 1) | t][*poly]
                }),
            )),
            _ => None,
        })
        .collect())
}

/// The input index of the step's `p(·, 0)` layer child (NC-0913's target).
pub(super) fn first_layer(step: &GkrStep) -> Option<usize> {
    step.inputs
        .iter()
        .position(|i| matches!(i, Gin::Layer { .. }))
}
