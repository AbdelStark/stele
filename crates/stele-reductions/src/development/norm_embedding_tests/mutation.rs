//! Constraint mutation survey (RFC-0026 §5.2). For each identity, Compose, range,
//! lookup and matmul `C`, an attacker assignment that violates `C` and nothing else:
//! the full relation rejects it and the relation without `C` accepts it. Each one
//! starts from honest values (or from attacker-chosen inputs `X`, which are free
//! columns of the module), changes a few cells, and solves the other witnesses as an
//! attacker would: matmul outputs and limbs, `M`/`J` from the selected constants, chain
//! carries and free bytes, and the output `Y` itself. Nothing is recomputed from the
//! honest formulas. Each attack is classed `output` when it changes `Y` (or `R0`), else
//! `aux`. The survey must equal the golden table, so deleting any constraint from the
//! module fails the test.

use super::*;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use core::cell::Cell;
use stele_ir::relation::{check_except, eval_column, Def, Ref, Term};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Constraint {
    Range(usize),
    Lookup(usize),
    Compose(usize),
    Identity(usize),
    Matmul(usize),
}

pub(super) fn constraints(r: &Relation) -> Vec<(Constraint, String)> {
    let mut out = Vec::new();
    for (i, c) in r.ranges.iter().enumerate() {
        out.push((Constraint::Range(i), format!("range {}", c.name)));
    }
    for (i, c) in r.lookups.iter().enumerate() {
        out.push((Constraint::Lookup(i), format!("lookup {}", c.name)));
    }
    for (i, c) in r.composes.iter().enumerate() {
        out.push((Constraint::Compose(i), format!("compose {}", c.name)));
    }
    for (i, c) in r.identities.iter().enumerate() {
        out.push((Constraint::Identity(i), format!("identity {}", c.name)));
    }
    for (i, c) in r.matmuls.iter().enumerate() {
        out.push((Constraint::Matmul(i), format!("matmul {}", c.name)));
    }
    // `check_except` addresses constraints by name, so names must be unique.
    let names: BTreeSet<&str> = out
        .iter()
        .map(|(_, n)| n.split_once(' ').map_or("", |n| n.1))
        .collect();
    assert_eq!(names.len(), out.len(), "constraint names are unique");
    out
}

/// The plain checker's integer semantics, reporting every violated constraint (up to
/// `cap`), with the lookup tables indexed once.
pub(super) struct Eval<'a> {
    r: &'a Relation,
    tables: Vec<BTreeSet<Vec<i64>>>,
}

impl<'a> Eval<'a> {
    pub(super) fn new(r: &'a Relation) -> Self {
        let tables = r
            .tables
            .iter()
            .map(|t| t.rows.iter().cloned().collect())
            .collect();
        Self { r, tables }
    }

    pub(super) fn violations(&self, v: &Values, cap: usize) -> Vec<Constraint> {
        let r = self.r;
        let evals: Vec<Option<Vec<i64>>> = (0..r.columns.len())
            .map(|i| eval_column(r, v, ColumnId(i as u32)).ok())
            .collect();
        let col = |c: ColumnId| evals[c.0 as usize].as_deref();
        let read = |f: &Ref, x: u64| col(f.column).map(|s| i128::from(s[f.index(x)]));
        let mut out = Vec::new();
        for (i, g) in r.ranges.iter().enumerate() {
            if col(g.column).is_none_or(|s| s.iter().any(|&x| !g.width.contains(x))) {
                out.push(Constraint::Range(i));
            }
        }
        for (i, l) in r.lookups.iter().enumerate() {
            let bad = (0..1u64 << l.vars).any(|x| {
                let active = l.selector.as_ref().is_none_or(|s| read(s, x) != Some(0));
                if !active {
                    return false;
                }
                let tuple: Option<Vec<i64>> = l
                    .tuple
                    .iter()
                    .map(|f| read(f, x).map(|n| n as i64))
                    .collect();
                tuple.is_none_or(|t| !self.tables[l.table.0 as usize].contains(&t))
            });
            if bad {
                out.push(Constraint::Lookup(i));
            }
        }
        for (i, c) in r.composes.iter().enumerate() {
            let bad = match col(c.column) {
                None => true,
                Some(column) => (0..column.len()).any(|x| {
                    let sum: Option<i128> = c.limbs.iter().try_fold(0i128, |acc, &(l, s)| {
                        Some(acc + (i128::from(col(l)?[x]) << s))
                    });
                    sum != Some(i128::from(column[x]))
                }),
            };
            if bad {
                out.push(Constraint::Compose(i));
            }
        }
        if out.len() > cap {
            return out;
        }
        for (i, d) in r.identities.iter().enumerate() {
            let bad = (0..1u64 << d.vars).any(|x| {
                let sum: Option<i128> = d.terms.iter().try_fold(0i128, |acc, t| {
                    let prod = t
                        .factors
                        .iter()
                        .try_fold(i128::from(t.coeff), |p, f| p.checked_mul(read(f, x)?))?;
                    acc.checked_add(prod)
                });
                sum != Some(0)
            });
            if bad {
                out.push(Constraint::Identity(i));
                if out.len() > cap {
                    return out;
                }
            }
        }
        for (i, m) in r.matmuls.iter().enumerate() {
            let bad = (0..1u64 << m.free).any(|x| {
                let s: Option<i128> = (0..1u64 << m.summed).try_fold(0i128, |acc, y| {
                    let prod = read(&m.lhs, x | (y << m.free))?
                        .checked_mul(read(&m.rhs, x | (y << m.free))?)?;
                    acc.checked_add(prod)
                });
                s != read(&m.out, x)
            });
            if bad {
                out.push(Constraint::Matmul(i));
            }
        }
        out
    }
}

pub(super) fn referenced_witness(r: &Relation, c: Constraint) -> Vec<ColumnId> {
    let v: Vec<ColumnId> = match c {
        Constraint::Identity(i) => r.identities[i]
            .terms
            .iter()
            .flat_map(|t| t.factors.iter().map(|f| f.column))
            .collect(),
        Constraint::Compose(i) => {
            let c = &r.composes[i];
            c.limbs.iter().map(|l| l.0).chain([c.column]).collect()
        }
        Constraint::Range(i) => vec![r.ranges[i].column],
        Constraint::Lookup(i) => r.lookups[i].tuple.iter().map(|f| f.column).collect(),
        Constraint::Matmul(i) => {
            let m = &r.matmuls[i];
            vec![m.out.column, m.lhs.column, m.rhs.column]
        }
    };
    // Transitively expand virtual columns to their committed witness operands so mutation
    // searches cover ranges and lookups over virtual columns (RFC-0028 §1.2).
    let mut stack = v;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    while let Some(col) = stack.pop() {
        if !seen.insert(col) {
            continue;
        }
        match &r.columns[col.0 as usize].kind {
            Kind::Witness(_) => out.push(col),
            Kind::Virtual(def) => stack.extend(def.operands()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(super) fn column(r: &Relation, name: &str) -> Option<ColumnId> {
    r.columns
        .iter()
        .position(|c| c.name == name)
        .map(|i| ColumnId(i as u32))
}

fn read(r: &Relation, v: &Values, f: &Ref, x: u64) -> i128 {
    i128::from(eval_column(r, v, f.column).expect("assigned")[f.index(x)])
}

pub(super) fn get(r: &Relation, v: &Values, c: ColumnId, i: usize) -> i128 {
    i128::from(eval_column(r, v, c).expect("assigned")[i])
}

pub(super) fn set(r: &Relation, v: &mut Values, c: ColumnId, i: usize, value: i128) {
    if matches!(r.columns[c.0 as usize].kind, Kind::Virtual(_)) {
        return;
    }
    let mut col = v.get(r, c).expect("assigned").to_vec();
    col[i] = value as i64;
    v.set(r, c, col).expect("length");
}

/// Re-derive the byte limbs of Compose `k` from its column (top limb keeps the rest).
pub(super) fn derive_limbs(r: &Relation, v: &mut Values, k: usize) {
    let c = r.composes[k].clone();
    let column = eval_column(r, v, c.column).expect("column");
    let n = c.limbs.len();
    let split: Vec<Vec<i64>> = column
        .iter()
        .map(|&x| crate::development::limbs::bytes(i128::from(x), n))
        .collect();
    for (i, (l, _)) in c.limbs.iter().enumerate() {
        v.set(r, *l, split.iter().map(|b| b[i]).collect())
            .expect("limb");
    }
}

/// Recompute every witness matmul output except `skip`, and the limbs of its Compose
/// (including `Compose` limbs of virtual `Def::Contraction` columns, RFC-0028 §1.2).
pub(super) fn recompute_matmuls(r: &Relation, v: &mut Values, skip: Constraint) {
    for (j, m) in r.matmuls.iter().enumerate() {
        if skip == Constraint::Matmul(j)
            || matches!(r.columns[m.out.column.0 as usize].kind, Kind::Public(_))
        {
            continue;
        }
        let mut out = v.get(r, m.out.column).expect("out").to_vec();
        for x in 0..1u64 << m.free {
            let s: i128 = (0..1u64 << m.summed)
                .map(|y| {
                    read(r, v, &m.lhs, x | (y << m.free)) * read(r, v, &m.rhs, x | (y << m.free))
                })
                .sum();
            out[m.out.index(x)] = s as i64;
        }
        v.set(r, m.out.column, out).expect("out");
        for (k, c) in r.composes.iter().enumerate() {
            if c.column == m.out.column && skip != Constraint::Compose(k) {
                derive_limbs(r, v, k);
            }
        }
    }
    for (k, c) in r.composes.iter().enumerate() {
        if skip != Constraint::Compose(k)
            && matches!(
                r.columns[c.column.0 as usize].kind,
                Kind::Virtual(Def::Contraction { .. })
            )
        {
            derive_limbs(r, v, k);
        }
    }
}

/// One radix-256 chain: identities `{name}/{i}`, free bytes `{free}{i}` and an optional
/// free wide column (the norm output). Carries are found structurally: the columns
/// with coefficient `−2^radix` (or `−2^(radix+16)`) at a position.
#[derive(Clone, Copy)]
pub(super) struct ChainSpec<'a> {
    pub(super) name: &'a str,
    pub(super) free: &'a str,
    pub(super) wide: Option<&'a str>,
    pub(super) radix: u32,
}

pub(super) struct Solver<'a> {
    pub(super) r: &'a Relation,
    pub(super) scope: &'a str,
    pub(super) specs: &'a [ChainSpec<'a>],
    /// The tampered columns: the solver never overwrites them.
    pub(super) keep: Cell<Option<ColumnId>>,
    /// Target `(virtual_col, index, value)` override for a kept virtual chain limb.
    pub(super) keep_val: Cell<Option<(ColumnId, usize, i128)>>,
}

enum ChainPos {
    Identity(usize, u8, Vec<Term>),
    Virtual(ColumnId, u8, Vec<Term>),
}

impl ChainPos {
    fn vars(&self) -> u8 {
        match *self {
            Self::Identity(_, v, _) | Self::Virtual(_, v, _) => v,
        }
    }

    fn terms(&self) -> &[Term] {
        match self {
            Self::Identity(_, _, t) | Self::Virtual(_, _, t) => t,
        }
    }

    fn identity_id(&self) -> Option<usize> {
        match *self {
            Self::Identity(id, _, _) => Some(id),
            Self::Virtual(_, _, _) => None,
        }
    }

    fn virtual_col(&self) -> Option<ColumnId> {
        match *self {
            Self::Virtual(col, _, _) => Some(col),
            Self::Identity(_, _, _) => None,
        }
    }
}

impl Solver<'_> {
    fn positions(&self, spec: ChainSpec) -> Vec<ChainPos> {
        let s = self.scope;
        let mut out = Vec::new();
        for i in 0.. {
            if let Some(id) = self
                .r
                .identities
                .iter()
                .position(|d| d.name == format!("{s}/{}/{i}", spec.name))
            {
                let d = &self.r.identities[id];
                out.push(ChainPos::Identity(id, d.vars, d.terms.clone()));
                continue;
            }
            let target_name = format!("{s}/{}{i}", spec.free);
            if let Some(col_idx) = self.r.columns.iter().position(|c| c.name == target_name) {
                match &self.r.columns[col_idx].kind {
                    Kind::Virtual(Def::Pointwise { terms }) => {
                        out.push(ChainPos::Virtual(
                            ColumnId(col_idx as u32),
                            self.r.columns[col_idx].log_len,
                            terms.clone(),
                        ));
                        continue;
                    }
                    Kind::Virtual(Def::Linear { constant, terms }) => {
                        let mut ts: Vec<Term> = terms
                            .iter()
                            .map(|(c, f)| Term {
                                coeff: *c,
                                factors: vec![f.clone()],
                            })
                            .collect();
                        if *constant != 0 {
                            ts.push(Term {
                                coeff: *constant,
                                factors: Vec::new(),
                            });
                        }
                        out.push(ChainPos::Virtual(
                            ColumnId(col_idx as u32),
                            self.r.columns[col_idx].log_len,
                            ts,
                        ));
                        continue;
                    }
                    _ => {}
                }
            }
            break;
        }
        out
    }

    /// Carry-out columns of a position: (column, weight) with `carry = Σ weight·column`.
    fn carries(&self, pos: &ChainPos, radix: u32) -> Vec<(ColumnId, i128)> {
        let base = 1i64 << radix;
        let split = base << 16;
        pos.terms()
            .iter()
            .filter(|t| t.factors.len() == 1 && (t.coeff == -base || t.coeff == -split))
            .map(|t| (t.factors[0].column, i128::from(t.coeff / -base)))
            .collect()
    }

    fn put(&self, v: &mut Values, out: &[(ColumnId, i128)], carries: &[i128]) -> Option<()> {
        match out {
            [] if carries.iter().any(|&c| c != 0) => None,
            [] => Some(()),
            [(c, _)] => v
                .set(self.r, *c, carries.iter().map(|&c| c as i64).collect())
                .ok(),
            [(l, _), (h, _)] => {
                v.set(
                    self.r,
                    *l,
                    carries
                        .iter()
                        .map(|c| c.rem_euclid(1 << 16) as i64)
                        .collect(),
                )
                .ok()?;
                v.set(
                    self.r,
                    *h,
                    carries
                        .iter()
                        .map(|c| c.div_euclid(1 << 16) as i64)
                        .collect(),
                )
                .ok()
            }
            _ => None,
        }
    }

    fn sum(&self, v: &Values, pos: &ChainPos, x: u64, skip: &[ColumnId]) -> i128 {
        pos.terms()
            .iter()
            .filter(|t| t.factors.iter().all(|f| !skip.contains(&f.column)))
            .map(|t| {
                t.factors
                    .iter()
                    .fold(i128::from(t.coeff), |p, f| p * read(self.r, v, f, x))
            })
            .sum()
    }

    /// Recompute `P_q0` and `P2` from `(X0, X1, H0, H1)` unless kept.
    fn solve_product(&self, v: &mut Values) -> Option<()> {
        let (r, s) = (self.r, self.scope);
        let (Some(qp0), Some(p2)) = (
            column(r, &format!("{s}/P_q0")),
            column(r, &format!("{s}/P2")),
        ) else {
            return Some(());
        };
        let x0 = column(r, &format!("{s}/X0"))?;
        let x1 = column(r, &format!("{s}/X1"))?;
        let h0 = column(r, &format!("{s}/H0"))?;
        let h1 = column(r, &format!("{s}/H1"))?;
        let keep = self.keep.get();
        let len = 1usize << r.columns[qp0.0 as usize].log_len;
        let d_len = 1usize << r.columns[h0.0 as usize].log_len;
        let mut qv = v.get(r, qp0)?.to_vec();
        let mut p2v = v.get(r, p2)?.to_vec();
        for i in 0..len {
            let k = i & (d_len - 1);
            let xv0 = get(r, v, x0, i);
            let xv1 = get(r, v, x1, i);
            let hv0 = get(r, v, h0, k);
            let hv1 = get(r, v, h1, k);
            if keep != Some(qp0) {
                qv[i] = (xv0 * hv0 + 256 * (xv0 * hv1 + xv1 * hv0)).div_euclid(4096) as i64;
            }
            if keep != Some(p2) {
                p2v[i] = (i128::from(qv[i]) + 16 * xv1 * hv1).div_euclid(4096) as i64;
            }
        }
        if keep != Some(qp0) {
            v.set(r, qp0, qv).ok()?;
        }
        if keep != Some(p2) {
            v.set(r, p2, p2v).ok()?;
        }
        Some(())
    }

    pub(super) fn solve(&self, v: &mut Values, cut: Constraint) -> Option<()> {
        self.solve_product(v)?;
        for spec in self.specs {
            self.chain(v, *spec, cut)?;
        }
        Some(())
    }

    /// Solve one chain bottom-up (free bytes and carries); when it holds the removed
    /// identity `cut`, solve the positions above it top-down instead.
    pub(super) fn chain(&self, v: &mut Values, spec: ChainSpec, cut: Constraint) -> Option<()> {
        let (r, s) = (self.r, self.scope);
        let base = 1i128 << spec.radix;
        let positions = self.positions(spec);
        if positions.is_empty() {
            return Some(());
        }
        let last = positions.len() - 1;
        let split = positions.iter().position(|p| {
            p.identity_id()
                .is_some_and(|id| cut == Constraint::Identity(id))
        });
        let keep = self.keep.get();
        let keep_val = self.keep_val.get();
        let wide = spec
            .wide
            .and_then(|w| column(r, &format!("{s}/{w}")))
            .filter(|&w| Some(w) != keep);
        let size = 1u64 << positions[0].vars();
        let mentions = |pos: &ChainPos, c: ColumnId| {
            pos.terms()
                .iter()
                .any(|t| t.factors.iter().any(|f| f.column == c))
        };
        let outs: Vec<Vec<(ColumnId, i128)>> = positions
            .iter()
            .map(|p| self.carries(p, spec.radix))
            .collect();
        let cols = |k: usize| outs[k].iter().map(|c| c.0).collect::<Vec<_>>();
        let byte_at = |i: usize| {
            if let Some(vc) = positions[i].virtual_col() {
                return (Some(vc) != keep || keep_val.is_some_and(|(c, _, _)| c == vc))
                    .then_some(vc);
            }
            column(r, &format!("{s}/{}{i}", spec.free))
                .filter(|&c| mentions(&positions[i], c) && Some(c) != keep)
        };
        let top_free = if split.is_none() && wide.is_none() {
            (0..=last).rev().find(|&i| byte_at(i).is_some())
        } else {
            None
        };
        for i in 0..split.or(top_free).unwrap_or(last + 1) {
            let byte = byte_at(i);
            let is_virtual = positions[i].virtual_col().is_some();
            if let Some(w) = wide.filter(|&w| mentions(&positions[i], w)) {
                let mut y = Vec::new();
                for x in 0..size {
                    let mut total = 0i128;
                    for j in (i..=last).rev() {
                        let mut skip = cols(j);
                        skip.push(w);
                        if j > i {
                            skip.extend(cols(j - 1));
                        }
                        total = total * base + self.sum(v, &positions[j], x, &skip);
                    }
                    y.push((-total) as i64);
                }
                v.set(r, w, y).ok()?;
            }
            let mut skip = cols(i);
            skip.extend(byte);
            let (mut carries, mut bytes) = (Vec::new(), Vec::new());
            for x in 0..size {
                let mut sum = self.sum(v, &positions[i], x, &skip);
                if let Some(b_col) = byte {
                    let b = if let Some((kc, kidx, kval)) = keep_val {
                        if kc == b_col && kidx == x as usize {
                            kval
                        } else if i == last {
                            sum
                        } else {
                            sum.rem_euclid(base)
                        }
                    } else if i == last {
                        sum
                    } else {
                        sum.rem_euclid(base)
                    };
                    bytes.push(b as i64);
                    sum -= b;
                }
                if (i == last && sum != 0) || sum % base != 0 {
                    return None;
                }
                carries.push(sum / base);
            }
            if let Some(b) = byte {
                if !is_virtual {
                    v.set(r, b, bytes).ok()?;
                }
            }
            self.put(v, &outs[i], &carries)?;
        }
        let mut above = vec![0i128; size as usize];
        if let Some(cut) = split.or(top_free) {
            for j in (cut + 1..=last).rev() {
                let mut skip = cols(j);
                skip.extend(cols(j - 1));
                for (x, c) in above.iter_mut().enumerate() {
                    *c = base * *c - self.sum(v, &positions[j], x as u64, &skip);
                }
                self.put(v, &outs[j - 1], &above)?;
            }
        }
        if let Some(t) = top_free {
            if positions[t].virtual_col().is_none() {
                let byte = byte_at(t).expect("free byte");
                let mut skip = cols(t);
                skip.push(byte);
                let bytes = (0..size)
                    .map(|x| {
                        (self.sum(v, &positions[t], x, &skip) - base * above[x as usize]) as i64
                    })
                    .collect();
                v.set(r, byte, bytes).ok()?;
            }
        }
        Some(())
    }
}

/// A per-constraint attack search; the callback returns true to stop.
pub(super) type Search<'a> = dyn Fn(Constraint, &mut dyn FnMut(Attack) -> bool) + 'a;

/// An attack: a full assignment, how it was built, and whether it changes an output.
pub(super) struct Attack {
    pub(super) how: String,
    pub(super) values: Values,
    pub(super) output: bool,
}

/// Run the survey: for each constraint, the first output-changing attack found, else the
/// first auxiliary one. Returns `(constraint, class, how)` rows.
///
/// `expected` is the golden table: when given, a constraint whose golden class is `none`
/// is not searched, and an `aux` one stops at its first auxiliary attack (the table is
/// still compared in full). Without it, the search is exhaustive.
pub(super) fn survey(
    r: &Relation,
    honest: &Values,
    pool: &[Attack],
    search: &Search,
    expected: Option<&str>,
) -> Vec<(String, String, String)> {
    let eval = Eval::new(r);
    assert!(eval.violations(honest, 0).is_empty(), "honest values pass");
    check(r, honest).expect("honest values pass the plain checker");
    let golden: BTreeMap<&str, &str> = expected
        .unwrap_or("")
        .lines()
        .filter_map(|l| l.rsplit_once(" | "))
        .collect();
    // `widen`: for a range, the attack must also lie within the range widened by one
    // bit, so a range declared one bit too wide would accept it (RFC-0026 §5.2).
    // `signed` picks the widening: one more bit at the top (`false`, unsigned ranges)
    // or one more bit as a sign (`true`).
    let attack_for = |c: Constraint, name: &str, widen: Option<bool>| -> (String, String, String) {
        let fits = |v: &Values| match (widen, c) {
            (Some(signed), Constraint::Range(i)) => {
                let g = &r.ranges[i];
                let wide = stele_ir::relation::Width {
                    signed,
                    bits: g.width.bits + 1,
                };
                eval_column(r, v, g.column).is_ok_and(|s| s.iter().all(|&x| wide.contains(x)))
            }
            _ => true,
        };
        let label = match widen {
            None => name.to_string(),
            Some(false) => format!("widen-up {name}"),
            Some(true) => format!("widen-signed {name}"),
        };
        let mut best: Option<Attack> = pool
            .iter()
            .filter(|a| eval.violations(&a.values, 1) == [c] && fits(&a.values))
            .max_by_key(|a| a.output)
            .map(|a| Attack {
                how: a.how.clone(),
                values: a.values.clone(),
                output: a.output,
            });
        let class = golden.get(label.as_str()).copied();
        let enough = |b: &Option<Attack>| match class {
            Some("none") => true,
            Some("aux") => b.is_some(),
            _ => b.as_ref().is_some_and(|b| b.output),
        };
        if !enough(&best) {
            search(c, &mut |a: Attack| {
                if eval.violations(&a.values, 1) != [c] || !fits(&a.values) {
                    return false;
                }
                if best.as_ref().is_none_or(|b| !b.output && a.output) {
                    best = Some(a);
                }
                enough(&best)
            });
        }
        match best {
            Some(a) => {
                // The relation's own oracle: `check` rejects the attack and accepts it once
                // this one constraint (by its unique name) is skipped.
                let raw = name.split_once(' ').map_or(name, |n| n.1);
                assert!(
                    check(r, &a.values).is_err(),
                    "{label}: the full relation rejects the attack"
                );
                assert_eq!(
                    check_except(r, &a.values, &[raw]),
                    Ok(()),
                    "{label}: only this constraint rejects the attack"
                );
                (
                    label,
                    (if a.output { "output" } else { "aux" }).to_string(),
                    a.how,
                )
            }
            None => (label, "none".to_string(), String::new()),
        }
    };
    let mut rows = Vec::new();
    for (c, name) in constraints(r) {
        rows.push(attack_for(c, &name, None));
    }
    for (c, name) in constraints(r) {
        if let Constraint::Range(i) = c {
            if !r.ranges[i].width.signed {
                rows.push(attack_for(c, &name, Some(false)));
            }
            rows.push(attack_for(c, &name, Some(true)));
        }
    }
    rows
}

/// Compare the survey with the golden table `expected` (`constraint | class` lines).
pub(super) fn golden(module: &str, rows: &[(String, String, String)], expected: &str) {
    let table: Vec<String> = rows.iter().map(|(n, c, _)| format!("{n} | {c}")).collect();
    let counts = rows.iter().fold(
        BTreeMap::new(),
        |mut m: BTreeMap<&str, usize>, (_, c, _)| {
            *m.entry(c.as_str()).or_default() += 1;
            m
        },
    );
    std::println!("{module}: {} constraints {counts:?}", rows.len());
    for (n, c, how) in rows {
        std::println!("| {n} | {c} | {how} |");
    }
    let expected: Vec<String> = expected
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    assert_eq!(
        table, expected,
        "{module} mutation survey differs from its golden table"
    );
}
