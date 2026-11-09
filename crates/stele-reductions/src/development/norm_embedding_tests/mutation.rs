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
use stele_ir::relation::{check_except, Ref};

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
        let col = |c: ColumnId| v.get(r, c).expect("assigned");
        let read = |f: &Ref, x: u64| i128::from(col(f.column)[f.index(x)]);
        let mut out = Vec::new();
        for (i, g) in r.ranges.iter().enumerate() {
            if col(g.column).iter().any(|&x| !g.width.contains(x)) {
                out.push(Constraint::Range(i));
            }
        }
        for (i, l) in r.lookups.iter().enumerate() {
            let bad = (0..1u64 << l.vars).any(|x| {
                l.selector.as_ref().is_none_or(|s| read(s, x) != 0)
                    && !self.tables[l.table.0 as usize].contains(
                        &l.tuple
                            .iter()
                            .map(|f| read(f, x) as i64)
                            .collect::<Vec<_>>(),
                    )
            });
            if bad {
                out.push(Constraint::Lookup(i));
            }
        }
        for (i, c) in r.composes.iter().enumerate() {
            let column = col(c.column);
            let bad = (0..column.len()).any(|x| {
                let sum: i128 = c
                    .limbs
                    .iter()
                    .map(|&(l, s)| i128::from(col(l)[x]) << s)
                    .sum();
                sum != i128::from(column[x])
            });
            if bad {
                out.push(Constraint::Compose(i));
            }
        }
        if out.len() > cap {
            return out;
        }
        for (i, d) in r.identities.iter().enumerate() {
            let bad = (0..1u64 << d.vars).any(|x| {
                d.terms
                    .iter()
                    .map(|t| {
                        t.factors
                            .iter()
                            .fold(i128::from(t.coeff), |p, f| p * read(f, x))
                    })
                    .sum::<i128>()
                    != 0
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
                let s: i128 = (0..1u64 << m.summed)
                    .map(|y| read(&m.lhs, x | (y << m.free)) * read(&m.rhs, x | (y << m.free)))
                    .sum();
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
    let mut v: Vec<ColumnId> = match c {
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
    v.sort();
    v.dedup();
    v.retain(|c| matches!(r.columns[c.0 as usize].kind, Kind::Witness(_)));
    v
}

pub(super) fn column(r: &Relation, name: &str) -> Option<ColumnId> {
    r.columns
        .iter()
        .position(|c| c.name == name)
        .map(|i| ColumnId(i as u32))
}

fn read(r: &Relation, v: &Values, f: &Ref, x: u64) -> i128 {
    i128::from(v.get(r, f.column).expect("assigned")[f.index(x)])
}

pub(super) fn get(r: &Relation, v: &Values, c: ColumnId, i: usize) -> i128 {
    i128::from(v.get(r, c).expect("assigned")[i])
}

pub(super) fn set(r: &Relation, v: &mut Values, c: ColumnId, i: usize, value: i128) {
    let mut col = v.get(r, c).expect("assigned").to_vec();
    col[i] = value as i64;
    v.set(r, c, col).expect("length");
}

/// Re-derive the byte limbs of Compose `k` from its column (top limb keeps the rest).
pub(super) fn derive_limbs(r: &Relation, v: &mut Values, k: usize) {
    let c = r.composes[k].clone();
    let column = v.get(r, c.column).expect("column").to_vec();
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

/// Recompute every witness matmul output except `skip`, and the limbs of its Compose.
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
}

/// One radix-256 chain: identities `{name}/{i}`, free bytes `{free}{i}` and an optional
/// free wide column (the norm output). Carries are found structurally: the columns
/// with coefficient `−256` (or `−2^24`) at a position.
#[derive(Clone, Copy)]
pub(super) struct ChainSpec<'a> {
    pub(super) name: &'a str,
    pub(super) free: &'a str,
    pub(super) wide: Option<&'a str>,
}

pub(super) struct Solver<'a> {
    pub(super) r: &'a Relation,
    pub(super) scope: &'a str,
    pub(super) specs: &'a [ChainSpec<'a>],
    /// The tampered columns: the solver never overwrites them.
    pub(super) keep: Cell<Option<ColumnId>>,
}

impl Solver<'_> {
    fn ids(&self, spec: ChainSpec) -> Vec<usize> {
        let s = self.scope;
        (0..)
            .map_while(|i| {
                self.r
                    .identities
                    .iter()
                    .position(|d| d.name == format!("{s}/{}/{i}", spec.name))
            })
            .collect()
    }

    /// Carry-out columns of an identity: (column, weight) with `carry = Σ weight·column`.
    fn carries(&self, id: usize) -> Vec<(ColumnId, i128)> {
        self.r.identities[id]
            .terms
            .iter()
            .filter(|t| t.factors.len() == 1 && (t.coeff == -256 || t.coeff == -(1 << 24)))
            .map(|t| (t.factors[0].column, i128::from(t.coeff / -256)))
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

    fn sum(&self, v: &Values, id: usize, x: u64, skip: &[ColumnId]) -> i128 {
        self.r.identities[id]
            .terms
            .iter()
            .filter(|t| t.factors.iter().all(|f| !skip.contains(&f.column)))
            .map(|t| {
                t.factors
                    .iter()
                    .fold(i128::from(t.coeff), |p, f| p * read(self.r, v, f, x))
            })
            .sum()
    }

    pub(super) fn solve(&self, v: &mut Values, cut: Constraint) -> Option<()> {
        for spec in self.specs {
            self.chain(v, *spec, cut)?;
        }
        Some(())
    }

    /// Solve one chain bottom-up (free bytes and carries); when it holds the removed
    /// identity `cut`, solve the positions above it top-down instead.
    pub(super) fn chain(&self, v: &mut Values, spec: ChainSpec, cut: Constraint) -> Option<()> {
        let (r, s) = (self.r, self.scope);
        let ids = self.ids(spec);
        let last = ids.len() - 1;
        let split = ids.iter().position(|&id| cut == Constraint::Identity(id));
        let keep = self.keep.get();
        let wide = spec
            .wide
            .and_then(|w| column(r, &format!("{s}/{w}")))
            .filter(|&w| Some(w) != keep);
        let size = 1u64 << r.identities[ids[0]].vars;
        let mentions = |id: usize, c: ColumnId| {
            r.identities[id]
                .terms
                .iter()
                .any(|t| t.factors.iter().any(|f| f.column == c))
        };
        let outs: Vec<Vec<(ColumnId, i128)>> = ids.iter().map(|&id| self.carries(id)).collect();
        let cols = |k: usize| outs[k].iter().map(|c| c.0).collect::<Vec<_>>();
        let byte_at = |i: usize| {
            column(r, &format!("{s}/{}{i}", spec.free))
                .filter(|&c| mentions(ids[i], c) && Some(c) != keep)
        };
        // Without a cut, the highest free byte takes whatever the positions above leave:
        // its carry-out comes top-down, so a value change lands in that byte.
        let top_free = if split.is_none() && wide.is_none() {
            (0..=last).rev().find(|&i| byte_at(i).is_some())
        } else {
            None
        };
        for i in 0..split.or(top_free).unwrap_or(last + 1) {
            let byte = byte_at(i);
            if let Some(w) = wide.filter(|&w| mentions(ids[i], w)) {
                // Y = −(c_in + Σ_{j>=i} 256^(j−i)·T'_j): the output the chain implies.
                let mut y = Vec::new();
                for x in 0..size {
                    let mut total = 0i128;
                    for j in (i..=last).rev() {
                        let mut skip = cols(j);
                        skip.push(w);
                        if j > i {
                            skip.extend(cols(j - 1));
                        }
                        total = total * 256 + self.sum(v, ids[j], x, &skip);
                    }
                    y.push((-total) as i64);
                }
                v.set(r, w, y).ok()?;
            }
            let mut skip = cols(i);
            skip.extend(byte);
            let (mut carries, mut bytes) = (Vec::new(), Vec::new());
            for x in 0..size {
                let mut sum = self.sum(v, ids[i], x, &skip);
                if byte.is_some() {
                    let b = if i == last { sum } else { sum.rem_euclid(256) };
                    bytes.push(b as i64);
                    sum -= b;
                }
                if (i == last && sum != 0) || sum % 256 != 0 {
                    return None;
                }
                carries.push(sum / 256);
            }
            if let Some(b) = byte {
                v.set(r, b, bytes).ok()?;
            }
            self.put(v, &outs[i], &carries)?;
        }
        let mut above = vec![0i128; size as usize];
        if let Some(cut) = split.or(top_free) {
            // c_{j-1} = 256·c_j − T'_j from the top down to the removed position.
            for j in (cut + 1..=last).rev() {
                let mut skip = cols(j);
                skip.extend(cols(j - 1));
                for (x, c) in above.iter_mut().enumerate() {
                    *c = 256 * *c - self.sum(v, ids[j], x as u64, &skip);
                }
                self.put(v, &outs[j - 1], &above)?;
            }
        }
        if let Some(t) = top_free {
            let byte = byte_at(t).expect("free byte");
            let mut skip = cols(t);
            skip.push(byte);
            let bytes = (0..size)
                .map(|x| (self.sum(v, ids[t], x, &skip) - 256 * above[x as usize]) as i64)
                .collect();
            v.set(r, byte, bytes).ok()?;
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
    // Each pool attack is charged to the single constraint it violates, if any.
    let mut charged: BTreeMap<Constraint, usize> = BTreeMap::new();
    for (i, a) in pool.iter().enumerate() {
        if let [c] = eval.violations(&a.values, 1)[..] {
            let better = charged.get(&c).is_none_or(|&j| !pool[j].output && a.output);
            if better {
                charged.insert(c, i);
            }
        }
    }
    let mut rows = Vec::new();
    for (c, name) in constraints(r) {
        let mut best: Option<Attack> = charged.get(&c).map(|&i| Attack {
            how: pool[i].how.clone(),
            values: pool[i].values.clone(),
            output: pool[i].output,
        });
        let class = golden.get(name.as_str()).copied();
        let enough = |b: &Option<Attack>| match class {
            Some("none") => true,
            Some("aux") => b.is_some(),
            _ => b.as_ref().is_some_and(|b| b.output),
        };
        if !enough(&best) {
            search(c, &mut |a: Attack| {
                if eval.violations(&a.values, 1) != [c] {
                    return false;
                }
                if best.as_ref().is_none_or(|b| !b.output && a.output) {
                    best = Some(a);
                }
                enough(&best)
            });
        }
        let row = match best {
            Some(a) => {
                // The relation's own oracle: `check` rejects the attack and accepts it once
                // this one constraint (by its unique name) is skipped.
                let raw = name.split_once(' ').map_or(name.as_str(), |n| n.1);
                assert!(
                    check(r, &a.values).is_err(),
                    "{name}: the full relation rejects the attack"
                );
                assert_eq!(
                    check_except(r, &a.values, &[raw]),
                    Ok(()),
                    "{name}: only this constraint rejects the attack"
                );
                (
                    name,
                    (if a.output { "output" } else { "aux" }).to_string(),
                    a.how,
                )
            }
            None => (name, "none".to_string(), String::new()),
        };
        rows.push(row);
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
