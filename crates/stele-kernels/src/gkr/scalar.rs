//! RFC-0014 A3. Scalar evaluation of the original masked multilinear factors.
use super::plan::{Op, Plan, Span, TablePlan};
use super::{GkrBackend, GkrConstruction, RelationBackend, RelationConstruction};
use crate::{Error, Field, Scalar, CM31, M31, QM31 as K};
use alloc::vec::Vec;

fn base(value: u32) -> Result<M31, Error> {
    M31::from_canonical(value).ok_or(Error::Shape)
}
fn extension(words: &[u32], i: usize) -> Result<K, Error> {
    let row = words.get(4 * i..4 * i + 4).ok_or(Error::Shape)?;
    Ok(K(
        CM31(base(row[0])?, base(row[1])?),
        CM31(base(row[2])?, base(row[3])?),
    ))
}
fn embed(x: u32) -> Result<K, Error> {
    Ok(K(CM31(base(x)?, M31::ZERO), CM31::ZERO))
}
fn mix(a: K, b: K, t: K) -> K {
    a + t * (b - a)
}

fn span_value(s: &Span<'_>, pos: usize) -> Result<K, Error> {
    let words = &s.data;
    let arg = s.arg as usize;
    match s.op {
        Op::Constant => embed(s.arg),
        Op::Equality => {
            let index = pos - s.begin as usize;
            let mut q = extension(words, 0)?;
            for axis in 0..arg {
                let r = extension(words, axis + 1)?;
                q = q * if index >> (arg - 1 - axis) & 1 == 0 {
                    K::ONE - r
                } else {
                    r
                };
            }
            Ok(q)
        }
        Op::Block => {
            let j = pos % arg;
            Ok(mix(
                embed(words[4 + j])?,
                embed(words[4 + arg + j])?,
                extension(words, 0)?,
            ))
        }
        Op::GatherBase | Op::GatherExt => {
            let index = s
                .shifts
                .iter()
                .fold(0usize, |at, bit| (at << 1) | ((pos >> bit) & 1));
            let value = if s.op == Op::GatherBase {
                embed(words[index])?
            } else {
                extension(words, index)?
            };
            Ok(value + embed(s.arg)?)
        }
        Op::Layer => {
            let layer = s.layer.ok_or(Error::Shape)?;
            Ok(layer[2 * pos + arg / 2][arg % 2])
        }
        Op::Table => {
            let mut value = extension(words, 0)?;
            let beta = extension(words, 1)?;
            let mut power = K::ONE;
            for &cell in &words[8 + pos * arg..8 + (pos + 1) * arg] {
                value = value - power * embed(cell)?;
                power = power * beta;
            }
            Ok(value)
        }
    }
}

fn table(t: &TablePlan<'_>, len: usize) -> Result<Vec<K>, Error> {
    let mut values = Vec::new();
    values.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    values.resize(len, K::ZERO);
    for s in &t.spans {
        for pos in s.begin as usize..s.end as usize {
            let value = span_value(s, pos)?;
            for index in (pos..len).step_by(s.period as usize) {
                values[index] = value;
            }
        }
    }
    Ok(values)
}

struct Factor {
    x: Vec<K>,
    mask: Option<(Vec<K>, usize)>,
}
pub struct State {
    degree: usize,
    width: usize,
    axis: usize,
    needs_fold: bool,
    terms: Vec<(K, Vec<u32>)>,
    factors: Vec<Factor>,
}

impl State {
    fn from_plan(plan: Plan<'_>) -> Result<Self, Error> {
        let factors = plan
            .factors
            .iter()
            .map(|f| {
                Ok(Factor {
                    x: table(&f.values, plan.len)?,
                    mask: f
                        .mask
                        .as_ref()
                        .map(|(m, v)| table(m, plan.len).map(|t| (t, *v)))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(State {
            degree: plan.degree,
            width: plan.len,
            axis: 0,
            needs_fold: false,
            terms: plan.terms,
            factors,
        })
    }
}

impl RelationBackend<K> for Scalar<K> {
    fn relation_start(&self, input: &RelationConstruction<'_, K>) -> Result<State, Error> {
        State::from_plan(Plan::relation(input).map_err(|_| Error::Shape)?)
    }
}

impl GkrBackend<K> for Scalar<K> {
    type Gkr<'s> = State;
    fn gkr_start(&self, input: &GkrConstruction<'_, K>) -> Result<State, Error> {
        State::from_plan(Plan::new(input).map_err(|_| Error::Shape)?)
    }

    fn gkr_round<'s>(s: &mut State) -> Result<Vec<K>, Error>
    where
        Self: 's,
    {
        if s.needs_fold || s.width <= 1 {
            return Err(Error::Phase);
        }
        let half = s.width / 2;
        let mut out = alloc::vec![K::ZERO;s.degree+1];
        let mut values = alloc::vec![K::ZERO;s.factors.len()];
        for (n, result) in out.iter_mut().enumerate() {
            let t = K::from_i64(n as i64);
            let k = t * (K::ONE - t);
            for j in 0..half {
                for (value, f) in values.iter_mut().zip(&s.factors) {
                    *value = mix(f.x[j], f.x[j + half], t);
                    if let Some((mask, v)) = &f.mask {
                        if *v == s.axis {
                            *value = *value + k * mix(mask[j], mask[j + half], t);
                        }
                    }
                }
                for (coeff, indices) in &s.terms {
                    *result = *result
                        + indices
                            .iter()
                            .fold(*coeff, |product, &i| product * values[i as usize]);
                }
            }
        }
        s.needs_fold = true;
        Ok(out)
    }
    fn gkr_fold<'s>(s: &mut State, t: K) -> Result<(), Error>
    where
        Self: 's,
    {
        if !s.needs_fold {
            return Err(Error::Phase);
        }
        let half = s.width / 2;
        let fold = |arr: &mut Vec<K>| {
            let (lo, hi) = arr.split_at_mut(half);
            for (a, b) in lo.iter_mut().zip(hi) {
                *a = mix(*a, *b, t);
            }
            arr.truncate(half);
        };
        let k = t * (K::ONE - t);
        for f in &mut s.factors {
            fold(&mut f.x);
            if let Some((mask, v)) = &mut f.mask {
                fold(mask);
                if *v == s.axis {
                    for (a, r) in f.x.iter_mut().zip(mask) {
                        *a = *a + k * *r;
                    }
                    f.mask = None;
                }
            }
        }
        s.width = half;
        s.axis += 1;
        s.needs_fold = false;
        Ok(())
    }
    fn gkr_finals<'s>(s: &State) -> Result<Vec<K>, Error>
    where
        Self: 's,
    {
        if s.width != 1 || s.needs_fold {
            return Err(Error::Phase);
        }
        Ok(s.factors.iter().map(|f| f.x[0]).collect())
    }
}
