//! RFC-0008 A7: checked input spans for constructing genuine GKR factors on device.
//! Each span writes its interval in every period. Untouched output values are zero.
use crate::{lookup::words, round::Terms, Field, K, M31};
use std::ops::Range;
use stele_reductions::zk::claims::bench::{GkrConstruction, GkrFactor, GkrMask};

#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum Op {
    Constant,
    Equality,
    Block,
    GatherBase,
    GatherExt,
    Layer,
    Table,
}

pub(crate) struct Span {
    pub period: u32,
    pub begin: u32,
    pub end: u32,
    pub op: Op,
    pub arg: u32,
    pub shifts: Vec<u32>,
    pub data: Vec<u32>,
}

pub(crate) struct TablePlan {
    pub base: bool,
    pub spans: Vec<Span>,
}

pub(crate) struct FactorPlan {
    pub values: TablePlan,
    pub mask: Option<(TablePlan, usize)>,
}

pub(crate) struct Plan {
    pub len: usize,
    pub degree: usize,
    pub terms: Vec<(K, Vec<u32>)>,
    pub factors: Vec<FactorPlan>,
}

type Build<T> = Result<T, &'static str>;

fn domain(n: usize) -> Build<u32> {
    1u32.checked_shl(u32::try_from(n).map_err(|_| "GKR domain")?)
        .ok_or("GKR domain")
}

fn span(period: u32, range: Range<usize>, op: Op, arg: u32, data: Vec<u32>) -> Build<Span> {
    if range.start >= range.end || range.end > period as usize {
        return Err("GKR span range");
    }
    Ok(Span {
        period,
        begin: range.start as u32,
        end: range.end as u32,
        op,
        arg,
        shifts: Vec::new(),
        data,
    })
}

impl TablePlan {
    fn single(span: Span) -> Self {
        let base = matches!(span.op, Op::GatherBase | Op::Constant);
        Self {
            base,
            spans: vec![span],
        }
    }

    // Member offsets are disjoint by the lookup layout. Reject overlap before any launch.
    fn members(mut spans: Vec<Span>) -> Build<Self> {
        spans.sort_by_key(|s| s.begin);
        if spans.windows(2).any(|pair| pair[0].end > pair[1].begin) {
            return Err("overlapping GKR members");
        }
        let base = spans
            .iter()
            .all(|s| matches!(s.op, Op::GatherBase | Op::Constant));
        Ok(Self { base, spans })
    }
}

fn gather(mut s: Span, coords: &[usize], entries: usize) -> Build<Span> {
    let n = s.period.ilog2() as usize;
    if domain(coords.len())? as usize != entries || coords.iter().any(|&q| q >= n) {
        return Err("GKR gather coordinates");
    }
    s.shifts = coords.iter().map(|q| (n - 1 - q) as u32).collect();
    Ok(s)
}

fn column(
    period: u32,
    range: Range<usize>,
    values: &[K],
    coords: &[usize],
    shift: i64,
) -> Build<Span> {
    let (op, data) = if values
        .iter()
        .all(|k| k.0 .1 == M31::ZERO && k.1 .0 == M31::ZERO && k.1 .1 == M31::ZERO)
    {
        (
            Op::GatherBase,
            values.iter().map(|k| k.0 .0.as_u32()).collect(),
        )
    } else {
        (
            Op::GatherExt,
            values.iter().copied().flat_map(words).collect(),
        )
    };
    gather(
        span(period, range, op, M31::from_i64(shift).as_u32(), data)?,
        coords,
        values.len(),
    )
}

fn mask(len: u32, m: &GkrMask<'_>) -> Build<(TablePlan, usize)> {
    let s = span(
        len,
        0..len as usize,
        Op::GatherBase,
        0,
        m.values.iter().map(|v| v.as_u32()).collect(),
    )?;
    Ok((
        TablePlan::single(gather(s, m.coordinates, m.values.len())?),
        m.vanishing,
    ))
}

fn factor(input: &GkrFactor<'_, K>, len: u32, half: u32) -> Build<FactorPlan> {
    let all = 0..len as usize;
    let layer = 0..half as usize;
    let (values, mask) = match input {
        GkrFactor::Equality {
            point,
            scale,
            offset,
        } => {
            let size = domain(point.len())?;
            let end = offset
                .checked_add(size as usize)
                .ok_or("GKR equality offset")?;
            let data = std::iter::once(*scale)
                .chain(point.iter().copied())
                .flat_map(words)
                .collect();
            (
                TablePlan::single(span(
                    len,
                    *offset..end,
                    Op::Equality,
                    point.len() as u32,
                    data,
                )?),
                None,
            )
        }
        GkrFactor::Block { values, point } => {
            if values.len() < 2
                || !values.len().is_power_of_two()
                || values.len() / 2 > half as usize
            {
                return Err("GKR block size");
            }
            let data = words(*point)
                .into_iter()
                .chain(values.iter().map(|m| m.as_u32()))
                .collect();
            (
                TablePlan::single(span(
                    half,
                    layer,
                    Op::Block,
                    (values.len() / 2) as u32,
                    data,
                )?),
                None,
            )
        }
        GkrFactor::Column {
            values,
            coordinates,
            mask: m,
        } => (
            TablePlan::single(column(len, all, values, coordinates, 0)?),
            Some(mask(len, m)?),
        ),
        GkrFactor::Layer {
            values,
            component,
            side,
            mask: m,
        } => {
            if *component > 1 || *side > 1 || values.len() != half as usize * 2 {
                return Err("GKR child layer");
            }
            let data = values.iter().flatten().copied().flat_map(words).collect();
            (
                TablePlan::single(span(
                    half,
                    layer,
                    Op::Layer,
                    (2 * side + component) as u32,
                    data,
                )?),
                Some(mask(len, m)?),
            )
        }
        GkrFactor::Pad { variables } => (
            TablePlan::single(span(
                half,
                0..domain(*variables)? as usize,
                Op::Constant,
                1,
                vec![],
            )?),
            None,
        ),
        GkrFactor::Selector { members } => {
            let spans = members
                .iter()
                .map(|m| match m.values {
                    None => span(half, m.range.clone(), Op::Constant, 1, vec![]),
                    Some((vals, coords)) => gather(
                        span(
                            half,
                            m.range.clone(),
                            Op::GatherBase,
                            0,
                            vals.iter().map(|x| M31::from_i64(*x).as_u32()).collect(),
                        )?,
                        coords,
                        vals.len(),
                    ),
                })
                .collect::<Build<Vec<_>>>()?;
            (TablePlan::members(spans)?, None)
        }
        GkrFactor::Table {
            rows,
            valid,
            alpha,
            beta,
        } => {
            if *valid > half as usize || *valid > rows.len() {
                return Err("GKR valid rows");
            }
            let mut spans = vec![];
            if *valid > 0 {
                let width = rows[0].len();
                if rows[..*valid].iter().any(|r| r.len() != width) {
                    return Err("GKR row width");
                }
                let data = words(*alpha)
                    .into_iter()
                    .chain(words(*beta))
                    .chain(
                        rows[..*valid]
                            .iter()
                            .flatten()
                            .map(|z| M31::from_i64(*z).as_u32()),
                    )
                    .collect();
                spans.push(span(
                    half,
                    0..*valid,
                    Op::Table,
                    u32::try_from(width).map_err(|_| "GKR row width")?,
                    data,
                )?);
            }
            if *valid < half as usize {
                spans.push(span(half, *valid..half as usize, Op::Constant, 1, vec![])?);
            }
            (TablePlan::members(spans)?, None)
        }
        GkrFactor::Combined { members, vanishing } => {
            let mut xs = Vec::new();
            let mut rs = Vec::new();
            for m in members {
                xs.push(column(
                    half,
                    m.range.clone(),
                    m.values,
                    m.coordinates,
                    m.shift,
                )?);
                if !m.mask.len().is_power_of_two() || m.mask.len() > half as usize {
                    return Err("GKR member mask");
                }
                let mask_bits = m.mask.len().ilog2();
                let mut s = span(
                    half,
                    m.range.clone(),
                    Op::GatherBase,
                    0,
                    m.mask.iter().map(|v| v.as_u32()).collect(),
                )?;
                s.shifts = (0..mask_bits).rev().collect();
                rs.push(s);
            }
            (
                TablePlan::members(xs)?,
                Some((TablePlan::members(rs)?, *vanishing)),
            )
        }
    };
    if mask
        .as_ref()
        .is_some_and(|(_, v)| *v >= len.ilog2() as usize)
    {
        return Err("GKR vanishing coordinate");
    }
    Ok(FactorPlan { values, mask })
}

impl Plan {
    pub fn new(input: &GkrConstruction<'_, K>) -> Build<Self> {
        let n = input.num_vars as usize;
        if n == 0
            || n > 30
            || input.layer_variables > n
            || n - input.layer_variables > 1
            || input.factors.is_empty()
        {
            return Err("GKR construction geometry");
        }
        let len = domain(n)?;
        let half = domain(input.layer_variables)?;
        let terms: Vec<_> = input
            .terms
            .iter()
            .map(|t| (t.coefficient, t.factors.clone()))
            .collect();
        Terms::new(
            input.factors.len(),
            &terms,
            input.degree.checked_add(1).ok_or("GKR degree")?,
        )?;
        let factors = input
            .factors
            .iter()
            .map(|f| factor(f, len, half))
            .collect::<Build<_>>()?;
        Ok(Self {
            len: len as usize,
            degree: input.degree,
            terms,
            factors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_geometry_before_device_access() {
        let mut input = GkrConstruction {
            num_vars: 3,
            layer_variables: 3,
            degree: 2,
            terms: vec![],
            factors: vec![GkrFactor::Pad { variables: 4 }],
        };
        assert!(matches!(Plan::new(&input), Err("GKR span range")));
        input.factors[0] = GkrFactor::Column {
            values: &[K::ZERO],
            coordinates: vec![3],
            mask: GkrMask {
                values: vec![M31::ONE],
                coordinates: &[],
                vanishing: 0,
            },
        };
        assert!(matches!(Plan::new(&input), Err("GKR gather coordinates")));
        let rows = [vec![1], vec![1, 2]];
        input.factors[0] = GkrFactor::Table {
            rows: &rows,
            valid: 2,
            alpha: K::ONE,
            beta: K::ONE,
        };
        assert!(matches!(Plan::new(&input), Err("GKR row width")));
    }
}
