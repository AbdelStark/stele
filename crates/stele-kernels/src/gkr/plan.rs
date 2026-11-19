//! RFC-0014 A3. Validated device construction spans. Each interval repeats within its period.
//! The child layers remain borrowed to allow bounded transfer without duplicating complete layers.
use super::{GkrConstruction, GkrFactor, GkrMask, RelationConstruction, Term};
use crate::{Field, M31, QM31 as K};
use alloc::{vec, vec::Vec};
use core::ops::Range;

fn words(x: K) -> [u32; 4] {
    [
        x.0 .0.as_u32(),
        x.0 .1.as_u32(),
        x.1 .0.as_u32(),
        x.1 .1.as_u32(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Op {
    Constant,
    Equality,
    Block,
    GatherBase,
    GatherExt,
    Layer,
    Table,
}

pub struct Span<'a> {
    pub period: u32,
    pub begin: u32,
    pub end: u32,
    pub op: Op,
    pub arg: u32,
    pub shifts: Vec<u32>,
    pub data: Vec<u32>,
    pub layer: Option<&'a [[K; 2]]>,
}

pub struct TablePlan<'a> {
    pub base: bool,
    pub spans: Vec<Span<'a>>,
}

pub struct FactorPlan<'a> {
    pub values: TablePlan<'a>,
    pub mask: Option<(TablePlan<'a>, usize)>,
}

pub struct Plan<'a> {
    pub len: usize,
    pub degree: usize,
    pub terms: Vec<(K, Vec<u32>)>,
    pub factors: Vec<FactorPlan<'a>>,
}

type Build<T> = Result<T, &'static str>;

fn domain(n: usize) -> Build<u32> {
    1u32.checked_shl(u32::try_from(n).map_err(|_| "GKR domain")?)
        .ok_or("GKR domain")
}

fn span<'a>(period: u32, range: Range<usize>, op: Op, arg: u32, data: Vec<u32>) -> Build<Span<'a>> {
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
        layer: None,
    })
}

impl<'a> TablePlan<'a> {
    fn single(span: Span<'a>) -> Self {
        let base = matches!(span.op, Op::GatherBase | Op::Constant);
        Self {
            base,
            spans: vec![span],
        }
    }

    // Member offsets are disjoint by the lookup layout. Reject overlap before any launch.
    fn members(mut spans: Vec<Span<'a>>) -> Build<Self> {
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

fn gather<'a>(mut s: Span<'a>, coords: &[usize], entries: usize) -> Build<Span<'a>> {
    let n = s.period.ilog2() as usize;
    if domain(coords.len())? as usize != entries || coords.iter().any(|&q| q >= n) {
        return Err("GKR gather coordinates");
    }
    s.shifts = coords.iter().map(|q| (n - 1 - q) as u32).collect();
    Ok(s)
}

fn column<'a>(
    period: u32,
    range: Range<usize>,
    values: &[K],
    coords: &[usize],
    shift: i64,
) -> Build<Span<'a>> {
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

fn mask<'a>(len: u32, m: &GkrMask<'_>) -> Build<(TablePlan<'a>, usize)> {
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

fn factor<'a>(
    input: &GkrFactor<'a, K>,
    len: u32,
    half: u32,
    retained: Option<(usize, Option<&'a [[K; 2]]>)>,
) -> Build<FactorPlan<'a>> {
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
            let data = core::iter::once(*scale)
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
        GkrFactor::RetainedLayer {
            layer: level,
            component,
            side,
            mask: m,
        } => {
            let (expected, host) = retained.ok_or("GKR missing lookup tree")?;
            if *level != expected
                || *component > 1
                || *side > 1
                || host.is_some_and(|v| v.len() != 2 * half as usize)
            {
                return Err("GKR retained layer geometry");
            }
            let mut child = span(
                half,
                layer,
                Op::Layer,
                (2 * side + component) as u32,
                vec![],
            )?;
            child.layer = host;
            (TablePlan::single(child), Some(mask(len, m)?))
        }
        GkrFactor::Layer {
            values,
            component,
            side,
            mask: m,
        } => {
            if *component > 1 || *side > 1 || values.len() != half as usize * 2 {
                return Err("GKR child layer");
            }
            let mut child = span(
                half,
                layer,
                Op::Layer,
                (2 * side + component) as u32,
                Vec::new(),
            )?;
            child.layer = Some(*values);
            (TablePlan::single(child), Some(mask(len, m)?))
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

// RFC-0013 A5 item 3. An input is multilinear except on its vanishing axis.
// There the input is X + v(1-v)R, with one more degree if R depends on v.
fn axis_degree(factor: &GkrFactor<'_, K>, axis: usize, n: usize, half: usize) -> usize {
    match factor {
        GkrFactor::Column { mask, .. }
        | GkrFactor::Layer { mask, .. }
        | GkrFactor::RetainedLayer { mask, .. }
            if mask.vanishing == axis =>
        {
            2 + usize::from(mask.coordinates.contains(&axis))
        }
        GkrFactor::Combined { vanishing, members } if *vanishing == axis => {
            let bit = 1usize << (n - 1 - axis);
            // The compact mask repeats over the layer half. Inside that half
            // both the low mask coordinates and the member interval may depend on v.
            let dependent = bit < half
                && members.iter().any(|m| {
                    bit < m.mask.len()
                        || m.range.start % (2 * bit) != 0
                        || m.range.end % (2 * bit) != 0
                });
            2 + usize::from(dependent)
        }
        _ => 1,
    }
}

fn checked_terms(
    n: usize,
    degree: usize,
    terms: &[Term<K>],
    count: usize,
    bound: impl Fn(usize, usize) -> usize,
) -> Build<Vec<(K, Vec<u32>)>> {
    if !(1..32).contains(&degree) || terms.is_empty() || count == 0 {
        return Err("masked factor count or degree");
    }
    for term in terms {
        if term.factors.len() > degree || term.factors.iter().any(|&i| i as usize >= count) {
            return Err("masked term index or degree");
        }
        if (0..n).any(|axis| {
            term.factors
                .iter()
                .map(|&i| bound(i as usize, axis))
                .sum::<usize>()
                > degree
        }) {
            return Err("declared degree below term bound");
        }
    }
    Ok(terms
        .iter()
        .map(|t| (t.coefficient, t.factors.clone()))
        .collect())
}

impl<'a> Plan<'a> {
    /// RFC-0014 A4. The complete domain may broadcast a genuine projected input.
    pub fn relation(input: &RelationConstruction<'a, K>) -> Build<Self> {
        let n = input.num_vars as usize;
        if !(1..=30).contains(&n) {
            return Err("relation domain");
        }
        let len = domain(n)?;
        let terms = checked_terms(
            n,
            input.degree,
            &input.terms,
            input.factors.len(),
            |i, axis| match &input.factors[i].mask {
                Some(m) if m.vanishing == axis => 2 + usize::from(m.coordinates.contains(&axis)),
                _ => 1,
            },
        )?;
        let factors = input
            .factors
            .iter()
            .map(|f| {
                if f.mask.as_ref().is_some_and(|m| m.vanishing >= n) {
                    return Err("relation vanishing coordinate");
                }
                let values =
                    TablePlan::single(column(len, 0..len as usize, f.values, &f.coordinates, 0)?);
                let mask = f.mask.as_ref().map(|m| mask(len, m)).transpose()?;
                Ok(FactorPlan { values, mask })
            })
            .collect::<Build<_>>()?;
        Ok(Self {
            len: len as usize,
            degree: input.degree,
            terms,
            factors,
        })
    }

    pub fn new(input: &GkrConstruction<'a, K>) -> Build<Self> {
        Self::gkr(input, None)
    }

    pub fn retained(
        input: &GkrConstruction<'a, K>,
        level: usize,
        host: Option<&'a [[K; 2]]>,
    ) -> Build<Self> {
        let projections: Vec<_> = input
            .factors
            .iter()
            .filter_map(|f| match f {
                GkrFactor::RetainedLayer {
                    side, component, ..
                } => Some((*component, *side)),
                _ => None,
            })
            .collect();
        if projections != [(0, 0), (0, 1), (1, 0), (1, 1)]
            || input.layer_variables.checked_add(1) != Some(level)
            || input
                .factors
                .iter()
                .any(|f| matches!(f, GkrFactor::Layer { .. }))
        {
            return Err("GKR retained child order");
        }
        Self::gkr(input, Some((level, host)))
    }

    fn gkr(
        input: &GkrConstruction<'a, K>,
        retained: Option<(usize, Option<&'a [[K; 2]]>)>,
    ) -> Build<Self> {
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
        let terms = checked_terms(
            n,
            input.degree,
            &input.terms,
            input.factors.len(),
            |idx, axis| axis_degree(&input.factors[idx], axis, n, half as usize),
        )?;
        let factors = input
            .factors
            .iter()
            .map(|f| factor(f, len, half, retained))
            .collect::<Build<_>>()?;
        Ok(Self {
            len: len as usize,
            degree: input.degree,
            terms,
            factors,
        })
    }
}
