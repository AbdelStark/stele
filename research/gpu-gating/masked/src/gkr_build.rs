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
    OriginalBase,
    OriginalBlock,
}

/// Actual source of uploaded words. The coordinate and term descriptors are accounted separately.
#[derive(Clone, Copy)]
pub(crate) enum InputKind {
    Equality,
    Block,
    Column,
    Mask,
    Layer,
    Public,
    Selector,
}

pub(crate) struct Span {
    pub period: u32,
    pub begin: u32,
    pub end: u32,
    pub op: Op,
    pub kind: InputKind,
    pub original: Option<[usize; 6]>,
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
        kind: match op {
            Op::Equality => InputKind::Equality,
            Op::Block | Op::OriginalBlock => InputKind::Block,
            Op::Layer => InputKind::Layer,
            Op::Table | Op::Constant => InputKind::Public,
            Op::OriginalBase | Op::GatherBase | Op::GatherExt => InputKind::Column,
        },
        original: None,
        arg,
        shifts: Vec::new(),
        data,
    })
}

impl TablePlan {
    /// Unmasked Gin::Block depends only on the low bits of its tiled block.
    /// All other tables retain the full logical domain.
    pub(crate) fn storage_len(&self, domain: usize) -> usize {
        match self.spans.as_slice() {
            [s] if !self.base
                && matches!(s.op, Op::Block | Op::OriginalBlock)
                && s.begin == 0
                && s.end == s.period
                && s.arg.is_power_of_two()
                && s.arg <= s.period
                && s.period.is_power_of_two()
                && domain.is_multiple_of(s.period as usize)
                && match s.op {
                    Op::Block => s.data.len() == 4 + 2 * s.arg as usize,
                    Op::OriginalBlock => {
                        s.data.len() == 4 && s.original.is_some_and(|v| v[5] == 2 * s.arg as usize)
                    }
                    _ => false,
                } =>
            {
                s.arg as usize
            }
            _ => domain,
        }
    }

    fn single(span: Span) -> Self {
        let base = matches!(span.op, Op::GatherBase | Op::OriginalBase | Op::Constant);
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
            .all(|s| matches!(s.op, Op::GatherBase | Op::OriginalBase | Op::Constant));
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
    origin: Option<[usize; 6]>,
) -> Build<Span> {
    if let Some(origin @ [_, _, rows, cols, at, count]) = origin {
        let cells = rows.checked_mul(cols).ok_or("GKR original extent")?;
        if rows < 2
            || cols < 2
            || !rows.is_power_of_two()
            || !cols.is_power_of_two()
            || count != values.len()
            || at.checked_add(count).is_none_or(|end| end > cells / 4)
        {
            return Err("GKR original column geometry");
        }
        // Origin comes from the statement's base-typed column, before embedding
        // into the CPU challenge field. No host field scan or payload copy is required.
        let mut s = span(
            period,
            range,
            Op::OriginalBase,
            M31::from_i64(shift).as_u32(),
            vec![],
        )?;
        s.original = Some(origin);
        return gather(s, coords, count);
    }
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

fn factor(
    input: &GkrFactor<'_, K>,
    len: u32,
    half: u32,
    resident: bool,
    original: Option<&crate::gkr::ColumnOrigin>,
) -> Build<FactorPlan> {
    if let Some(legs) = original {
        let count = match input {
            GkrFactor::Column { .. } => 1,
            GkrFactor::Combined { members, .. } => members.len(),
            GkrFactor::Layer { .. } => return Err("original GKR leaf has a child"),
            _ => 0,
        };
        // At k0 == n, Gin::Top and Gin::Leaf share a step. The former is a
        // later QM31 source, explicitly marked None by the producing plan.
        if legs.len() != count
            || (matches!(input, GkrFactor::Combined { .. }) && legs.iter().any(Option::is_none))
        {
            return Err("original GKR leaf column provenance");
        }
    }
    let leg = |i: usize| original.and_then(|s| s[i]);
    let all = 0..len as usize;
    let layer = 0..half as usize;
    let (mut values, mut mask) = match input {
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
            TablePlan::single(column(len, all, values, coordinates, 0, leg(0))?),
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
            // The resident tree supplies these checked pairs directly from its device
            // allocation. All other factor inputs keep their ordinary representation.
            let data = if resident {
                Vec::new()
            } else {
                values.iter().flatten().copied().flat_map(words).collect()
            };
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
            for (ordinal, m) in members.iter().enumerate() {
                xs.push(column(
                    half,
                    m.range.clone(),
                    m.values,
                    m.coordinates,
                    m.shift,
                    leg(ordinal),
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
    if matches!(input, GkrFactor::Selector { .. }) {
        for span in &mut values.spans {
            span.kind = InputKind::Selector;
        }
    }
    if let Some((mask, _)) = &mut mask {
        for span in &mut mask.spans {
            span.kind = InputKind::Mask;
        }
    }
    Ok(FactorPlan { values, mask })
}

/// Explicit live bytes on the single CUDA stream. An allocation being replaced
/// remains live through its kernel, then its free precedes the next allocation.
pub(crate) struct Peak {
    pub construction: usize,
    pub fold: usize,
}

impl Plan {
    pub fn peak(&self, blocks: usize) -> Build<Peak> {
        let len = self.len as u128;
        let table_bytes = |table: &TablePlan| {
            table.storage_len(self.len) as u128 * if table.base { 4 } else { 16 }
        };
        let mut live = 0;
        let mut construction = 0;
        for f in &self.factors {
            if let Some((mask, _)) = &f.mask {
                if f.values.storage_len(self.len) != self.len
                    || mask.storage_len(self.len) != self.len
                {
                    return Err("masked cyclic GKR table");
                }
            }
            for t in std::iter::once(&f.values).chain(f.mask.as_ref().map(|(t, _)| t)) {
                live += table_bytes(t);
                // gkr_table allocates its output before it uploads each individual span.
                construction = construction.max(live);
                for span in &t.spans {
                    construction = construction
                        .max(live + 4 * (span.data.len() as u128 + span.shifts.len() as u128));
                }
            }
        }
        let terms = self.terms.len() as u128;
        let indices = self
            .terms
            .iter()
            .map(|(_, t)| t.len() as u128)
            .sum::<u128>()
            .max(1);
        let descriptors =
            20 * self.factors.len() as u128 + 4 * (terms + 1 + indices) + 16 * terms.max(1);
        let scratch = 16 * (self.degree as u128 + 1) * (blocks as u128 + 1);
        live += descriptors + scratch;
        construction = construction.max(live);
        let mut fold = live;
        // DeviceMasked::fold visits x then r. At coordinate zero a vanishing
        // mask is consumed by fold_mask without a separate promotion. After
        // round zero every surviving table is QM31 and folds in place.
        let promote = |t: &TablePlan, live: &mut u128, high: &mut u128| {
            if t.base {
                *high = (*high).max(*live + 8 * len);
                *live += 4 * len;
            }
        };
        for f in &self.factors {
            promote(&f.values, &mut live, &mut fold);
            if let Some((mask, v)) = &f.mask {
                if *v == 0 {
                    live -= table_bytes(mask);
                } else {
                    promote(mask, &mut live, &mut fold);
                }
            }
        }
        let bytes = |n| usize::try_from(n).map_err(|_| "GKR allocation bound");
        Ok(Peak {
            construction: bytes(construction)?,
            fold: bytes(fold)?,
        })
    }

    pub fn new(input: &GkrConstruction<'_, K>) -> Build<Self> {
        Self::with_layers(input, false)
    }

    pub(crate) fn with_originals(
        input: &GkrConstruction<'_, K>,
        origins: &[crate::gkr::ColumnOrigin],
    ) -> Build<Self> {
        if origins.len() != input.factors.len() {
            return Err("original GKR factor count");
        }
        Self::make(input, false, Some(origins))
    }

    pub(crate) fn with_layers(input: &GkrConstruction<'_, K>, resident: bool) -> Build<Self> {
        Self::make(input, resident, None)
    }

    fn make(
        input: &GkrConstruction<'_, K>,
        resident: bool,
        origins: Option<&[crate::gkr::ColumnOrigin]>,
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
            .enumerate()
            .map(|(i, f)| factor(f, len, half, resident, origins.map(|v| &v[i])))
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
    fn matches_reference_construction_before_device_access() {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for case in 0..24 {
            crate::gkr_cases::observe(case, |step| {
                let plan = Plan::new(&step.construction()?).unwrap();
                let reference = step.reference()?;
                assert_eq!(plan.len, 1 << reference.variables());
                assert_eq!(plan.degree, reference.degree());
                assert!(plan
                    .terms
                    .iter()
                    .zip(reference.terms())
                    .all(|((c, f), t)| *c == t.coefficient && *f == t.factors));
                assert_eq!(plan.terms.len(), reference.terms().len());
                assert_eq!(plan.factors.len(), reference.tables().count());
                for ((f, (x, r)), v) in plan
                    .factors
                    .into_iter()
                    .zip(reference.tables())
                    .zip(reference.vanishing())
                {
                    assert_eq!(f.mask.as_ref().map(|(_, v)| *v), v);
                    let ts = std::iter::once((f.values, x)).chain(f.mask.map(|(m, _)| (m, r)));
                    for (t, values) in ts {
                        input.extend([plan.len as u32, u32::from(t.base), t.spans.len() as u32]);
                        for s in t.spans {
                            input.extend([
                                s.period,
                                s.begin,
                                s.end,
                                s.op as u32,
                                s.arg,
                                s.shifts.len() as u32,
                                s.data.len() as u32,
                            ]);
                            input.extend(s.shifts);
                            input.extend(s.data);
                        }
                        for &x in values {
                            let limbs = words(x);
                            if t.base {
                                assert_eq!(&limbs[1..], &[0; 3]);
                            }
                            expected.extend_from_slice(if t.base { &limbs[..1] } else { &limbs });
                        }
                    }
                }
                Ok(())
            });
        }
        let code = format!("#include <cstdio>\n#include <vector>\n#define __device__\n#define __global__\n#define __forceinline__ inline\n{}\n#define GRID_STRIDE(i,n) for(u64 i=0;i<(n);++i)\n{}\n{}", crate::host_probe::helpers(), include_str!("gkr_build.cu"), include_str!("gkr_build_host.cuh"));
        let actual = crate::host_probe::run(&code, &input);
        assert_eq!(actual.len(), expected.len());
        assert_eq!(actual.iter().zip(expected).position(|(a, b)| *a != b), None);
    }

    #[test]
    fn accepts_gkr_peak_including_upload_and_promotion_overlap() {
        let table = |base, words| TablePlan {
            base,
            spans: vec![span(8, 0..8, Op::Constant, 1, vec![0; words]).unwrap()],
        };
        let mut plan = Plan {
            len: 8,
            degree: 2,
            terms: vec![(K::ONE, vec![0])],
            factors: vec![FactorPlan {
                values: table(false, 1),
                mask: Some((table(true, 0), 0)),
            }],
        };
        // A mask binding immediately is consumed without being promoted.
        let descriptors = 20 + 8 + 4 + 16 + 2 * 3 * 16;
        let first = plan.peak(1).unwrap();
        assert_eq!(first.construction, 128 + 32 + descriptors);
        assert_eq!(first.fold, first.construction);
        plan.factors[0].mask.as_mut().unwrap().1 = 2;
        assert_eq!(plan.peak(1).unwrap().fold, 128 + 32 + 64 + descriptors);
        // Staging for x is gone before the mask output or scratch is allocated.
        plan.factors[0].values.spans[0].data.resize(150, 0);
        assert_eq!(plan.peak(1).unwrap().construction, 128 + 600);
        // Live scheduling is sensitive to factor order. Releasing the first
        // x's base mask before a later promotion saves the mask's whole table.
        plan.factors[0].mask.as_mut().unwrap().1 = 0;
        plan.factors.push(FactorPlan {
            values: table(true, 0),
            mask: None,
        });
        let released = plan.peak(1).unwrap().fold;
        plan.factors.reverse();
        assert_eq!(plan.peak(1).unwrap().fold, released + 32);
    }

    #[test]
    fn accepts_only_complete_unmasked_cyclic_extension_blocks() {
        let make = |p| {
            TablePlan::single(span(8, 0..8, Op::Block, p, vec![0; 4 + 2 * p as usize]).unwrap())
        };
        assert_eq!(make(1).storage_len(16), 1);
        assert_eq!(make(8).storage_len(8), 8);
        let mut partial = make(2);
        partial.spans[0].end = 7;
        assert_eq!(partial.storage_len(16), 16);
        let mut wrong = make(2);
        wrong.base = true;
        assert_eq!(wrong.storage_len(16), 16);
        let mut plan = Plan {
            len: 16,
            degree: 2,
            terms: vec![],
            factors: vec![FactorPlan {
                values: make(2),
                mask: Some((make(2), 1)),
            }],
        };
        assert!(plan.peak(1).is_err());
        plan.factors[0].mask = None;
        assert!(plan.peak(1).is_ok());
    }

    #[test]
    fn matches_reference_large_t32_allocation_phases() {
        // Job 6781 steps 96/97: nine extension x tables and four delayed base
        // masks, followed by a leaf with a coordinate-zero base mask and one
        // delayed mask. Construct only field-width and lifetime metadata.
        let table = |base| TablePlan {
            base,
            spans: Vec::new(),
        };
        let factors = |masks: &[Option<usize>], base_indices: &[usize]| {
            masks
                .iter()
                .enumerate()
                .map(|(i, v)| FactorPlan {
                    values: table(base_indices.contains(&i)),
                    mask: v.map(|v| (table(true), v)),
                })
                .collect()
        };
        let mut p = Plan {
            len: 1 << 27,
            degree: 5,
            terms: Vec::new(),
            factors: factors(
                &[
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(1),
                    Some(1),
                    Some(2),
                    Some(2),
                ],
                &[],
            ),
        };
        let peak = p.peak(1024).unwrap();
        let fixed = 20 * p.factors.len() + 8 + 16 + 16 * 6 * 1025;
        assert_eq!(peak.construction, fixed + 160 * p.len);
        assert_eq!(peak.fold, fixed + 180 * p.len);
        p.len = 1 << 28;
        p.degree = 6;
        p.factors = factors(
            &[
                None,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
                Some(25),
                None,
            ],
            &[5, 6, 7, 8],
        );
        let peak = p.peak(1024).unwrap();
        let fixed = 20 * p.factors.len() + 8 + 16 + 16 * 7 * 1025;
        assert_eq!(peak.construction, fixed + 120 * p.len);
        assert_eq!(peak.fold, fixed + 140 * p.len);
    }

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

#[cfg(test)]
#[test]
fn accepts_origin_bound_column_and_rejects_wrong_gather_geometry() {
    use stele_reductions::zk::claims::bench::{GkrFactor, GkrMask};
    use stele_sumcheck::Term;
    let values = [K::ONE, K::ZERO];
    let input = GkrConstruction {
        num_vars: 2,
        layer_variables: 1,
        degree: 3,
        terms: vec![Term {
            coefficient: K::ONE,
            factors: vec![0],
        }],
        factors: vec![GkrFactor::Column {
            values: &values,
            coordinates: vec![1],
            mask: GkrMask {
                values: vec![M31::ONE, M31::ZERO],
                coordinates: &[1],
                vanishing: 0,
            },
        }],
    };
    let origin = [3, 0, 8, 4, 1, 2];
    let origins = vec![vec![Some(origin)]];
    let p = Plan::with_originals(&input, &origins).unwrap();
    let s = &p.factors[0].values.spans[0];
    assert!(matches!(s.op, Op::OriginalBase));
    assert!(s.data.is_empty());
    assert_eq!(s.original, Some(origin));
    assert!(matches!(
        p.factors[0].mask.as_ref().unwrap().0.spans[0].kind,
        InputKind::Mask
    ));
    assert!(Plan::with_originals(&input, &[]).is_err());
    for bad in [[3, 0, 8, 4, 1, 4], [3, 0, 8, 4, 7, 2], [3, 0, 8, 3, 1, 2]] {
        assert!(Plan::with_originals(&input, &[vec![Some(bad)]]).is_err());
    }
}

#[cfg(any(feature = "cuda", test))]
#[path = "gkr_private.rs"]
mod private;
