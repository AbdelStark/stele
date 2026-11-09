//! Attention: executor-equivalent honest values pass the plain checker, RFC-0026
//! §5.2 near misses built as an attacker would fail it, every constraint is needed
//! (mutation sweep), and realistic plans pass the bound rule.

use super::*;
use crate::development::{ConversionCapture, Policy, RowConversion};
use alloc::collections::BTreeMap;
use stele_cqis::bounds::arithmetic::Row;
use stele_cqis::functions::Descriptor as Function;
use stele_cqis::row::Quantiser;
use stele_ir::relation::{check, check_except, Range};

/// Deterministic test stream (xorshift64*); not a protocol RNG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
}

/// One layer configuration (Model block parameters plus shape).
#[derive(Clone, Debug)]
struct Cfg {
    rows: usize,
    heads: usize,
    groups: usize,
    head_width: usize,
    policy: [Policy; 3],
    score: (u16, i8),
    fractions: [u8; 4],
    accumulation: u8,
    drop: u8,
    /// `(mode, B, F, E, k)`; `k` ignored in mode 0.
    exp: (u8, u8, u8, u8, u8),
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            rows: 5,
            heads: 2,
            groups: 1,
            head_width: 4,
            policy: [Policy::Dynamic; 3],
            score: (181, -10),
            fractions: [8, 8, 8, 8],
            accumulation: 0,
            drop: 0,
            exp: (1, 15, 6, 8, 7),
        }
    }
}

impl Cfg {
    fn representation(&self) -> Representation {
        let (mode, b, f, e, k) = self.exp;
        let function = if mode == 1 {
            Function::new("exp_q/product", 1, &[b, f, e, k])
        } else {
            Function::new("exp_q/nearest", 1, &[b, f, e])
        }
        .expect("exp function");
        let params: &[u8] = if mode == 2 { &[k] } else { &[] };
        Representation::new(function, mode, params).expect("representation")
    }
}

/// Executor-equivalent exp (`Executor::exponential`), `None` outside the domain.
struct Exponential {
    mode: u8,
    p: [u8; 3],
    k: u8,
    maps: Vec<BTreeMap<i64, i64>>,
}

impl Exponential {
    fn new(r: &Representation) -> Self {
        let p = r.function().parameters();
        let maps = r
            .components()
            .iter()
            .map(|c| {
                let table = CqisTable::generate(*c).expect("table");
                table
                    .entries()
                    .chunks_exact(2)
                    .take(c.shape().rows() as usize)
                    .map(|row| (i64::from(row[0]), i64::from(row[1])))
                    .collect()
            })
            .collect();
        Self {
            mode: r.mode(),
            p: [p[0], p[1], p[2]],
            k: if r.mode() == 0 {
                0
            } else {
                r.components()[0].parameters()[3]
            },
            maps,
        }
    }

    fn eval(&self, t: i64) -> Option<i64> {
        if t > 0 || t < -(1i64 << self.p[0]) {
            return None;
        }
        if self.mode == 0 {
            return self.maps[0].get(&t).copied();
        }
        let n = -t;
        let high = self.maps[0][&(n >> self.k)];
        let low = self.maps[1][&(n % (1 << self.k))];
        let product = high * low / (1 << self.p[2]);
        Some(if self.mode == 2 {
            product + self.maps[2][&t]
        } else {
            product
        })
    }
}

/// `R(n * 2^shift / divisor)`, ties away from zero (`numerics::scaled_sum`).
fn round(n: i128, shift: i32, divisor: i128) -> i128 {
    let (num, den) = if shift >= 0 {
        (n.abs() << shift, divisor)
    } else {
        (n.abs(), divisor << (-shift))
    };
    n.signum() * ((2 * num + den) / (2 * den))
}

/// An executor quantity an attack replaces; downstream values then follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Dot,
    Score,
    Maximum,
    Exp,
    Normaliser,
    Block,
    Output,
}

/// `(stage, (i, head, key or lane), honest) -> attacked`.
type Tamper<'a> = &'a dyn Fn(Stage, (usize, usize, usize), i128) -> i128;

fn honest(_: Stage, _: (usize, usize, usize), v: i128) -> i128 {
    v
}

/// Executor-equivalent `Executor::attend` over every position (RFC-0025 §2.4),
/// `None` where the executor rejects; with a tamper, downstream follows the attacked
/// values and executor rejections are ignored.
fn reference(
    cfg: &Cfg,
    codes: &[Vec<Vec<i64>>; 3],
    scales: &[Vec<u32>; 3],
    tamper: Option<Tamper<'_>>,
) -> Option<Vec<PositionCapture>> {
    let strict = tamper.is_none();
    let tamper = tamper.unwrap_or(&honest);
    let exp = Exponential::new(&cfg.representation());
    let (n, h, dh) = (cfg.rows, cfg.heads, cfg.head_width);
    let r = h / cfg.groups;
    let [fq, fk, fv, fa] = cfg.fractions.map(i32::from);
    let e = i32::from(cfg.score.1) - fq - fk + i32::from(cfg.exp.2);
    let mut out = Vec::new();
    for i in 0..n {
        let mut pc = PositionCapture::default();
        for head in 0..h {
            let group = head / r;
            let mut scores = Vec::new();
            for j in 0..n {
                let dot: i64 = (0..dh)
                    .map(|c| codes[0][i][head * dh + c] * codes[1][j][group * dh + c])
                    .sum();
                let dot = tamper(Stage::Dot, (i, head, j), i128::from(dot)) as i64;
                let product = i128::from(dot)
                    * i128::from(scales[0][i])
                    * i128::from(scales[1][j])
                    * i128::from(cfg.score.0);
                let score = tamper(Stage::Score, (i, head, j), round(product, e, 1));
                if strict && score.unsigned_abs() >= 1 << 31 {
                    return None;
                }
                pc.dot.push(dot);
                pc.score.push(score as i64);
                scores.push(score as i64);
            }
            let maximum = *scores[..=i].iter().max()?;
            let maximum = tamper(Stage::Maximum, (i, head, 0), i128::from(maximum)) as i64;
            pc.maximum.push(maximum);
            let mut weights = vec![0i64; n];
            for j in 0..=i {
                let w = match exp.eval(scores[j] - maximum) {
                    Some(w) => w,
                    None if !strict => 0,
                    None => return None,
                };
                weights[j] = tamper(Stage::Exp, (i, head, j), i128::from(w)) as i64;
                pc.exp.push(weights[j]);
            }
            let z = tamper(
                Stage::Normaliser,
                (i, head, 0),
                i128::from(weights.iter().sum::<i64>()),
            );
            if strict && z <= 0 {
                return None;
            }
            pc.normaliser.push(z.max(0) as u128);
            for lane in 0..dh {
                let (mut total, mut partial) = (0i128, 0i128);
                for (j, weight) in weights.iter().enumerate() {
                    partial += i128::from(*weight)
                        * i128::from(scales[2][j])
                        * i128::from(codes[2][j][group * dh + lane]);
                    if cfg.accumulation == 1 && ((j + 1) % 1024 == 0 || j + 1 == n) {
                        let block = round(partial, -i32::from(cfg.drop), 1);
                        let block = tamper(Stage::Block, (i, head, lane), block);
                        if strict && !(-32768..=32767).contains(&block) {
                            return None;
                        }
                        pc.block.push(block as i64);
                        total += block;
                        partial = 0;
                    }
                }
                if cfg.accumulation == 0 {
                    total = partial;
                }
                let value = round(total, fa - fv + i32::from(cfg.drop), z.max(1));
                let value = tamper(Stage::Output, (i, head, lane), value);
                if strict && !(-32768..=32767).contains(&value) {
                    return None;
                }
                pc.total.push(total);
                pc.output.push(value as i64);
            }
        }
        out.push(pc);
    }
    Some(out)
}

/// Executor conversion of `inputs` (RFC-0025 §2.2).
fn convert(policy: Policy, inputs: &[Vec<i64>]) -> Option<ConversionCapture> {
    let (mode, scale) = match policy {
        Policy::Dynamic => (0, 0),
        Policy::Static(s) => (1, s),
        Policy::Grouped(g) => (2, g),
    };
    let quantiser = Quantiser::new(Row {
        dimension: inputs[0].len() as u16,
        kind: 0,
        fraction: 8,
        policy: mode,
        scale,
    })
    .expect("row parameters");
    let mut capture = ConversionCapture {
        inputs: inputs.to_vec(),
        ..ConversionCapture::default()
    };
    for row in inputs {
        let narrow: Vec<i16> = row.iter().map(|&v| v as i16).collect();
        let out = quantiser.convert_wide(&narrow).ok()?;
        capture
            .codes
            .push(out.codes().iter().map(|&c| i64::from(c)).collect());
        capture.scales.push(out.scales().to_vec());
    }
    Some(capture)
}

/// A complete case: Q/K/V int16 inputs, their row conversions, attention, and the
/// O-input row conversion of the attention output.
struct Case {
    cfg: Cfg,
    relation: Relation,
    values: Values,
    attention: Attention,
    inputs: Inputs,
}

/// Executor inputs of one case: conversions of random Q'/K'/V rows.
#[derive(Clone)]
struct Inputs {
    convs: Vec<ConversionCapture>,
    codes: [Vec<Vec<i64>>; 3],
    scales: [Vec<u32>; 3],
}

impl Case {
    fn column(&self, values: &Values, name: &str) -> Vec<i64> {
        values
            .get(&self.relation, self.id(name))
            .expect("column")
            .to_vec()
    }
    fn id(&self, name: &str) -> ColumnId {
        let full = format!("L0/attention/{name}");
        ColumnId(
            self.relation
                .columns
                .iter()
                .position(|c| c.name == full)
                .expect("column name") as u32,
        )
    }
    fn set(&self, values: &mut Values, name: &str, index: usize, v: i64) {
        let mut column = self.column(values, name);
        column[index] = v;
        values
            .set(&self.relation, self.id(name), column)
            .expect("set");
    }
    /// The attention assignment of a tampered executor run (downstream follows it).
    fn attacked(&self, tamper: Tamper<'_>) -> Values {
        let positions = reference(
            &self.cfg,
            &self.inputs.codes,
            &self.inputs.scales,
            Some(tamper),
        )
        .expect("attacked run");
        let capture = AttentionCapture {
            codes: self.inputs.codes.clone(),
            scales: self.inputs.scales.clone(),
            positions,
        };
        let mut values = self.values.clone();
        self.attention
            .assign(&self.relation, &capture, &mut values)
            .expect("attacked assign");
        values
    }
    /// S-domain index of `(j, head, i)`.
    fn s(&self, j: usize, head: usize, i: usize) -> usize {
        let b = self.attention.bits();
        j | (head << b.t) | (i << (b.t + b.hb))
    }
}

fn padded(rows: &[Vec<i64>], log_rows: u8, log_lanes: u8) -> Vec<i64> {
    let mut out = vec![0; 1 << (log_rows + log_lanes)];
    for (r, row) in rows.iter().enumerate() {
        for (i, v) in row.iter().enumerate() {
            out[(r << log_lanes) | i] = *v;
        }
    }
    out
}

/// Random int16 Q'/K'/V rows (mixed magnitudes, int16 endpoints) that the
/// executor-equivalent reference admits.
fn inputs(cfg: &Cfg, seed: u64) -> (Inputs, Vec<PositionCapture>) {
    let mut rng = Rng(seed);
    let widths = [
        cfg.heads * cfg.head_width,
        cfg.groups * cfg.head_width,
        cfg.groups * cfg.head_width,
    ];
    (0..200)
        .find_map(|attempt| {
            let convs: Vec<ConversionCapture> = (0..3)
                .map(|k| {
                    let peak = [32767, 4000, 300, 0, 20000, 100][(attempt / 6 + attempt * k) % 6];
                    let rows: Vec<Vec<i64>> = (0..cfg.rows)
                        .map(|row| {
                            let peak = if row % 4 == 3 { peak / 7 } else { peak };
                            (0..widths[k]).map(|_| rng.range(-peak, peak)).collect()
                        })
                        .collect();
                    convert(cfg.policy[k], &rows)
                })
                .collect::<Option<_>>()?;
            let codes = [0, 1, 2].map(|k| convs[k].codes.clone());
            let scales = [0, 1, 2].map(|k| convs[k].scales.iter().map(|s| s[0]).collect());
            let positions = reference(cfg, &codes, &scales, None)?;
            Some((
                Inputs {
                    convs,
                    codes,
                    scales,
                },
                positions,
            ))
        })
        .expect("an executor-admitted case")
}

/// Declare the conversions, attention and the O-input conversion; assign honestly.
fn case(cfg: &Cfg, seed: u64) -> Case {
    case_with(cfg, seed, true)
}

/// As [`case`]; `o` adds the downstream O-input conversion (left out of the deletion
/// survey, which isolates this module's constraints).
fn case_with(cfg: &Cfg, seed: u64, o: bool) -> Case {
    let (inputs, positions) = inputs(cfg, seed);
    build(cfg, inputs, positions, o)
}

/// Declare and assign a case from executor inputs and attention captures.
fn build(cfg: &Cfg, inputs: Inputs, positions: Vec<PositionCapture>, o: bool) -> Case {
    let widths = [
        cfg.heads * cfg.head_width,
        cfg.groups * cfg.head_width,
        cfg.groups * cfg.head_width,
    ];
    let mut relation = Relation::default();
    let t = log2_ceil(cfg.rows);
    let mut columns = Vec::new();
    let mut conversions = Vec::new();
    for (k, name) in ["q", "k", "v"].iter().enumerate() {
        let lanes = log2_ceil(widths[k]);
        let group = relation.add_group(&format!("L0/{name}/input/{}", t + lanes), t + lanes);
        let input = relation.add_column(name, Kind::Witness(group), Width::signed(16), t + lanes);
        relation.ranges.push(Range {
            name: (*name).into(),
            column: input,
            width: Width::signed(16),
        });
        let mut conv = RowConversion::new(
            &format!("L0/{name}"),
            input,
            cfg.rows,
            widths[k],
            cfg.policy[k],
        )
        .expect("conversion");
        conv.declare(&mut relation);
        columns.push((input, lanes));
        conversions.push(conv);
    }
    let plan = AttentionPlan {
        rows: cfg.rows,
        heads: cfg.heads,
        groups: cfg.groups,
        head_width: cfg.head_width,
        query: conversions[0].output().expect("q"),
        key: conversions[1].output().expect("k"),
        value: conversions[2].output().expect("v"),
        score_multiplier: cfg.score,
        fractions: cfg.fractions,
        accumulation: cfg.accumulation,
        drop: cfg.drop,
        exponential: cfg.representation(),
    };
    let mut attention = Attention::new(0, plan).expect("plan");
    attention.declare(&mut relation);
    // Head assembly: the output column is the O-input row conversion's input.
    let mut o_conv = o.then(|| {
        RowConversion::new(
            "L0/o",
            attention.output().expect("output"),
            cfg.rows,
            widths[0],
            Policy::Dynamic,
        )
        .expect("o conversion")
    });
    if let Some(conv) = o_conv.as_mut() {
        conv.declare(&mut relation);
    }
    let mut values = Values::new(&relation);
    for (((input, lanes), conv), capture) in columns.iter().zip(&conversions).zip(&inputs.convs) {
        values
            .set(&relation, *input, padded(&capture.inputs, t, *lanes))
            .expect("input");
        conv.assign(&relation, capture, &mut values)
            .expect("conversion");
    }
    let capture = AttentionCapture {
        codes: inputs.codes.clone(),
        scales: inputs.scales.clone(),
        positions: positions.clone(),
    };
    attention
        .assign(&relation, &capture, &mut values)
        .expect("assign");
    let rows: Vec<Vec<i64>> = positions.iter().map(|p| p.output.clone()).collect();
    if let Some(conv) = &o_conv {
        let o_capture = convert(Policy::Dynamic, &rows).expect("o conversion");
        conv.assign(&relation, &o_capture, &mut values)
            .expect("o assign");
    }
    Case {
        cfg: cfg.clone(),
        relation,
        values,
        attention,
        inputs,
    }
}

fn configs() -> Vec<(&'static str, Cfg)> {
    let base = Cfg::default();
    vec![
        ("product", base.clone()),
        (
            "direct",
            Cfg {
                exp: (0, 15, 6, 8, 0),
                ..base.clone()
            },
        ),
        (
            "corrected",
            Cfg {
                exp: (2, 15, 6, 8, 7),
                ..base.clone()
            },
        ),
        (
            "mha-static",
            Cfg {
                heads: 2,
                groups: 2,
                policy: [Policy::Static(17), Policy::Static(3), Policy::Static(130)],
                ..base.clone()
            },
        ),
        (
            "block",
            Cfg {
                accumulation: 1,
                drop: 17,
                fractions: [8, 8, 8, 7],
                ..base.clone()
            },
        ),
        (
            "negative-e2",
            Cfg {
                fractions: [8, 8, 9, 6],
                ..base.clone()
            },
        ),
        (
            "positive-e",
            Cfg {
                score: (1, 6),
                fractions: [3, 3, 8, 8],
                policy: [Policy::Static(1), Policy::Static(1), Policy::Dynamic],
                exp: (1, 20, 0, 6, 8),
                head_width: 2,
                ..base.clone()
            },
        ),
        (
            "gqa-4",
            Cfg {
                rows: 3,
                heads: 4,
                groups: 1,
                head_width: 2,
                ..base
            },
        ),
    ]
}

fn small(exp: (u8, u8, u8, u8, u8)) -> Cfg {
    Cfg {
        rows: 3,
        heads: 2,
        groups: 1,
        head_width: 2,
        exp,
        ..Cfg::default()
    }
}

#[test]
fn accepts_honest_executor_values() {
    for (name, cfg) in configs() {
        for seed in 1..4 {
            let case = case(&cfg, seed);
            assert_eq!(
                check(&case.relation, &case.values),
                Ok(()),
                "{name} seed {seed}"
            );
        }
    }
}

// ---- Attacker assignments -------------------------------------------------------

/// Every Compose of this module: parents from limbs (`true`) or limbs from parents.
fn recompose(case: &Case, values: &mut Values, from_limbs: bool) {
    for compose in &case.relation.composes {
        if !compose.name.starts_with("L0/attention") {
            continue;
        }
        let get = |v: &Values, id: ColumnId| v.get(&case.relation, id).expect("c").to_vec();
        if from_limbs {
            let mut parent = vec![0i64; get(values, compose.column).len()];
            for &(limb, shift) in &compose.limbs {
                for (p, l) in parent.iter_mut().zip(get(values, limb)) {
                    *p += l << shift;
                }
            }
            values
                .set(&case.relation, compose.column, parent)
                .expect("p");
        } else {
            let parent = get(values, compose.column);
            let last = compose.limbs.len() - 1;
            for (k, &(limb, shift)) in compose.limbs.iter().enumerate() {
                let column = parent
                    .iter()
                    .map(|v| {
                        let y = v >> shift;
                        if k == last {
                            y
                        } else {
                            y & ((1 << (compose.limbs[k + 1].1 - shift)) - 1)
                        }
                    })
                    .collect();
                values.set(&case.relation, limb, column).expect("l");
            }
        }
    }
}

/// The remainder-like limbs that absorb a chain's residual, as an attacker chooses.
fn absorber(chain: &str) -> Option<&'static str> {
    Some(match chain {
        "score/scales" => "score/scales",
        "score/round" => "score/remainder",
        "value/weight" => "value/weight",
        "total/sign" => "total/magnitude",
        "block/round" => "block/remainder",
        "output/split" => "output/low",
        "output/division" => "output/remainder",
        "output/spare" => "output/spare",
        _ => return None,
    })
}

/// Byte limbs `prefix/0..` of this module, low first.
fn byte_ids(case: &Case, prefix: &str) -> Vec<ColumnId> {
    (0..)
        .map_while(|i| {
            let full = format!("L0/attention/{prefix}/{i}");
            case.relation
                .columns
                .iter()
                .position(|c| c.name == full)
                .map(|p| ColumnId(p as u32))
        })
        .collect()
}

/// Value of a chain's identity `sum 256^k E_k` at `x`, carries excluded.
fn chain_value(case: &Case, values: &Values, chain: &Chain, x: usize) -> i128 {
    let mut total = 0i128;
    for (k, terms) in chain.positions.iter().enumerate() {
        for t in terms {
            let mut p = t.coeff as i128;
            for f in &t.factors {
                p *= values.get(&case.relation, f.column).expect("c")[f.index(x as u64)] as i128;
            }
            total += p << (8 * k);
        }
    }
    total
}

fn set_bytes(case: &Case, values: &mut Values, ids: &[ColumnId], v: &[i128]) {
    let last = ids.len() - 1;
    for (i, id) in ids.iter().enumerate() {
        let column = v
            .iter()
            .map(|v| {
                let y = v >> (8 * i);
                (if i == last { y } else { y & 255 }) as i64
            })
            .collect();
        values.set(&case.relation, *id, column).expect("bytes");
    }
}

/// The attacker's repair: each chain's residual goes into its remainder-like limbs
/// (the output division re-divides, so `q`, `r` and the output follow the
/// numerator when `redivide`), compositions follow their limbs, and carries are refilled. The chain
/// `skip` (a deleted position's) is left to the caller.
fn rebalance_except(case: &Case, values: &mut Values, skip: Option<&str>, redivide: bool) {
    let columns = case.attention.columns.as_ref().expect("declared");
    let mut split_done = false;
    for (name, chain) in &columns.chains {
        if Some(*name) == skip {
            continue;
        }
        let size = 1usize << chain.vars;
        if redivide && (*name == "output/split" || (*name == "output/division" && !split_done)) {
            split_done = true;
            rederive_numerator(case, values);
        }
        if redivide && *name == "block/round" {
            let qs = case.id("block/quotient");
            let rs = byte_ids(case, "block/remainder");
            let mut zeroed = values.clone();
            zeroed.set(&case.relation, qs, vec![0; size]).expect("z");
            set_bytes(case, &mut zeroed, &rs, &vec![0; size]);
            let c = u32::from(case.cfg.drop);
            let num: Vec<i128> = (0..size)
                .map(|x| chain_value(case, &zeroed, chain, x))
                .collect();
            values
                .set(
                    &case.relation,
                    qs,
                    num.iter().map(|v| (v >> c) as i64).collect(),
                )
                .expect("qb");
            if !rs.is_empty() {
                let low: Vec<i128> = num.iter().map(|v| v & ((1 << c) - 1)).collect();
                set_bytes(case, values, &rs, &low);
            }
            // Only a moved quotient moves B (an attacker leaves the rest honest).
            if case.column(values, "block/quotient") != case.column(&case.values, "block/quotient")
            {
                rederive_block(case, values);
            }
            continue;
        }
        if redivide && *name == "output/split" {
            let ids = [byte_ids(case, "output/high"), byte_ids(case, "output/low")];
            let mut zeroed = values.clone();
            for id in ids.iter().flatten() {
                zeroed.set(&case.relation, *id, vec![0; size]).expect("z");
            }
            zeroed
                .set(&case.relation, case.id("output/bit"), vec![0; size])
                .expect("z");
            let j = -(i32::from(case.cfg.fractions[3]) - i32::from(case.cfg.fractions[2])
                + i32::from(case.cfg.drop));
            let num: Vec<i128> = (0..size)
                .map(|x| chain_value(case, &zeroed, chain, x))
                .collect();
            if !ids[0].is_empty() {
                set_bytes(
                    case,
                    values,
                    &ids[0],
                    &num.iter().map(|v| v >> j).collect::<Vec<_>>(),
                );
            }
            if !ids[1].is_empty() {
                let low: Vec<i128> = num.iter().map(|v| v & ((1 << (j - 1)) - 1)).collect();
                set_bytes(case, values, &ids[1], &low);
            }
            let bit = num.iter().map(|v| ((v >> (j - 1)) & 1) as i64).collect();
            values
                .set(&case.relation, case.id("output/bit"), bit)
                .expect("bit");
            continue;
        }
        if redivide && *name == "output/division" {
            let (qs, rs, zs) = (
                byte_ids(case, "output/quotient/byte"),
                byte_ids(case, "output/remainder"),
                byte_ids(case, "normaliser/byte"),
            );
            let mut zeroed = values.clone();
            set_bytes(case, &mut zeroed, &qs, &vec![0; size]);
            set_bytes(case, &mut zeroed, &rs, &vec![0; size]);
            let tau = if case
                .relation
                .columns
                .iter()
                .any(|c| c.name == "L0/attention/block/sign")
            {
                case.column(values, "block/sign")
            } else {
                case.column(values, "total/sign")
            };
            let b = case.attention.bits();
            let (mut q, mut r) = (vec![0i128; size], vec![0i128; size]);
            let mut output = vec![0i64; size];
            for x in 0..size {
                let numerator = chain_value(case, &zeroed, chain, x);
                let z: i128 = zs
                    .iter()
                    .enumerate()
                    .map(|(i, id)| {
                        (values.get(&case.relation, *id).expect("z")[x >> b.d] as i128) << (8 * i)
                    })
                    .sum();
                if z > 0 {
                    q[x] = numerator.div_euclid(2 * z);
                    r[x] = numerator.rem_euclid(2 * z);
                } else {
                    r[x] = numerator;
                }
                output[x] = (q[x] * (1 - 2 * tau[x] as i128)) as i64;
            }
            set_bytes(case, values, &qs, &q);
            set_bytes(case, values, &rs, &r);
            values
                .set(&case.relation, case.id("output"), output)
                .expect("o");
            recompose(case, values, true);
            continue;
        }
        let Some(prefix) = absorber(name) else {
            continue;
        };
        let ids = byte_ids(case, prefix);
        if ids.is_empty() {
            continue;
        }
        let sign = (*name == "total/sign").then(|| case.column(values, "total/sign"));
        let mut absorbed = vec![0i128; size];
        for (x, a) in absorbed.iter_mut().enumerate() {
            let total = chain_value(case, values, chain, x);
            let limbs: i128 = ids
                .iter()
                .enumerate()
                .map(|(i, id)| (values.get(&case.relation, *id).expect("l")[x] as i128) << (8 * i))
                .sum();
            let flip = sign.as_ref().map_or(1, |s| 1 - 2 * s[x] as i128);
            *a = limbs + total * flip;
        }
        set_bytes(case, values, &ids, &absorbed);
        recompose(case, values, true);
    }
    for (name, chain) in &columns.chains {
        if Some(*name) != skip {
            chain
                .assign_around(&case.relation, values, None)
                .expect("carries");
        }
    }
}

/// `B = (1-2sigma)*qB` (block mode).
fn rederive_block(case: &Case, values: &mut Values) {
    let qb = case.column(values, "block/quotient");
    let sigma = case.column(values, "total/sign");
    let block: Vec<i64> = qb
        .iter()
        .zip(&sigma)
        .map(|(q, s)| q * (1 - 2 * s))
        .collect();
    values
        .set(&case.relation, case.id("block"), block)
        .expect("b");
}

/// Block mode: `tau`, `|T|` from `T = B` (one block).
fn rederive_numerator(case: &Case, values: &mut Values) {
    if case.cfg.accumulation != 1 {
        return;
    }
    let block = case.column(values, "block");
    if block == case.column(&case.values, "block") {
        return;
    }
    values
        .set(
            &case.relation,
            case.id("block/sign"),
            block.iter().map(|v| i64::from(*v < 0)).collect(),
        )
        .expect("tau");
    values
        .set(
            &case.relation,
            case.id("block/magnitude"),
            block.iter().map(|v| v.abs()).collect(),
        )
        .expect("nt");
    recompose(case, values, false);
}

fn rebalance(case: &Case, values: &mut Values) {
    rebalance_except(case, values, None, false);
}

/// Executor runs with one quantity off by one, downstream following it; each with
/// the strongest repair (remainders absorb residuals, carries refilled).
fn semantic(case: &Case) -> Vec<(String, Values)> {
    let n = case.cfg.rows;
    let i = n - 1;
    let mut out = Vec::new();
    let mut push = |name: String, mut v: Values| {
        rebalance(case, &mut v);
        out.push((name, v));
    };
    for d in [1i128, -1] {
        push(
            format!("score{d:+}"),
            case.attacked(&move |s, k, v| v + d * i128::from(s == Stage::Score && k == (i, 0, 0))),
        );
        push(
            format!("masked dot{d:+}"),
            case.attacked(&move |s, k, v| {
                v + d * i128::from(s == Stage::Dot && k == (0, 0, n - 1))
            }),
        );
        push(
            format!("masked score{d:+}"),
            case.attacked(&move |s, k, v| {
                v + d * i128::from(s == Stage::Score && k == (0, 0, n - 1))
            }),
        );
        push(
            format!("exp{d:+}"),
            case.attacked(&move |s, k, v| v + d * i128::from(s == Stage::Exp && k == (i, 0, 0))),
        );
        push(
            format!("normaliser{d:+}"),
            case.attacked(&move |s, k, v| {
                v + d * i128::from(s == Stage::Normaliser && k == (i, 0, 0))
            }),
        );
        push(
            format!("output{d:+}"),
            case.attacked(&move |s, k, v| v + d * i128::from(s == Stage::Output && k == (i, 0, 0))),
        );
        if case.cfg.accumulation == 1 {
            push(
                format!("block{d:+}"),
                case.attacked(&move |s, k, v| {
                    v + d * i128::from(s == Stage::Block && k == (i, 0, 0))
                }),
            );
        }
        // Maximum off by one; for +1 the one-hot still marks the true argmax.
        let mut v = case
            .attacked(&move |s, k, v| v + d * i128::from(s == Stage::Maximum && k == (i, 0, 0)));
        let scores = &case.reference_scores();
        let top = (0..=i)
            .max_by_key(|&j| (scores[j], core::cmp::Reverse(j)))
            .unwrap_or(0);
        case.set(&mut v, "maximum/hit", case.s(top, 0, i), 1);
        push(format!("maximum{d:+}"), v);
    }
    // exp + 1 with a looked-up value moved to absorb it (H, L or C off its table).
    if case.cfg.exp.0 != 0 {
        let x = case.s(0, 0, i);
        let e = case.cfg.exp.3;
        let attacked = case.attacked(&|s, k, v| v + i128::from(s == Stage::Exp && k == (i, 0, 0)));
        let at = |v: &Values, name: &str| case.column(v, name)[x];
        let target = at(&attacked, "exp/p")
            - if case.cfg.exp.0 == 2 {
                at(&attacked, "exp/c")
            } else {
                0
            };
        for (moved, other) in [("exp/high", "exp/low"), ("exp/low", "exp/high")] {
            let mut v = attacked.clone();
            let o = at(&v, other);
            if o > 0 {
                let m = ((target << e) + o - 1) / o;
                case.set(&mut v, moved, x, m);
                case.set(&mut v, "exp/rr", x, m * o - (target << e));
                rebalance(case, &mut v);
                out.push((format!("exp+1 absorbed by {moved}"), v));
            }
        }
        if case.cfg.exp.0 == 2 {
            let mut v = attacked.clone();
            let c = at(&v, "exp/c");
            case.set(&mut v, "exp/c", x, c + 1);
            case.set(&mut v, "exp/rr", x, at(&case.values, "exp/rr"));
            rebalance(case, &mut v);
            out.push(("exp+1 absorbed by the correction".into(), v));
        }
    }
    // Z bytes moved off the matmul's Z (the normaliser column stays honest).
    let mut v = case.attacked(&|s, k, v| v + i128::from(s == Stage::Normaliser && k == (i, 0, 0)));
    rebalance(case, &mut v);
    let honest = case.column(&case.values, "normaliser");
    v.set(&case.relation, case.id("normaliser"), honest)
        .expect("z");
    out.push(("normaliser bytes+1 under the honest Z".into(), v));
    // A nonzero output on a padded row (Z = 0 there), q and o moved together.
    let b = case.attention.bits();
    if n < 1 << b.t {
        let x = n << (b.d + b.hb);
        let mut v = case.values.clone();
        case.set(&mut v, "output/quotient/byte/0", x, 1);
        case.set(&mut v, "output/quotient", x, 1);
        case.set(&mut v, "output", x, 1);
        out.push(("padded-row output 1".into(), v));
    }
    out
}

impl Case {
    /// Honest scores of `(i = n-1, head 0)` over every key.
    fn reference_scores(&self) -> Vec<i64> {
        let positions =
            reference(&self.cfg, &self.inputs.codes, &self.inputs.scales, None).expect("honest");
        positions[self.cfg.rows - 1].score[..self.cfg.rows].to_vec()
    }
}

/// Constraint kinds of a relation, for the mutation sweep.
#[derive(Clone, Copy, Debug)]
enum Item {
    Identity(usize),
    Lookup(usize),
    Range(usize),
    Matmul(usize),
    Compose(usize),
}

fn items(relation: &Relation) -> Vec<(Item, String, Vec<ColumnId>)> {
    let mine = |n: &str| n.starts_with("L0/attention");
    let mut out = Vec::new();
    for (k, x) in relation.identities.iter().enumerate() {
        let cols = x
            .terms
            .iter()
            .flat_map(|t| t.factors.iter().map(|f| f.column))
            .collect();
        out.push((Item::Identity(k), x.name.clone(), cols));
    }
    for (k, x) in relation.lookups.iter().enumerate() {
        out.push((
            Item::Lookup(k),
            x.name.clone(),
            x.tuple.iter().map(|f| f.column).collect(),
        ));
    }
    for (k, x) in relation.ranges.iter().enumerate() {
        out.push((Item::Range(k), x.name.clone(), vec![x.column]));
    }
    for (k, x) in relation.matmuls.iter().enumerate() {
        let cols = vec![x.out.column, x.lhs.column, x.rhs.column];
        out.push((Item::Matmul(k), x.name.clone(), cols));
    }
    for (k, x) in relation.composes.iter().enumerate() {
        let mut cols = vec![x.column];
        cols.extend(x.limbs.iter().map(|l| l.0));
        out.push((Item::Compose(k), x.name.clone(), cols));
    }
    out.retain(|(_, name, _)| mine(name));
    out
}

fn without(relation: &Relation, item: Item) -> Relation {
    let mut r = relation.clone();
    match item {
        Item::Identity(k) => {
            r.identities.remove(k);
        }
        Item::Lookup(k) => {
            r.lookups.remove(k);
        }
        Item::Range(k) => {
            r.ranges.remove(k);
        }
        Item::Matmul(k) => {
            r.matmuls.remove(k);
        }
        Item::Compose(k) => {
            r.composes.remove(k);
        }
    }
    r
}

/// Single-entry attacker edits of the constraint's own columns, with each repair.
fn local<'a>(case: &'a Case, columns: &[ColumnId]) -> impl Iterator<Item = (String, Values)> + 'a {
    let ids: Vec<ColumnId> = columns
        .iter()
        .copied()
        .filter(|id| {
            let c = &case.relation.columns[id.0 as usize];
            c.name.starts_with("L0/attention") && !matches!(c.kind, Kind::Public(_))
        })
        .collect();
    ids.into_iter().flat_map(move |id| {
        let len = 1usize << case.relation.columns[id.0 as usize].log_len;
        let stride = len.div_ceil(48).max(1);
        (0..len).step_by(stride).flat_map(move |x| {
            [1i64, -1, 2, -2, 256, -256, 1 << 16, -(1 << 16)]
                .into_iter()
                .flat_map(move |d| {
                    (0..6).map(move |repair| {
                        let mut v = case.values.clone();
                        let mut column = v.get(&case.relation, id).expect("c").to_vec();
                        column[x] += d;
                        v.set(&case.relation, id, column).expect("s");
                        match repair {
                            1 => rebalance(case, &mut v),
                            2 => {
                                recompose(case, &mut v, false);
                                rebalance(case, &mut v);
                            }
                            3 => recompose(case, &mut v, true),
                            4 => {
                                recompose(case, &mut v, false);
                                rebalance_except(case, &mut v, None, true);
                            }
                            5 => rebalance_except(case, &mut v, None, true),
                            _ => {}
                        }
                        let name = &case.relation.columns[id.0 as usize].name;
                        (format!("{name}[{x}]{d:+} repair {repair}"), v)
                    })
                })
        })
    })
}

/// Carries of `chain` with position `k` left free: forward below it, backward above.
fn fill_around(case: &Case, values: &mut Values, chain: &Chain, k: usize) -> Option<()> {
    chain.assign_around(&case.relation, values, Some(k)).ok()
}

/// For a deleted chain position `k`: move one entry of a column at that position by
/// +-1 and let the carries around `k` absorb it.
fn around(case: &Case, name: &str) -> Option<String> {
    let columns = case.attention.columns.as_ref().expect("declared");
    let rest = name.strip_prefix("L0/attention/")?;
    let (chain_name, k) = rest.rsplit_once('/')?;
    let k: usize = k.parse().ok()?;
    let chain = &columns.chains.iter().find(|(n, _)| *n == chain_name)?.1;
    // A primary moved by a multiple of 256^k that only position k sees.
    let primary = match chain_name {
        "total/sign" => Some(("total/magnitude", 8 * k)),
        "block/round" => Some(("block/quotient", 8 * k)),
        _ => None,
    };
    if let Some((column, bit)) = primary {
        let offset = if column == "block/quotient" {
            bit.checked_sub(usize::from(case.cfg.drop))
        } else {
            Some(0)
        };
        for x in 0..1usize << chain.vars {
            for d in [1i128, -1] {
                let Some(offset) = offset else { break };
                let mut v = case.values.clone();
                let ids = byte_ids(case, column);
                let delta = d
                    << if column == "block/quotient" {
                        offset
                    } else {
                        bit
                    };
                if ids.is_empty() {
                    let mut c = case.column(&v, column);
                    c[x] += delta as i64;
                    v.set(&case.relation, case.id(column), c).expect("s");
                } else {
                    let mut value: Vec<i128> = (0..1usize << chain.vars)
                        .map(|y| {
                            ids.iter()
                                .enumerate()
                                .map(|(i, id)| {
                                    (v.get(&case.relation, *id).expect("b")[y] as i128) << (8 * i)
                                })
                                .sum()
                        })
                        .collect();
                    value[x] += delta;
                    set_bytes(case, &mut v, &ids, &value);
                }
                recompose(case, &mut v, true);
                if column == "block/quotient" {
                    rederive_block(case, &mut v);
                }
                rebalance_except(case, &mut v, Some(chain_name), true);
                if fill_around(case, &mut v, chain, k).is_some()
                    && check_except(&case.relation, &v, &[name]).is_ok()
                    && check(&case.relation, &v).is_err()
                {
                    return Some(format!(
                        "{column}[{x}] moved by {delta}, carries around {k}"
                    ));
                }
            }
        }
    }
    // The division re-solved for a numerator off by 256^k.
    if chain_name == "output/division" {
        let (qs, rs, zs) = (
            byte_ids(case, "output/quotient/byte"),
            byte_ids(case, "output/remainder"),
            byte_ids(case, "normaliser/byte"),
        );
        let size = 1usize << chain.vars;
        let b = case.attention.bits();
        let tau = if case.cfg.accumulation == 1 {
            case.column(&case.values, "block/sign")
        } else {
            case.column(&case.values, "total/sign")
        };
        let mut zeroed = case.values.clone();
        set_bytes(case, &mut zeroed, &qs, &vec![0; size]);
        set_bytes(case, &mut zeroed, &rs, &vec![0; size]);
        for x in 0..size {
            let z: i128 = zs
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    (case.values.get(&case.relation, *id).expect("z")[x >> b.d] as i128) << (8 * i)
                })
                .sum();
            if z == 0 {
                continue;
            }
            for d in [1i128, -1] {
                let numerator = chain_value(case, &zeroed, chain, x) - (d << (8 * k));
                let mut v = case.values.clone();
                let read = |v: &Values, ids: &[ColumnId]| -> Vec<i128> {
                    (0..size)
                        .map(|y| {
                            ids.iter()
                                .enumerate()
                                .map(|(i, id)| {
                                    (v.get(&case.relation, *id).expect("b")[y] as i128) << (8 * i)
                                })
                                .sum()
                        })
                        .collect()
                };
                let (mut q, mut r) = (read(&v, &qs), read(&v, &rs));
                q[x] = numerator.div_euclid(2 * z);
                r[x] = numerator.rem_euclid(2 * z);
                set_bytes(case, &mut v, &qs, &q);
                set_bytes(case, &mut v, &rs, &r);
                case.set(
                    &mut v,
                    "output",
                    x,
                    (q[x] * (1 - 2 * tau[x] as i128)) as i64,
                );
                recompose(case, &mut v, true);
                rebalance_except(case, &mut v, Some(chain_name), false);
                if fill_around(case, &mut v, chain, k).is_some()
                    && check_except(&case.relation, &v, &[name]).is_ok()
                    && check(&case.relation, &v).is_err()
                {
                    return Some(format!(
                        "output[{x}] re-divided off by 256^{k}, carries around {k}"
                    ));
                }
            }
        }
    }
    for t in &chain.positions[k] {
        for f in &t.factors {
            let c = &case.relation.columns[f.column.0 as usize];
            if !c.name.starts_with("L0/attention") || matches!(c.kind, Kind::Public(_)) {
                continue;
            }
            let len = 1usize << c.log_len;
            for x in (0..len).step_by(len.div_ceil(48).max(1)) {
                for d in [1i64, -1] {
                    let mut v = case.values.clone();
                    let mut column = v.get(&case.relation, f.column).expect("c").to_vec();
                    column[x] += d;
                    v.set(&case.relation, f.column, column).expect("s");
                    recompose(case, &mut v, true);
                    rebalance_except(case, &mut v, Some(chain_name), true);
                    if fill_around(case, &mut v, chain, k).is_some()
                        && check_except(&case.relation, &v, &[name]).is_ok()
                        && check(&case.relation, &v).is_err()
                    {
                        return Some(format!("{}[{x}]{d:+}, carries around {k}", c.name));
                    }
                }
            }
        }
    }
    None
}

/// Limb carry shifts that keep every composed value: `limb_i += 2^w`, `limb_(i+1) -= 1`
/// (and back), for byte families `x/i`, `x/i+1` and 16-bit splits `x/lo`, `x/hi`.
fn shifts<'a>(case: &'a Case, columns: &[ColumnId]) -> impl Iterator<Item = (String, Values)> + 'a {
    let find = |name: &str| {
        case.relation
            .columns
            .iter()
            .position(|c| c.name == name)
            .map(|p| ColumnId(p as u32))
    };
    let mut pairs = Vec::new();
    for id in columns {
        let name = case.relation.columns[id.0 as usize].name.clone();
        if let Some(base) = name
            .strip_suffix("/lo")
            .or_else(|| name.strip_suffix("/hi"))
        {
            if let (Some(lo), Some(hi)) = (find(&format!("{base}/lo")), find(&format!("{base}/hi")))
            {
                pairs.push((lo, hi, 1i64 << 16));
            }
        }
        if name.ends_with("output/bit") {
            if let (Some(bit), Some(high)) = (Some(*id), find("L0/attention/output/high/0")) {
                pairs.push((bit, high, 2));
            }
        }
        if let Some((base, i)) = name.rsplit_once('/') {
            if let Ok(i) = i.parse::<usize>() {
                for (a, b) in [(i.wrapping_sub(1), i), (i, i + 1)] {
                    if let (Some(lo), Some(hi)) =
                        (find(&format!("{base}/{a}")), find(&format!("{base}/{b}")))
                    {
                        pairs.push((lo, hi, 256));
                    }
                }
            }
        }
    }
    pairs.into_iter().flat_map(move |(lo, hi, w)| {
        let len = 1usize << case.relation.columns[lo.0 as usize].log_len;
        (0..len).flat_map(move |x| {
            [1i64, -1].into_iter().map(move |d| {
                let mut v = case.values.clone();
                for (id, delta) in [(lo, d * w), (hi, -d)] {
                    let mut column = v.get(&case.relation, id).expect("c").to_vec();
                    column[x] += delta;
                    v.set(&case.relation, id, column).expect("s");
                }
                for (_, chain) in &case.attention.columns.as_ref().expect("declared").chains {
                    chain
                        .assign_around(&case.relation, &mut v, None)
                        .expect("carries");
                }
                let name = &case.relation.columns[lo.0 as usize].name;
                (
                    format!("{name}[{x}] {:+} with its next limb {:+}", d * w, -d),
                    v,
                )
            })
        })
    })
}

/// Why a constraint with no over-Z attacker witness is still required. Each is also
/// rejected statically: its deletion leaves a column undisciplined (RFC-0026 §3.6).
fn redundant(name: &str) -> &'static str {
    let name = name
        .trim_start_matches("L0/attention/")
        .trim_end_matches("/range");
    if name.contains("/carry") {
        "a carry is fixed over Z by its positions' values; its range keeps the position identity below p (bound rule)"
    } else if ["output", "block", "block/quotient"].contains(&name) {
        "int16/u16 executor range (`wide`); test inputs never reach it, a reachable overflow is exactly an executor Range rejection"
    } else if name == "exp/slack" {
        "u <= 2^B (executor ExpDomain); reachable only for score spreads past 2^B, which admitted test inputs never have"
    } else if ["exp/p", "exp/masked", "exp/rr"].contains(&name) {
        "the value is fixed over Z by exp/product (or its lookup) and exp/masked; the width feeds the bound rule"
    } else {
        "a top or sole limb whose value is fixed over Z by its composition or producer (|dot|, sq*sk, Q, Pm*sv, |T|, Z, q, r + s, Mx, B); the width feeds the bound rule"
    }
}

/// For every constraint of the module: deleting it admits an attacker assignment
/// that the full relation rejects (or makes the relation statically invalid).
fn sweep(case: &Case) -> Vec<(String, String)> {
    let semantic = semantic(case);
    for (name, v) in &semantic {
        assert!(check(&case.relation, v).is_err(), "{name} accepted");
    }
    let mut table = Vec::new();
    for (item, name, columns) in items(&case.relation) {
        let mutant = without(&case.relation, item);
        let killer = semantic
            .iter()
            .find(|(_, v)| check_except(&case.relation, v, &[name.as_str()]).is_ok())
            .map(|(n, _)| n.clone())
            .or_else(|| around(case, &name))
            .or_else(|| {
                local(case, &columns)
                    .chain(shifts(case, &columns))
                    .find(|(_, v)| {
                        check_except(&case.relation, v, &[name.as_str()]).is_ok()
                            && check(&case.relation, v).is_err()
                    })
                    .map(|(n, _)| n)
            })
            .or_else(|| {
                mutant
                    .validate()
                    .err()
                    .map(|e| format!("static: {e:?}; {}", redundant(&name)))
            });
        table.push((
            format!("{item:?} {name}"),
            killer.unwrap_or_else(|| "SURVIVED".into()),
        ));
    }
    table
}

#[test]
fn rejects_every_constraint_deletion() {
    let configs = [
        ("product", small((1, 7, 2, 12, 3))),
        ("direct", small((0, 7, 2, 12, 0))),
        ("corrected", small((2, 7, 2, 12, 3))),
        (
            "block",
            Cfg {
                accumulation: 1,
                drop: 18,
                fractions: [8, 8, 8, 7],
                ..small((1, 7, 2, 12, 3))
            },
        ),
        (
            "negative-e2",
            Cfg {
                fractions: [8, 8, 20, 8],
                policy: [Policy::Static(17), Policy::Dynamic, Policy::Static(3)],
                ..small((1, 7, 2, 12, 3))
            },
        ),
    ];
    let mut survived = Vec::new();
    for (label, cfg) in configs {
        let case = case_with(&cfg, 7, false);
        for (constraint, killer) in sweep(&case) {
            extern crate std;
            std::println!("| {label} | `{constraint}` | {killer} |");
            if killer == "SURVIVED" {
                survived.push(format!("{label}: {constraint}"));
            }
        }
    }
    assert!(survived.is_empty(), "constraints not needed: {survived:#?}");
}

// ---- RFC-0026 §5.2 near misses ------------------------------------------------

#[test]
fn rejects_near_miss_outputs() {
    for (name, cfg) in configs() {
        let case = case(&cfg, 3);
        for (attack, values) in semantic(&case) {
            assert!(
                check(&case.relation, &values).is_err(),
                "{name}: {attack} accepted"
            );
        }
    }
}

#[test]
fn rejects_score_other_rounding_direction() {
    // e = -20: the score is R(N/2^20); floor and ceil differ from it by at most one,
    // and whichever differs is a +-1 near miss, rejected by the remainder range.
    let case = case(&Cfg::default(), 5);
    let x = case.s(0, 0, case.cfg.rows - 1);
    let remainder = case.column(&case.values, "score/quotient");
    let q = remainder[x];
    for other in [q - 1, q + 1] {
        let mut v = case.values.clone();
        case.set(&mut v, "score/quotient", x, other);
        for (k, byte) in [other & 255, other >> 8, other >> 16].iter().enumerate() {
            if case
                .relation
                .columns
                .iter()
                .any(|c| c.name == format!("L0/attention/score/quotient/byte/{k}"))
            {
                case.set(&mut v, &format!("score/quotient/byte/{k}"), x, *byte);
            }
        }
        rebalance(&case, &mut v);
        assert!(matches!(
            check(&case.relation, &v),
            Err(Violation::Range { .. })
        ));
    }
}

// ---- Static validity ----------------------------------------------------------

/// Declare attention for a shape with stand-in row conversions and validate.
fn validate_shape(
    rows: usize,
    heads: usize,
    groups: usize,
    dh: usize,
    cfg: &Cfg,
) -> Result<(), Invalid> {
    let mut relation = Relation::default();
    let t = log2_ceil(rows);
    let mut outs = Vec::new();
    for (k, name) in ["q", "k", "v"].iter().enumerate() {
        let width = if k == 0 { heads * dh } else { groups * dh };
        let lanes = log2_ceil(width);
        let group = relation.add_group(&format!("in/{name}"), t + lanes);
        let input = relation.add_column(name, Kind::Witness(group), Width::signed(16), t + lanes);
        relation.ranges.push(Range {
            name: (*name).into(),
            column: input,
            width: Width::signed(16),
        });
        let mut conv =
            RowConversion::new(&format!("L0/{name}"), input, rows, width, Policy::Dynamic)
                .expect("conversion");
        conv.declare(&mut relation);
        outs.push(conv.output().expect("output"));
    }
    let plan = AttentionPlan {
        rows,
        heads,
        groups,
        head_width: dh,
        query: outs[0],
        key: outs[1],
        value: outs[2],
        score_multiplier: cfg.score,
        fractions: cfg.fractions,
        accumulation: cfg.accumulation,
        drop: cfg.drop,
        exponential: cfg.representation(),
    };
    let mut attention = Attention::new(0, plan).map_err(|_| Invalid::Shape {
        relation: "unsupported".into(),
    })?;
    attention.declare(&mut relation);
    relation.validate()
}

#[test]
fn accepts_static_validity_realistic_shapes() {
    // Llama-style scores: m = 181, e_score = -14 (1/sqrt(dh) * 2^-6.5), F = 6.
    let llama = Cfg {
        score: (181, -14),
        fractions: [8, 8, 8, 8],
        exp: (1, 14, 6, 12, 7),
        ..Cfg::default()
    };
    let block = Cfg {
        accumulation: 1,
        drop: 20,
        fractions: [8, 8, 8, 0],
        ..llama.clone()
    };
    let corrected = Cfg {
        exp: (2, 14, 6, 12, 7),
        ..llama.clone()
    };
    // E16-10 target (d = 512, h = 8, dh = 64) and GQA variants.
    for (rows, heads, groups, dh, cfg) in [
        (64, 8, 8, 64, &llama),
        (128, 8, 8, 64, &llama),
        (128, 8, 2, 64, &corrected),
        (128, 8, 8, 64, &block),
        (1024, 8, 8, 64, &llama),
        (512, 8, 2, 128, &llama),
    ] {
        assert_eq!(
            validate_shape(rows, heads, groups, dh, cfg),
            Ok(()),
            "{rows} {heads} {groups} {dh}"
        );
    }
}

#[test]
fn rejects_unsupported_plans_before_declaring() {
    let cfg = Cfg::default();
    // Past MAX_VARS without a row-block split (T = 1024, 32 heads, dh = 128).
    assert!(validate_shape(1024, 32, 8, 128, &cfg).is_err());
    // Non-power-of-two GQA ratio.
    assert!(validate_shape(8, 3, 1, 4, &cfg).is_err());
}

// ---- Executor capture on the fixture corpora ----------------------------------

/// `"key":{"offset":a,"length":b}` of one fixture case.
fn span(case: &str, key: &str) -> (usize, usize) {
    let at = case
        .find(&format!("\"{key}\":{{\"offset\":"))
        .expect("span")
        + key.len()
        + 13;
    let rest = &case[at..];
    let offset: usize = rest[..rest.find(',').expect(",")].parse().expect("offset");
    let rest = &rest[rest.find("\"length\":").expect("length") + 9..];
    let length = rest[..rest.find('}').expect("}")].parse().expect("length");
    (offset, length)
}

#[test]
fn matches_reference_executor_capture_on_fixtures() {
    use stele_cqis::execution::capture::Block;
    use stele_cqis::execution::Executor;
    use stele_cqis::model::{Model, Preparation, Scales};
    let corpora: [(&str, &[u8]); 2] = [
        (
            include_str!("../../../../stele-cqis/tests/fixtures/model-execution.json"),
            include_bytes!("../../../../stele-cqis/tests/fixtures/model-execution.bin"),
        ),
        (
            include_str!("../../../../stele-cqis/tests/fixtures/grouped-rows.json"),
            include_bytes!("../../../../stele-cqis/tests/fixtures/grouped-rows.bin"),
        ),
    ];
    let (mut checked, mut modes) = (0, [0usize; 3]);
    for (json, raw) in corpora {
        for case_json in json.split("{\"model\":").skip(1) {
            let case_json = format!("\"model\":{case_json}");
            let bytes = |key: &str| {
                let (o, l) = span(&case_json, key);
                &raw[o..o + l]
            };
            let id = &case_json[case_json.find("\"artifact_id\":\"").expect("id") + 15..][..64];
            let mut digest = [0u8; 32];
            for (k, d) in digest.iter_mut().enumerate() {
                *d = u8::from_str_radix(&id[2 * k..2 * k + 2], 16).expect("hex");
            }
            let tokens: Vec<u32> = {
                let t = &case_json[case_json.find("\"tokens\":[").expect("tokens") + 10..];
                t[..t.find(']').expect("]")]
                    .split(',')
                    .map(|v| v.trim().parse().expect("token"))
                    .collect()
            };
            let model = Model::decode(bytes("model")).expect("Model");
            if model.shape().family() != 1 {
                continue;
            }
            let prep = Preparation::decode(&model, bytes("preparation")).expect("Preparation");
            let scales = Scales::decode(&model, bytes("scales")).expect("Scales");
            let mut ex = Executor::new(&model, &prep, &scales, bytes("artifact"), &digest, 1 << 30)
                .expect("executor");
            let Ok(capture) = ex.capture(&tokens) else {
                continue;
            };
            let s = model.shape();
            let (h, g, dh) = (
                usize::from(s.heads()),
                usize::from(s.groups()),
                usize::from(s.head_width()),
            );
            for (layer, block) in model.blocks().iter().enumerate() {
                let positions = &capture.blocks[layer];
                let policy = |k: usize| match block.policies()[k] {
                    p if p.mode() == 1 => Policy::Static(p.scale()),
                    _ => Policy::Dynamic,
                };
                let f = block.projection_fractions();
                let r = block.exponential();
                let p = r.function().parameters();
                let k = if r.mode() == 0 {
                    0
                } else {
                    r.components()[0].parameters()[3]
                };
                let cfg = Cfg {
                    rows: tokens.len(),
                    heads: h,
                    groups: g,
                    head_width: dh,
                    policy: [policy(1), policy(2), policy(3)],
                    score: block.score_multiplier(),
                    fractions: [f[0], f[1], f[2], block.attention_fraction()],
                    accumulation: block.accumulation(),
                    drop: block.drop(),
                    exp: (r.mode(), p[0], p[1], p[2], k),
                };
                let rows: [fn(&Block) -> &stele_cqis::execution::capture::Quantised; 3] =
                    [|p| &p.query_row, |p| &p.key_row, |p| &p.value_row];
                let convs: Vec<ConversionCapture> = rows
                    .iter()
                    .map(|row| ConversionCapture {
                        inputs: positions.iter().map(|p| row(p).input.clone()).collect(),
                        codes: positions.iter().map(|p| row(p).codes.clone()).collect(),
                        scales: positions.iter().map(|p| row(p).scales.clone()).collect(),
                    })
                    .collect();
                let inputs = Inputs {
                    codes: [0, 1, 2].map(|k| convs[k].codes.clone()),
                    scales: [0, 1, 2].map(|k| convs[k].scales.iter().map(|s| s[0]).collect()),
                    convs,
                };
                let attention: Vec<PositionCapture> = positions
                    .iter()
                    .map(|p| PositionCapture::from(&p.attention))
                    .collect();
                // The executor-equivalent reference used elsewhere matches the capture.
                assert_eq!(
                    reference(&cfg, &inputs.codes, &inputs.scales, None).as_ref(),
                    Some(&attention),
                    "reference parity, layer {layer}"
                );
                let case = build(&cfg, inputs, attention, false);
                assert_eq!(check(&case.relation, &case.values), Ok(()), "layer {layer}");
                modes[usize::from(cfg.exp.0)] += 1;
                checked += 1;
            }
        }
    }
    assert!(
        checked > 10 && modes.iter().all(|m| *m > 0),
        "{checked} {modes:?}"
    );
}
