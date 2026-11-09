//! Task E16-03: the prefill capture against `full` and independent re-derivation
//! of every recorded column, over every executor fixture corpus.
use super::{
    capture::{Division, Lookup, Norm, Projection, Quantised, Rounding},
    Capture, Executor,
};
use crate::{
    functions::Representation,
    model::{Model, Preparation, Role, Scales},
    tables::{Descriptor, Table},
};
use alloc::{collections::BTreeMap, vec::Vec};

const CORPORA: [(&str, &[u8]); 3] = [
    (
        include_str!("../../tests/fixtures/model-execution.json"),
        include_bytes!("../../tests/fixtures/model-execution.bin"),
    ),
    (
        include_str!("../../tests/fixtures/wide-residual.json"),
        include_bytes!("../../tests/fixtures/wide-residual.bin"),
    ),
    (
        include_str!("../../tests/fixtures/grouped-rows.json"),
        include_bytes!("../../tests/fixtures/grouped-rows.bin"),
    ),
];

/// Independent (n, d) for R((l*2^le + r*2^re)/divisor).
fn aligned(l: i128, le: i32, r: i128, re: i32, divisor: u64) -> (i128, u128) {
    let sh = 0.max(-le).max(-re);
    (
        (l << (le + sh)) + (r << (re + sh)),
        u128::from(divisor) << sh,
    )
}

fn division(d: &Division) {
    let n = d.numerator.len();
    assert!([d.divisor.len(), d.quotient.len(), d.remainder.len()] == [n; 3]);
    for i in 0..n {
        let (num, div, q, r) = (d.numerator[i], d.divisor[i], d.quotient[i], d.remainder[i]);
        if div == 0 {
            assert_eq!((num, q, r), (0, 0, 0), "canonical zero branch");
            continue;
        }
        let div = i128::try_from(div).expect("divisor");
        assert_eq!(num, i128::from(q) * div + r, "n = q*d + r");
        match d.rounding {
            Rounding::Nearest => {
                let expected = (2 * num.abs() + div) / (2 * div);
                assert_eq!(i128::from(q), num.signum() * expected, "nearest");
                assert!(2 * r.abs() <= div);
            }
            Rounding::Floor => assert!(num >= 0 && (0..div).contains(&r), "floor"),
            Rounding::Ceil => assert!(num >= 0 && r <= 0 && -r < div, "ceil"),
        }
    }
}

#[derive(Default)]
struct Tables(Vec<(Descriptor, BTreeMap<i64, i64>)>);
impl Tables {
    fn check(&mut self, d: Descriptor, lookup: &Lookup) {
        assert_eq!(lookup.input.len(), lookup.output.len());
        if !self.0.iter().any(|(old, _)| *old == d) {
            let table = Table::generate(d).expect("table");
            let mut map = BTreeMap::new();
            for row in table.entries().chunks_exact(2) {
                map.entry(i64::from(row[0])).or_insert(i64::from(row[1]));
            }
            self.0.push((d, map));
        }
        let map = &self.0.iter().find(|(old, _)| *old == d).expect("table").1;
        for (t, v) in lookup.input.iter().zip(&lookup.output) {
            assert_eq!(map.get(t), Some(v), "table[index]");
        }
    }
}

fn values(raw: &[i64]) -> Vec<i64> {
    raw.to_vec()
}
fn quotient(d: &Division) -> &[i64] {
    &d.quotient
}

struct Checker<'e, 'a> {
    ex: &'e Executor<'a>,
    tables: Tables,
}
impl Checker<'_, '_> {
    fn norm(
        &mut self,
        r: &Representation,
        n: &Norm,
        input: &[i64],
        role: Role,
        layer: Option<u16>,
    ) {
        let data = &self.ex.data;
        assert_eq!(n.input, input, "norm input is the producer's output");
        let g = data.ordinal(role, layer).expect("gain");
        for (j, h) in n.gain.iter().enumerate() {
            assert_eq!(*h, i64::from(data.code(g, j)));
        }
        let p = r.function().parameters();
        let d = input.len() as i128;
        let squares: i128 = input.iter().map(|x| i128::from(*x).pow(2)).sum();
        assert_eq!(i128::from(n.squares), squares);
        let rms = data.model.shape().family() == 1;
        let (en, ed, unit, statistic) = if rms {
            let word =
                |i: usize| u128::from(u32::from_le_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]));
            assert_eq!((n.sum, n.variance), (0, n.squares));
            assert!(n.bias.is_empty());
            (word(5), word(9), (d as u128) << (2 * p[2]), n.squares)
        } else {
            let word =
                |i: usize| u128::from(u32::from_le_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]));
            let sum: i64 = input.iter().sum();
            assert_eq!(n.sum, sum);
            assert_eq!(i128::from(n.variance), d * squares - i128::from(sum).pow(2));
            (
                word(6),
                word(10),
                ((d * d) as u128) << (2 * p[2]),
                n.variance,
            )
        };
        assert_eq!(n.ratio, (ed * u128::from(statistic) + en * unit, ed * unit));
        let a = n.exponent;
        assert_eq!(n.mantissa.rounding, Rounding::Floor);
        assert_eq!(
            n.mantissa.numerator,
            [(n.ratio.0 as i128) << (2 * (-a).max(0))]
        );
        assert_eq!(n.mantissa.divisor, [n.ratio.1 << (2 * a.max(0))]);
        assert!((16384..65536).contains(&n.mantissa.quotient[0]));
        division(&n.mantissa);
        assert_eq!(n.reciprocal.input, n.mantissa.quotient);
        self.tables.check(
            Descriptor::new("rsqrt_q", 1, &[]).expect("rsqrt"),
            &n.reciprocal,
        );
        let e = i32::from(p[2]) + i32::from(p[3]) + 21 + a - i32::from(p[4]);
        assert_eq!(n.shift, e);
        let j = i128::from(n.reciprocal.output[0]);
        let bias = if rms {
            Vec::new()
        } else {
            let b = data
                .ordinal(
                    match role {
                        Role::FirstGain => Role::FirstBias,
                        Role::SecondGain => Role::SecondBias,
                        _ => Role::FinalBias,
                    },
                    layer,
                )
                .expect("bias");
            (0..input.len())
                .map(|i| i64::from(data.code(b, i)))
                .collect()
        };
        assert_eq!(n.bias, bias);
        for (i, x) in input.iter().enumerate() {
            let centered = if rms { *x } else { d as i64 * x - n.sum };
            assert_eq!(n.centered[i], centered);
            let product = i128::from(centered) * i128::from(n.gain[i]) * j;
            assert_eq!(n.product[i], product);
            let (num, div) = if rms {
                (product << (-e).max(0), 1u128 << e.max(0))
            } else {
                aligned(
                    product,
                    -e,
                    d * i128::from(bias[i]),
                    i32::from(p[4]) - i32::from(p[5]),
                    d as u64,
                )
            };
            assert_eq!((n.output.numerator[i], n.output.divisor[i]), (num, div));
        }
        assert_eq!(n.output.quotient.len(), input.len());
        division(&n.output);
    }
    fn quantised(&self, q: &Quantised, input: &[i64], q_index: Option<(usize, usize)>) {
        assert_eq!(q.input, input, "row input is the producer's output");
        let p = match q_index {
            Some((layer, i)) => self.ex.quantisers[layer][i].parameters(),
            None => self.ex.final_quantiser.parameters(),
        };
        let g = if p.policy == 2 {
            p.scale as usize
        } else {
            usize::from(p.dimension)
        };
        assert_eq!(q.scales.len(), input.len() / g);
        if p.policy == 1 {
            assert_eq!(q.scales, [p.scale]);
            assert!(q.scale.numerator.is_empty());
        } else {
            assert_eq!(q.scale.rounding, Rounding::Ceil);
            for (k, group) in input.chunks(g).enumerate() {
                let m = group.iter().map(|v| v.abs()).max().unwrap_or(0);
                assert_eq!(q.scale.numerator[k], i128::from(m));
                assert_eq!(q.scale.divisor[k], 127);
                assert_eq!(q.scale.quotient[k], i64::from(q.scales[k]));
            }
            division(&q.scale);
        }
        if p.policy == 0 {
            let m = input.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
            let first = input
                .iter()
                .position(|v| v.unsigned_abs() == m)
                .unwrap_or(0);
            let expected = if m == 0 {
                (0, 0)
            } else {
                (first as u16, m as u32)
            };
            assert_eq!(q.maximum, Some(expected));
        }
        assert_eq!(q.magnitude.rounding, Rounding::Floor);
        for (i, x) in input.iter().enumerate() {
            let s = i128::from(q.scales[i / g]);
            let n = if s == 0 {
                0
            } else {
                2 * i128::from(x.abs()) + s
            };
            assert_eq!(q.magnitude.numerator[i], n);
            assert_eq!(q.magnitude.divisor[i], 2 * s as u128);
            assert!(q.codes[i].abs() <= 127);
            assert_eq!(q.codes[i], x.signum() * q.magnitude.quotient[i]);
        }
        division(&q.magnitude);
    }
    fn projection(
        &self,
        p: &Projection,
        role: Role,
        layer: Option<u16>,
        input: &Quantised,
        input_fraction: u8,
        fraction: u8,
    ) {
        let data = &self.ex.data;
        let ordinal = data.ordinal(role, layer).expect("weights");
        let scale = data.scales.matrix(ordinal as u16).expect("scale");
        let family = data.model.shape().family();
        let bias = if family == 1 || role == Role::Head {
            None
        } else {
            Some(
                data.ordinal(
                    match role {
                        Role::Query => Role::QueryBias,
                        Role::Key => Role::KeyBias,
                        Role::Value => Role::ValueBias,
                        Role::Output => Role::OutputBias,
                        Role::Up => Role::UpBias,
                        _ => Role::DownBias,
                    },
                    layer,
                )
                .expect("bias"),
            )
        };
        let fb = bias.map_or(0, |i| data.model.formats()[i].parameter());
        let columns = input.codes.len();
        let g = columns / input.scales.len();
        let shift = i32::from(scale.exponent()) - i32::from(input_fraction) + i32::from(fraction);
        for j in 0..p.accumulator.len() {
            let mut acc = 0i128;
            for (k, x) in input.codes.iter().enumerate() {
                let w = i128::from(data.code(ordinal, j * columns + k));
                let s = if input.scales.len() > 1 {
                    i128::from(input.scales[k / g])
                } else {
                    1
                };
                acc += s * i128::from(*x) * w;
            }
            assert_eq!(p.accumulator[j], acc, "accumulator");
            let mut product = acc * i128::from(scale.mantissas()[j]);
            if input.scales.len() == 1 {
                product *= i128::from(input.scales[0]);
            }
            assert_eq!(p.product[j], product);
            let b = bias.map_or(0, |i| data.code(i, j));
            assert_eq!(p.bias[j], i64::from(b));
            let (n, d) = aligned(
                product,
                shift,
                i128::from(b),
                i32::from(fraction) - i32::from(fb),
                1,
            );
            assert_eq!((p.output.numerator[j], p.output.divisor[j]), (n, d));
        }
        assert_eq!(p.output.quotient.len(), p.accumulator.len());
        division(&p.output);
    }
    fn residual(&self, d: &Division, x: &[i64], fx: u8, y: &[i64], fy: u8, fo: u8) {
        for (i, (a, b)) in x.iter().zip(y).enumerate() {
            let (n, div) = aligned(
                i128::from(*a),
                i32::from(fo) - i32::from(fx),
                i128::from(*b),
                i32::from(fo) - i32::from(fy),
                1,
            );
            assert_eq!((d.numerator[i], d.divisor[i]), (n, div));
        }
        assert_eq!(d.quotient.len(), x.len());
        division(d);
    }
    fn exponential(&mut self, r: &Representation, e: &super::capture::Exponential) {
        let c = r.components();
        assert_eq!(e.components.len(), c.len());
        for (d, lookup) in c.iter().zip(&e.components) {
            self.tables.check(*d, lookup);
        }
        let p = r.function().parameters();
        for (i, t) in e.input.iter().enumerate() {
            let value = if r.mode() == 0 {
                assert_eq!(e.components[0].input[i], *t);
                e.components[0].output[i]
            } else {
                let k = c[0].parameters()[3];
                assert_eq!(e.components[0].input[i], -t >> k);
                assert_eq!(e.components[1].input[i], -t % (1 << k));
                let (h, l) = (e.components[0].output[i], e.components[1].output[i]);
                assert_eq!(
                    (e.product.numerator[i], e.product.divisor[i]),
                    (i128::from(h * l), 1u128 << p[2])
                );
                let mut v = e.product.quotient[i];
                if r.mode() == 2 {
                    assert_eq!(e.components[2].input[i], *t);
                    v += e.components[2].output[i];
                }
                v
            };
            assert_eq!(e.output[i], value);
        }
        assert_eq!(e.product.rounding, Rounding::Floor);
        division(&e.product);
    }
}

fn check(ex: &Executor<'_>, tokens: &[u32], w: &Capture) {
    let mut c = Checker {
        ex,
        tables: Tables::default(),
    };
    let model = ex.data.model;
    let s = model.shape();
    let full = w.full();
    let (width, hw) = (usize::from(s.width()), usize::from(s.head_width()));
    // Embedding: R_0.
    let t = ex.data.ordinal(Role::Token, None).expect("token");
    let ts = ex.data.scales.matrix(t as u16).expect("scale");
    let f0 = i32::from(model.initial_fraction());
    for (position, (e, token)) in w.embedding.iter().zip(tokens).enumerate() {
        assert_eq!(e.token, *token);
        let pos = (s.family() == 0).then(|| {
            let i = ex.data.ordinal(Role::Position, None).expect("position");
            (i, ex.data.scales.matrix(i as u16).expect("scale"))
        });
        for k in 0..width {
            let left = i128::from(ex.data.code(t, *token as usize * width + k))
                * i128::from(ts.mantissas()[*token as usize]);
            let (right, pe) = pos.map_or((0, 0), |(i, ps)| {
                (
                    i128::from(ex.data.code(i, position * width + k))
                        * i128::from(ps.mantissas()[position]),
                    i32::from(ps.exponent()),
                )
            });
            assert_eq!((e.token_term[k], e.position_term[k]), (left, right));
            let (n, d) = aligned(left, i32::from(ts.exponent()) + f0, right, pe + f0, 1);
            assert_eq!((e.output.numerator[k], e.output.divisor[k]), (n, d));
        }
        division(&e.output);
        let cut: Vec<i64> = full.cuts()[0][position]
            .iter()
            .map(|v| i64::from(*v))
            .collect();
        assert_eq!(e.output.quotient, cut);
    }
    for (layer, positions) in w.blocks.iter().enumerate() {
        let b = &model.blocks()[layer];
        let f = b.projection_fractions();
        let l = Some(layer as u16);
        let qf = |i: usize| ex.quantisers[layer][i].parameters().fraction;
        let incoming = if layer == 0 {
            model.initial_fraction()
        } else {
            model.blocks()[layer - 1].output_fraction()
        };
        for (position, x) in positions.iter().enumerate() {
            let cut = |i: usize| -> Vec<i64> {
                full.cuts()[i][position]
                    .iter()
                    .map(|v| i64::from(*v))
                    .collect()
            };
            c.norm(
                b.first_norm(),
                &x.first_norm,
                &cut(layer),
                Role::FirstGain,
                l,
            );
            c.quantised(
                &x.first_row,
                quotient(&x.first_norm.output),
                Some((layer, 0)),
            );
            c.projection(&x.query, Role::Query, l, &x.first_row, qf(0), f[0]);
            c.projection(&x.key, Role::Key, l, &x.first_row, qf(0), f[1]);
            c.projection(&x.value, Role::Value, l, &x.first_row, qf(0), f[2]);
            for (rot, p, heads) in [
                (&x.query_rotation, &x.query, s.heads()),
                (&x.key_rotation, &x.key, s.groups()),
            ] {
                let input = quotient(&p.output);
                let mut out = values(input);
                if let Some(r) = b.rotation() {
                    let half = usize::from(r.width() / 2);
                    assert_eq!(rot.pair.len(), half);
                    for (i, j) in rot.pair.iter().enumerate() {
                        assert_eq!(*j as usize, i);
                        let (cs, sn) = r
                            .coefficient(position as u32, *j as u16)
                            .expect("coefficient");
                        assert_eq!((rot.cos[i], rot.sin[i]), (i64::from(cs), i64::from(sn)));
                        for h in 0..usize::from(heads) {
                            let e = i * usize::from(heads) + h;
                            let left = h * hw + if r.layout() == 0 { 2 * i } else { i };
                            let right = left + if r.layout() == 0 { 1 } else { half };
                            assert_eq!((rot.left[e], rot.right[e]), (left as u32, right as u32));
                            let (xv, yv) = (i128::from(input[left]), i128::from(input[right]));
                            let (cv, sv) = (i128::from(cs), i128::from(sn));
                            assert_eq!(rot.rounding.numerator[2 * e], xv * cv - yv * sv);
                            assert_eq!(rot.rounding.numerator[2 * e + 1], xv * sv + yv * cv);
                            assert_eq!(rot.rounding.divisor[2 * e], 16384);
                            out[left] = rot.rounding.quotient[2 * e];
                            out[right] = rot.rounding.quotient[2 * e + 1];
                        }
                    }
                    division(&rot.rounding);
                } else {
                    assert!(rot.pair.is_empty() && rot.rounding.numerator.is_empty());
                }
                assert_eq!(rot.output, out);
            }
            c.quantised(&x.query_row, &x.query_rotation.output, Some((layer, 1)));
            c.quantised(&x.key_row, &x.key_rotation.output, Some((layer, 2)));
            c.quantised(&x.value_row, quotient(&x.value.output), Some((layer, 3)));
            // The cache holds exactly the captured K/V rows.
            let (k, v) = &full.cache().layers()[layer][position];
            for (row, q) in [(k, &x.key_row), (v, &x.value_row)] {
                let codes: Vec<i64> = row.codes().iter().map(|v| i64::from(*v)).collect();
                assert_eq!((codes, row.scales()), (q.codes.clone(), &q.scales[..]));
            }
            // Attention.
            let a = &x.attention;
            let ep = b.exponential().function().parameters();
            let (m, me) = b.score_multiplier();
            let shift = i32::from(me) - i32::from(f[0]) - i32::from(f[1]) + i32::from(ep[1]);
            let (heads, n) = (usize::from(s.heads()), positions.len());
            let group = |h: usize| h / (heads / usize::from(s.groups()));
            let mut exp_at = 0;
            let mut block_at = 0;
            for h in 0..heads {
                let mut scores = Vec::new();
                for (key, kx) in positions.iter().enumerate() {
                    let qc = &x.query_row.codes[h * hw..(h + 1) * hw];
                    let kc = &kx.key_row.codes[group(h) * hw..(group(h) + 1) * hw];
                    let dot: i64 = qc.iter().zip(kc).map(|(a, b)| a * b).sum();
                    let e = h * n + key;
                    assert_eq!(a.dot[e], dot);
                    let product = i128::from(dot)
                        * i128::from(x.query_row.scales[0])
                        * i128::from(kx.key_row.scales[0])
                        * i128::from(m);
                    let (num, d) = aligned(product, shift, 0, 0, 1);
                    assert_eq!((a.score.numerator[e], a.score.divisor[e]), (num, d));
                    scores.push(a.score.quotient[e]);
                }
                let maximum = *scores[..=position].iter().max().expect("max");
                assert_eq!(a.maximum[h], maximum);
                let weights: Vec<i64> = (0..n)
                    .map(|key| {
                        if key <= position {
                            assert_eq!(a.exp.input[exp_at + key], scores[key] - maximum);
                            a.exp.output[exp_at + key]
                        } else {
                            0
                        }
                    })
                    .collect();
                exp_at += position + 1;
                let z: i64 = weights.iter().sum();
                assert_eq!(a.normaliser[h], z as u128);
                for lane in 0..hw {
                    let (mut total, mut partial) = (0i128, 0i128);
                    for (key, kx) in positions.iter().enumerate() {
                        partial += i128::from(weights[key])
                            * i128::from(kx.value_row.scales[0])
                            * i128::from(kx.value_row.codes[group(h) * hw + lane]);
                        if b.accumulation() == 1 && ((key + 1) % 1024 == 0 || key + 1 == n) {
                            assert_eq!(a.block.numerator[block_at], partial);
                            assert_eq!(a.block.divisor[block_at], 1u128 << b.drop());
                            total += i128::from(a.block.quotient[block_at]);
                            block_at += 1;
                            partial = 0;
                        }
                    }
                    if b.accumulation() == 0 {
                        total = partial;
                    }
                    let e = h * hw + lane;
                    assert_eq!(a.total[e], total);
                    let exponent =
                        i32::from(b.attention_fraction()) - i32::from(f[2]) + i32::from(b.drop());
                    let (num, d) = aligned(total, exponent, 0, 0, z as u64);
                    assert_eq!((a.output.numerator[e], a.output.divisor[e]), (num, d));
                }
            }
            assert_eq!(
                (exp_at, block_at),
                (a.exp.input.len(), a.block.numerator.len())
            );
            c.exponential(b.exponential(), &a.exp);
            for d in [&a.score, &a.block, &a.output] {
                division(d);
            }
            c.quantised(&x.attention_row, quotient(&a.output), Some((layer, 4)));
            c.projection(&x.output, Role::Output, l, &x.attention_row, qf(4), f[3]);
            c.residual(
                &x.mid,
                &cut(layer),
                incoming,
                quotient(&x.output.output),
                f[3],
                b.mid_fraction(),
            );
            c.norm(
                b.second_norm(),
                &x.second_norm,
                quotient(&x.mid),
                Role::SecondGain,
                l,
            );
            c.quantised(
                &x.second_row,
                quotient(&x.second_norm.output),
                Some((layer, 5)),
            );
            c.projection(&x.up, Role::Up, l, &x.second_row, qf(5), f[4]);
            let up = quotient(&x.up.output);
            let table = b.activation().components()[0];
            c.tables.check(table, &x.activation);
            if s.family() == 1 {
                c.projection(&x.gate, Role::Gate, l, &x.second_row, qf(5), f[5]);
                assert_eq!(x.activation.input, x.gate.output.quotient);
                let gated: Vec<i64> = up
                    .iter()
                    .zip(&x.activation.output)
                    .map(|(u, a)| u * a)
                    .collect();
                assert_eq!(x.gated, gated);
                c.quantised(&x.down_row, &gated, Some((layer, 6)));
            } else {
                assert_eq!(x.activation.input, up);
                assert!(x.gate.accumulator.is_empty() && x.gated.is_empty());
                c.quantised(&x.down_row, &x.activation.output, Some((layer, 6)));
            }
            let df = *f.last().expect("down fraction");
            c.projection(&x.down, Role::Down, l, &x.down_row, qf(6), df);
            c.residual(
                &x.residual,
                quotient(&x.mid),
                b.mid_fraction(),
                quotient(&x.down.output),
                df,
                b.output_fraction(),
            );
            assert_eq!(
                x.residual.quotient,
                cut(layer + 1),
                "block output is the cut"
            );
        }
    }
    for (position, h) in w.head.iter().enumerate() {
        let last: Vec<i64> = full.cuts()[model.blocks().len()][position]
            .iter()
            .map(|v| i64::from(*v))
            .collect();
        c.norm(model.final_norm(), &h.norm, &last, Role::FinalGain, None);
        c.quantised(&h.row, quotient(&h.norm.output), None);
        let f = ex.final_quantiser.parameters().fraction;
        c.projection(
            &h.logits,
            Role::Head,
            None,
            &h.row,
            f,
            model.logits_fraction(),
        );
        let logits: Vec<i64> = full.logits()[position]
            .iter()
            .map(|v| i64::from(*v))
            .collect();
        assert_eq!(h.logits.output.quotient, logits);
        let maximum = *logits.iter().max().expect("logits");
        assert_eq!(h.maximum, maximum);
        assert_eq!(logits[h.argmax as usize], maximum);
        assert!(logits[..h.argmax as usize].iter().all(|v| *v < maximum));
    }
}

#[test]
fn matches_reference_prefill_capture_and_rederives_every_column() {
    let mut family_one = Vec::new();
    for (json, raw) in CORPORA {
        let corpus: serde_json::Value = serde_json::from_str(json).expect("fixture");
        for (index, case) in corpus["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .enumerate()
        {
            let bytes = |span: &serde_json::Value| {
                let start = span["offset"].as_u64().expect("offset") as usize;
                &raw[start..start + span["length"].as_u64().expect("length") as usize]
            };
            let model = Model::decode(bytes(&case["model"])).expect("Model");
            let prep =
                Preparation::decode(&model, bytes(&case["preparation"])).expect("Preparation");
            let scales = Scales::decode(&model, bytes(&case["scales"])).expect("Scales");
            let artifact = bytes(&case["artifact"]);
            let mut ex = Executor::new(
                &model,
                &prep,
                &scales,
                artifact,
                blake3::hash(artifact).as_bytes(),
                1 << 30,
            )
            .expect("executor");
            let tokens: Vec<u32> = case["tokens"]
                .as_array()
                .expect("tokens")
                .iter()
                .map(|v| v.as_u64().expect("token") as u32)
                .collect();
            let (full, capture) = (ex.full(&tokens), ex.capture(&tokens));
            let (full, capture) = match (full, capture) {
                (Ok(full), Ok(capture)) => (full, capture),
                (full, capture) => {
                    assert_eq!(full.err(), capture.err(), "same rejection");
                    continue;
                }
            };
            assert_eq!(full.cuts(), capture.full().cuts());
            assert_eq!(full.logits(), capture.full().logits());
            assert_eq!(full.cache(), capture.full().cache());
            check(&ex, &tokens, &capture);
            if model.shape().family() == 1 {
                family_one.push((json.len(), index, model.blocks().len()));
            }
        }
    }
    // Synthetic family-1 (Llama-style) Models with 2-3 layers execute completely.
    assert!(family_one.iter().any(|(_, _, layers)| *layers >= 2));
}
