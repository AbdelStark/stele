//! RFC-0024 §§2–5: complete native attempts exported for independent replay.
//! Public verifier requests contain no original matrices or captured accumulators.
use serde_json::{json, Value};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource};
use stele_reductions::{
    byte_range, integer_linear as linear, lookup,
    requant::{EmbeddedSchema, Format},
};
use stele_sumcheck::{Dense, Instance, Term};
#[path = "../requant/records.rs"]
mod records;
use records::{fields, hashes, hex, sc, usage};
#[path = "support/integer_linear_verifier.rs"]
mod verifier;

const LIMITS: lookup::Limits = lookup::Limits {
    positions: 1 << 16,
    public_bytes: 64 << 20,
    proof_bytes: 64 << 20,
};
const MATMUL: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 16,
    partial_entries: 1 << 16,
    axis_entries: 0,
};
const STAGE: u32 = 31;
const BASE: u64 = (STAGE as u64) << 40;
const PUBLIC: &[u8] = b"complete centered integer linear";

struct Case {
    bits: [u8; 4],
    mantissa: u32,
    shift: u32,
    format: Format,
    rates: [u8; 3],
    messages: [Vec<u8>; 2],
    base_point: bool,
}
fn case(name: &str) -> Result<Case, &'static str> {
    let (bits, mantissa, shift, format) = match name {
        "scalar" => ([0; 4], 1, 1, Format::Int8),
        "stacked" => ([1; 4], 1, 1, Format::Int8),
        "ties" => ([0, 0, 0, 2], 1, 1, Format::Int8),
        "zero_x" => ([1, 1, 1, 0], 32767, 62, Format::Int16),
        "zero_w" => ([0, 1, 1, 1], 1, 0, Format::Int8),
        "wide" => ([1, 1, 0, 1], 32767, 15, Format::Int16),
        "shift62" => ([0, 1, 1, 1], 32767, 62, Format::Int16),
        "int16_min" | "int16_max" => ([0, 0, 2, 0], 1, 0, Format::Int16),
        "int8_min" | "int8_max" => ([0; 4], 1, 0, Format::Int8),
        "cap" => ([0; 4], 1, 8, Format::Int8),
        _ => return Err("unknown fixture"),
    };
    let [h, a, b, c] = bits;
    let mut x: Vec<_> = (0..1usize << (h + a + b))
        .map(|i| 125 + (i % 7) as u8)
        .collect();
    let mut w: Vec<_> = (0..1usize << (h + c + b))
        .map(|i| 126 + (i % 5) as u8)
        .collect();
    match name {
        "ties" => {
            x = vec![127];
            w = vec![127, 129, 125, 131];
        }
        "zero_x" => x.fill(128),
        "zero_w" => w.fill(128),
        "wide" => {
            x = vec![0, 255, 129, 127];
            w = vec![255, 0, 127, 129];
        }
        "int16_min" => {
            x.fill(0);
            w.fill(192);
        }
        "int16_max" => {
            x = vec![255, 255, 255, 129];
            w = vec![255, 255, 132, 129];
        }
        "int8_min" => {
            x = vec![0];
            w = vec![129];
        }
        "int8_max" => {
            x = vec![255];
            w = vec![129];
        }
        "cap" => {
            x = vec![0];
            w = vec![0];
        }
        _ => (),
    }
    let base_point = matches!(name, "scalar" | "stacked");
    Ok(Case {
        bits,
        mantissa,
        shift,
        format,
        rates: if base_point { [1, 2, 1] } else { [2, 1, 2] },
        messages: [x, w],
        base_point,
    })
}

fn attempt<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    case: &Case,
    repetitions: usize,
) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bits = case.bits;
    let [h, a, b, c] = bits;
    let [layers, rows, inner, columns] = bits.map(|n| 1usize << n);
    let size = layers * inner;
    let [x, w] = case.messages.each_ref().map(|v| {
        v.iter()
            .map(|v| M31::from_i64(i64::from(*v)))
            .collect::<Vec<_>>()
    });
    let mut captured = Vec::new();
    for l in 0..layers {
        for i in 0..rows {
            for j in 0..columns {
                captured.push(
                    (0..inner)
                        .map(|k| {
                            (x[i * size + l * inner + k].as_u32() as i32 - 128)
                                * (w[j * size + l * inner + k].as_u32() as i32 - 128)
                        })
                        .sum(),
                );
            }
        }
    }
    let px = PreparedSource::<K>::new(101, a, h + b, case.rates[0], &x, &mut HashUsage::default())
        .expect("original X preparation");
    let pw = PreparedSource::<K>::new(102, c, h + b, case.rates[1], &w, &mut HashUsage::default())
        .expect("original W preparation");
    let xp = px.certificate().expect("original X certificate").0;
    let wp = pw.certificate().expect("original W certificate").0;
    let (cx, ix) = verify_certificate(*px.source(), &xp).expect("original X import");
    let (cw, iw) = verify_certificate(*pw.source(), &wp).expect("original W import");
    let xids = &[111, 112][..repetitions];
    let wids = &[121, 122][..repetitions];
    let dx = byte_range::Descriptor::new(&cx, 9, xids, LIMITS).expect("X range statement");
    let dw = byte_range::Descriptor::new(&cw, 10, wids, LIMITS).expect("W range statement");
    let range = |d: &byte_range::Descriptor<'_, K>, p: &PreparedSource<'_, K>| {
        d.prove(
            p,
            lookup::ProducerLimits {
                public_bytes: d.producer_public_bytes().expect("range public bound"),
                dense_elements: d.producer_dense_elements().expect("range dense bound"),
            },
        )
        .expect("complete original range production")
        .0
    };
    let rx = range(&dx, &px);
    let rw = range(&dw, &pw);
    let (mx, imx) = dx
        .register_multiplicities(&rx, LIMITS.public_bytes)
        .expect("X range imports");
    let (mw, imw) = dw
        .register_multiplicities(&rw, LIMITS.public_bytes)
        .expect("W range imports");
    let xr = dx
        .verify(&mx.iter().collect::<Vec<_>>(), &rx)
        .expect("complete X range");
    let wr = dw
        .verify(&mw.iter().collect::<Vec<_>>(), &rw)
        .expect("complete W range");
    let schema =
        EmbeddedSchema::new(b, case.mantissa, case.shift, case.format).expect("embedded schema");
    let witness = schema
        .witness(&captured, LIMITS.positions as usize)
        .expect("captured advice");
    let pa = PreparedSource::<K>::new(
        BASE + 2,
        schema.rows().trailing_zeros() as u8,
        h + a + c,
        case.rates[2],
        witness.advice(),
        &mut HashUsage::default(),
    )
    .expect("advice preparation");
    let packet = pa.certificate().expect("advice certificate").0;
    let (ca, ia) = verify_certificate(*pa.source(), &packet).expect("advice import");
    let point: Vec<_> = (0..h + a + c)
        .map(|i| {
            if case.base_point {
                return K::from_i64(i64::from(i) + 2);
            }
            let raw: Vec<_> = (0..<K as CodeField>::DEGREE)
                .flat_map(|j| ((u32::from(i) + 2) * (j as u32 + 1)).to_le_bytes())
                .collect();
            K::from_le_bytes(
                K::Bytes::try_from(raw.as_slice())
                    .ok()
                    .expect("fixture field width"),
            )
            .expect("canonical nonbase fixture point")
        })
        .collect();
    let eq = stele_poly::eq_table(&point).expect("output point");
    let value = eq
        .iter()
        .zip(witness.output())
        .fold(K::from_i64(0), |s, (e, v)| {
            s + *e * K::from_i64(i64::from(*v))
        });
    let descriptor = linear::Descriptor::new(
        linear::Statement {
            stage: STAGE,
            bits,
            mantissa: case.mantissa,
            shift: case.shift,
            format: case.format,
            repetitions: repetitions as u8,
            advice_blowup: case.rates[2],
            point: &point,
            value,
            originals: [&xr, &wr],
        },
        &ca,
        LIMITS,
        MATMUL,
    )
    .expect("integer-linear statement");
    let mut pt = Transcript::<K>::new(PUBLIC).expect("producer transcript");
    let (wire, produced) = descriptor
        .prove(
            &mut pt,
            [&px, &pw],
            &pa,
            &packet,
            linear::ProducerLimits {
                public_bytes: descriptor.producer_public_bytes().expect("public bound"),
                dense_elements: descriptor.producer_dense_elements().expect("dense bound"),
                retained_row_entries: descriptor.retained_row_entries(),
            },
        )
        .expect("complete integer-linear production");
    let (mu, imports) = descriptor
        .register_multiplicities(&wire, LIMITS.public_bytes)
        .expect("advice multiplicity imports");
    let mut vt = Transcript::<K>::new(PUBLIC).expect("verifier transcript");
    let (record, consumed) = descriptor
        .verify(&mut vt, &mu.iter().collect::<Vec<_>>(), &wire)
        .expect("complete integer-linear verification");
    assert_eq!(produced.transcript, consumed.transcript);
    let instance = Instance {
        id: BASE + (1 << 29),
        num_vars: 1,
        inputs: vec![BASE + (1 << 29) + 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(3),
    };
    let tables = vec![vec![K::from_i64(1), K::from_i64(2)]];
    let following = stele_sumcheck::prove(
        &instance,
        Dense::new(&instance, tables.clone()).expect("following strategy"),
        &mut pt,
    )
    .expect("following production");
    let next = stele_sumcheck::verify_public(&instance, &following, &tables, &mut vt)
        .expect("following public consumer");
    let continuation_usage = vt.usage();
    assert_eq!(pt.usage(), continuation_usage);
    let vp = vt
        .challenge(ChallengeLabel::Sumcheck)
        .expect("verifier continuation probe");
    assert!(
        pt.challenge(ChallengeLabel::Sumcheck)
            .expect("producer continuation probe")
            == vp
    );
    let following: Vec<_> = following
        .rounds
        .iter()
        .flatten()
        .chain(&following.final_values)
        .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
        .collect();
    let originals: Vec<_> = [(&px, &xp, &rx, 9, xids), (&pw, &wp, &rw, 10, wids)]
        .into_iter()
        .map(|(p, cert, range, id, mu)| {
            json!({
                "source_hex":hex(&p.source().bytes()), "certificate_hex":hex(cert),
                "lookup_id":id,"mu_ids":mu,"range_proof_hex":hex(range)
            })
        })
        .collect();
    json!({"request":{"degree":<K as CodeField>::DEGREE,"stage":STAGE,"dims":bits,
        "parameters":{"mantissa":case.mantissa,"shift":case.shift,"bits":match case.format {Format::Int8=>8,Format::Int16=>16}},"repetitions":repetitions,
        "advice_blowup":case.rates[2],"point":fields(&point),"value":fields(&[value])[0],
        "public_hex":hex(PUBLIC),"originals":originals,"proof_hex":hex(&wire),"following_hex":hex(&following)},
        "producer_usage":{"transcript":hashes(produced.transcript),"non_transcript":hashes(produced.non_transcript),
            "registrations":produced.registrations.map(|u|u.map(|u|json!({"production":hashes(u.production),"verification":usage(u.verification)})))},
        "verification":{"decision":"accept","imports":{"originals":[usage(ix),usage(iw)],"advice":usage(ia),
            "original_multiplicities":[imx.map(|u|u.map(usage)),imw.map(|u|u.map(usage))],
            "multiplicities":imports.map(|u|u.map(usage))},"usage":usage(consumed),
            "original_ranges":[{"record":records::lookup(xr.lookup()),"usage":usage(*xr.usage())},
                {"record":records::lookup(wr.lookup()),"usage":usage(*wr.usage())}],
            "record":verifier::record(&record),
            "continuation":{"record":{"sc":sc(&next.sc),"point":fields(&next.point)},"usage":hashes(continuation_usage),"probe":hex(vp.to_le_bytes().as_ref())}}})
}

fn main() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--verify"] {
        use std::io::{self, BufRead};
        for line in io::stdin().lock().lines() {
            let input: Value = serde_json::from_str(&line.map_err(|_| "request input")?)
                .map_err(|_| "request JSON")?;
            let result = match input["degree"].as_u64() {
                Some(4) => verifier::verify::<QM31>(&input),
                Some(8) => verifier::verify::<OM31>(&input),
                _ => Err("RequestDegree".into()),
            }
            .unwrap_or_else(|cause| json!({"phase":"request","decision":cause,"record":null}));
            println!("{result}");
        }
        return Ok(());
    }
    if args.len() != 3 {
        return Err("usage: integer_linear_corpus K CASE r, or --verify");
    }
    let case = case(&args[1])?;
    let repetitions = match args[2].as_str() {
        "1" => 1,
        "2" => 2,
        _ => return Err("invalid repetition count"),
    };
    let result = match args[0].as_str() {
        "4" => attempt::<QM31>(&case, repetitions),
        "8" => attempt::<OM31>(&case, repetitions),
        _ => return Err("invalid field degree"),
    };
    println!("{result}");
    Ok(())
}
