//! RFC-0024 §§2–6: one complete native attempt with phase and allocation markers.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::time::Instant;
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource};
use stele_reductions::{byte_range, integer_linear as linear, lookup, requant::EmbeddedSchema};
use stele_sumcheck::{Dense, Instance, Term};
#[path = "support/integer_linear_case.rs"]
mod fixture;
#[path = "support/integer_linear_record.rs"]
mod record;
#[path = "../requant/records.rs"]
mod records;
use fixture::{case, Case};
use records::{fields, hashes, hex, sc, usage};

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

struct Meter {
    start: Instant,
    times: Vec<(&'static str, u64)>,
    markers: Vec<(&'static str, bool, Vec<u8>)>,
    trace: bool,
}
impl Meter {
    fn new(trace: bool) -> Self {
        let mut m = Self {
            start: Instant::now(),
            times: Vec::new(),
            markers: Vec::new(),
            trace,
        };
        m.mark("pipeline", true);
        m
    }
    fn mark(&mut self, name: &'static str, begin: bool) {
        if self.trace {
            // Retaining each allocation disambiguates its address from earlier startup reuse.
            let block = vec![1u8; 17 + self.markers.len()];
            self.markers.push((name, begin, block));
        }
    }
    fn time<T>(&mut self, name: &'static str, call: impl FnOnce() -> T) -> T {
        assert!(self.times.iter().all(|(previous, _)| *previous != name));
        self.mark(name, true);
        let start = Instant::now();
        let result = call();
        let ns = u64::try_from(start.elapsed().as_nanos()).expect("phase timer");
        self.mark(name, false);
        self.times.push((name, ns));
        result
    }
    fn finish(&mut self) -> Value {
        self.mark("pipeline", false);
        let total = u64::try_from(self.start.elapsed().as_nanos()).expect("pipeline timer");
        let sum: u64 = self.times.iter().map(|(_, t)| *t).sum();
        assert!(sum <= total);
        json!({"worker_pid":std::process::id(),"trace":self.trace,
            "total_ns":total,"remainder_ns":total-sum,
            "stages_ns":self.times.iter().map(|(n,t)|(n.to_string(),json!(t))).collect::<serde_json::Map<_,_>>(),
            "markers":self.markers.iter().map(|(name,begin,block)|json!({
                "name":format!("{name}/{}",if *begin {"begin"} else {"end"}),
                "address":format!("{:p}",block.as_ptr()),"bytes":block.capacity()
            })).collect::<Vec<_>>()})
    }
}

fn produced(
    transcript: HashUsage,
    non_transcript: HashUsage,
    registrations: [Option<lookup::RegistrationUsage>; 2],
) -> Value {
    json!({"transcript":hashes(transcript),"non_transcript":hashes(non_transcript),
        "registrations":registrations.map(|u|u.map(|u|json!({
            "production":hashes(u.production),"verification":usage(u.verification)})))})
}

fn attempt<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    case: &Case,
    repetitions: usize,
    meter: &mut Meter,
) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let [h, a, b, c] = case.bits;
    let [layers, rows, inner, columns] = case.bits.map(|n| 1usize << n);
    let size = layers * inner;
    let [x, w] = meter.time("original-messages", || {
        case.messages.each_ref().map(|v| {
            v.iter()
                .map(|v| M31::from_i64(i64::from(*v)))
                .collect::<Vec<_>>()
        })
    });
    let mut forward_reads = [0usize; 2];
    let captured = meter.time("forward-capture", || {
        let mut values = Vec::new();
        for l in 0..layers {
            for i in 0..rows {
                for j in 0..columns {
                    values.push(
                        (0..inner)
                            .map(|k| {
                                forward_reads[0] += 1;
                                forward_reads[1] += 1;
                                (x[i * size + l * inner + k].as_u32() as i32 - 128)
                                    * (w[j * size + l * inner + k].as_u32() as i32 - 128)
                            })
                            .sum(),
                    );
                }
            }
        }
        values
    });
    let mut preparation_hashes = [HashUsage::default(); 3];
    let px = meter.time("prepare-X", || {
        PreparedSource::<K>::new(101, a, h + b, case.rates[0], &x, &mut preparation_hashes[0])
            .expect("X preparation")
    });
    let pw = meter.time("prepare-W", || {
        PreparedSource::<K>::new(102, c, h + b, case.rates[1], &w, &mut preparation_hashes[1])
            .expect("W preparation")
    });
    let (xp, hx) = meter.time("certificate-X-prove", || {
        px.certificate().expect("X certificate")
    });
    let (wp, hw) = meter.time("certificate-W-prove", || {
        pw.certificate().expect("W certificate")
    });
    let (cx, ix) = meter.time("certificate-X-import", || {
        verify_certificate(*px.source(), &xp).expect("X import")
    });
    let (cw, iw) = meter.time("certificate-W-import", || {
        verify_certificate(*pw.source(), &wp).expect("W import")
    });
    let xids = &[111, 112][..repetitions];
    let wids = &[121, 122][..repetitions];
    let dx = meter.time("range-X-descriptor", || {
        byte_range::Descriptor::new(&cx, 9, xids, LIMITS).expect("X range")
    });
    let dw = meter.time("range-W-descriptor", || {
        byte_range::Descriptor::new(&cw, 10, wids, LIMITS).expect("W range")
    });
    let range = |d: &byte_range::Descriptor<'_, K>, p: &PreparedSource<'_, K>| {
        d.prove(
            p,
            lookup::ProducerLimits {
                public_bytes: d.producer_public_bytes().expect("range public bound"),
                dense_elements: d.producer_dense_elements().expect("range dense bound"),
            },
        )
        .expect("complete range production")
    };
    let (rx, ux) = meter.time("range-X-prove-including-mu-registration", || {
        range(&dx, &px)
    });
    let (rw, uw) = meter.time("range-W-prove-including-mu-registration", || {
        range(&dw, &pw)
    });
    let (mx, imx) = meter.time("range-X-mu-import", || {
        dx.register_multiplicities(&rx, LIMITS.public_bytes)
            .expect("X range imports")
    });
    let (mw, imw) = meter.time("range-W-mu-import", || {
        dw.register_multiplicities(&rw, LIMITS.public_bytes)
            .expect("W range imports")
    });
    let xr = meter.time("range-X-verify", || {
        dx.verify(&mx.iter().collect::<Vec<_>>(), &rx)
            .expect("X range verification")
    });
    let wr = meter.time("range-W-verify", || {
        dw.verify(&mw.iter().collect::<Vec<_>>(), &rw)
            .expect("W range verification")
    });
    let schema = meter.time("schema", || {
        EmbeddedSchema::new(b, case.mantissa, case.shift, case.format).expect("schema")
    });
    let witness = meter.time("advice-witness", || {
        schema
            .witness(&captured, LIMITS.positions as usize)
            .expect("captured advice")
    });
    let pa = meter.time("prepare-advice", || {
        PreparedSource::<K>::new(
            BASE + 2,
            schema.rows().trailing_zeros() as u8,
            h + a + c,
            case.rates[2],
            witness.advice(),
            &mut preparation_hashes[2],
        )
        .expect("advice preparation")
    });
    let (packet, ha) = meter.time("certificate-advice-prove", || {
        pa.certificate().expect("advice certificate")
    });
    let (ca, ia) = meter.time("certificate-advice-import", || {
        verify_certificate(*pa.source(), &packet).expect("advice import")
    });
    let (point, value) = meter.time("expected-output", || {
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
                        .expect("field width"),
                )
                .expect("nonbase point")
            })
            .collect();
        let value = stele_poly::eq_table(&point)
            .expect("point")
            .iter()
            .zip(witness.output())
            .fold(K::from_i64(0), |s, (e, v)| {
                s + *e * K::from_i64(i64::from(*v))
            });
        (point, value)
    });
    let descriptor = meter.time("outer-descriptor", || {
        linear::Descriptor::new(
            linear::Statement {
                stage: STAGE,
                bits: case.bits,
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
        .expect("outer descriptor")
    });
    let mut pt = meter.time("producer-transcript", || {
        Transcript::<K>::new(PUBLIC).expect("producer transcript")
    });
    let (wire, pu, work) = meter.time("outer-prove-including-advice-mu-registration", || {
        descriptor
            .prove_measured(
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
            .expect("complete outer production")
    });
    for (observed, elements) in work.matmul.retained_rows.iter().zip([x.len(), w.len()]) {
        assert_eq!(observed.source_visits, 1);
        assert_eq!(observed.source_elements, elements);
    }
    let (mu, imports) = meter.time("outer-advice-mu-import", || {
        descriptor
            .register_multiplicities(&wire, LIMITS.public_bytes)
            .expect("advice mu imports")
    });
    let mut vt = meter.time("verifier-transcript", || {
        Transcript::<K>::new(PUBLIC).expect("verifier transcript")
    });
    let (record, consumed) = meter.time("outer-verify", || {
        descriptor
            .verify(&mut vt, &mu.iter().collect::<Vec<_>>(), &wire)
            .expect("complete verification")
    });
    assert_eq!(pu.transcript, consumed.transcript);
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
    let following = meter.time("following-prove", || {
        stele_sumcheck::prove(
            &instance,
            Dense::new(&instance, tables.clone()).expect("following table"),
            &mut pt,
        )
        .expect("following proof")
    });
    let next = meter.time("following-verify", || {
        stele_sumcheck::verify_public(&instance, &following, &tables, &mut vt)
            .expect("following verification")
    });
    let continuation_usage = vt.usage();
    assert_eq!(pt.usage(), continuation_usage);
    let probe = vt
        .challenge(ChallengeLabel::Sumcheck)
        .expect("verifier probe");
    assert!(
        probe
            == pt
                .challenge(ChallengeLabel::Sumcheck)
                .expect("producer probe")
    );
    meter.time("export-observations", || {
        let following:Vec<_> = following.rounds.iter().flatten().chain(&following.final_values)
            .flat_map(|v|v.to_le_bytes().as_ref().to_vec()).collect();
        let originals:Vec<_> = [(&px,&xp,&rx,9,xids),(&pw,&wp,&rw,10,wids)].into_iter().map(|(p,cert,range,id,mu)|json!({
            "source_hex":hex(&p.source().bytes()),"certificate_hex":hex(cert),"lookup_id":id,"mu_ids":mu,"range_proof_hex":hex(range)
        })).collect();
        let preparations:Vec<_> = [&px,&pw,&pa].into_iter().zip(preparation_hashes).map(|(p,h)| {
            let w=p.work();json!({"hashes":hashes(h),"work":{
                "borrowed_message_bytes":w.borrowed_message_bytes,"encoded_columns_bytes":w.encoded_columns_bytes,
                "encoder_peak_bytes":w.encoder_peak_bytes,"leaf_references_bytes":w.leaf_references_bytes,
                "merkle_nodes_bytes":w.merkle_nodes_bytes,"peak_owned_bytes":w.peak_owned_bytes}})
        }).collect();
        json!({"request":{"degree":<K as CodeField>::DEGREE,"stage":STAGE,"dims":case.bits,
            "parameters":{"mantissa":case.mantissa,"shift":case.shift,"bits":match case.format {stele_reductions::requant::Format::Int8=>8,stele_reductions::requant::Format::Int16=>16}},
            "repetitions":repetitions,"advice_blowup":case.rates[2],"point":fields(&point),"value":fields(&[value])[0],
            "public_hex":hex(PUBLIC),"originals":originals,"proof_hex":hex(&wire),"following_hex":hex(&following)},
            "producer_usage":produced(pu.transcript,pu.non_transcript,pu.registrations),
            "range_producer_usage":[produced(ux.transcript,ux.non_transcript,ux.registrations),produced(uw.transcript,uw.non_transcript,uw.registrations)],
            "preparations":preparations,"certificate_producers":[hashes(hx),hashes(hw),hashes(ha)],
            "capture":{"source_elements":forward_reads,"accumulators":captured.len()},
            "online_originals":work.matmul.retained_rows.map(|w|json!({"source_visits":w.source_visits,"source_elements":w.source_elements,"retained_bytes":w.retained_bytes})),
            "signed_input_bytes":work.signed_input_bytes,"affine_preparation_peak_bytes":work.affine_preparation_peak_bytes,
            "bytes":{"original_certificates":[xp.len(),wp.len()],"original_ranges":[rx.len(),rw.len()],
                "advice_certificate_embedded_in_outer":packet.len(),"outer":wire.len(),"following":following.len(),
                "complete_transmitted":xp.len()+wp.len()+rx.len()+rw.len()+wire.len()+following.len()},
            "verification":{"decision":"accept","imports":{"originals":[usage(ix),usage(iw)],"advice":usage(ia),
                "original_multiplicities":[imx.map(|u|u.map(usage)),imw.map(|u|u.map(usage))],"multiplicities":imports.map(|u|u.map(usage))},
                "usage":usage(consumed),"original_ranges":[{"record":records::lookup(xr.lookup()),"usage":usage(*xr.usage())},
                    {"record":records::lookup(wr.lookup()),"usage":usage(*wr.usage())}],"record":record::record(&record),
                "continuation":{"record":{"sc":sc(&next.sc),"point":fields(&next.point)},"usage":hashes(continuation_usage),"probe":hex(probe.to_le_bytes().as_ref())}}})
    })
}

fn main() -> Result<(), &'static str> {
    use std::io::{self, Write};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 && (args.len() != 4 || args[3] != "--trace") {
        return Err("usage: integer_linear_bench K CASE r [--trace]");
    }
    let mut meter = Meter::new(args.len() == 4);
    let case = meter.time("fixture", || case(&args[1]))?;
    let repetitions = match args[2].as_str() {
        "1" => 1,
        "2" => 2,
        _ => return Err("repetitions"),
    };
    let mut result = match args[0].as_str() {
        "4" => attempt::<QM31>(&case, repetitions, &mut meter),
        "8" => attempt::<OM31>(&case, repetitions, &mut meter),
        _ => return Err("field degree"),
    };
    result["measurement"] = meter.finish();
    println!("{result}");
    io::stdout().flush().map_err(|_| "measurement output")?;
    if meter.trace {
        let mut resume = String::new();
        io::stdin()
            .read_line(&mut resume)
            .map_err(|_| "trace resume")?;
        if resume != "continue\n" {
            return Err("expected trace resume");
        }
        std::hint::black_box(&meter.markers);
    }
    Ok(())
}
