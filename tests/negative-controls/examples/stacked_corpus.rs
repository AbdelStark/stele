//! RFC-0006 A4: fixture adapter for actual native public proofs, never a core parser.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use stele_field::{M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{self, Claim, Limits, Order, Prepared, Statement},
};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, Source, Usage};
use stele_reductions::{prove_stacked_sources, verify_stacked_sources};
use stele_sumcheck::{Proof, Term};

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or("InvalidStacked".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("InvalidStacked".into())
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut bytes = Vec::new();
    for limb in array(v)? {
        let n = u32::try_from(number(limb)?).map_err(|_| "NoncanonicalField")?;
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    K::from_le_bytes(bytes.try_into().map_err(|_| "NoncanonicalField")?)
        .ok_or("NoncanonicalField".into())
}
fn fields<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn axes(v: &Value) -> Result<Vec<Axis>, String> {
    array(v)?
        .iter()
        .map(|a| {
            Ok(Axis {
                bits: number(&a[0])?.try_into().map_err(|_| "InvalidStacked")?,
                real: number(&a[1])?,
            })
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wire<K: ChallengeField>(p: &Proof<K>, id: u64, count: usize) -> Vec<String> {
    let mut result: Vec<_> = p
        .rounds
        .iter()
        .enumerate()
        .map(|(r, row)| hex(&stele_sumcheck::message_bytes(id, r as u32, row).expect("round")))
        .collect();
    result.push(hex(&stele_sumcheck::message_bytes(
        id,
        count as u32,
        &p.final_values,
    )
    .expect("final")));
    result
}
fn unhex(v: &Value) -> Result<Vec<u8>, String> {
    let text = v.as_str().ok_or("FixtureHex")?;
    if text.len() % 2 != 0 {
        return Err("FixtureHex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).map_err(|_| "FixtureHex")?;
            u8::from_str_radix(pair, 16).map_err(|_| "FixtureHex".into())
        })
        .collect()
}
fn hashes(u: HashUsage) -> Value {
    json!({"hash_evaluations":u.hash_evaluations,"xof_requests":u.xof_requests,
        "xof_bytes":u.xof_bytes,"state_updates":u.state_updates,
        "candidate_words":u.candidate_words,"column_attempts":u.column_attempts})
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript)})
}
fn certified<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    case: &Value,
    s: &Statement<'_, K>,
    proof: &Proof<K>,
    limits: Limits,
) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let infos = array(&case["certificates"])?;
    let mut certificates = Vec::new();
    for info in infos {
        let source = Source::<K>::new(
            number(&info["id"])?,
            number(&info["ell"])?
                .try_into()
                .map_err(|_| "FixtureShape")?,
            number(&info["m"])?.try_into().map_err(|_| "FixtureShape")?,
            number(&info["blowup"])?
                .try_into()
                .map_err(|_| "FixtureShape")?,
            unhex(&info["root"])?
                .try_into()
                .map_err(|_| "FixtureRoot")?,
        )
        .map_err(|e| format!("{e:?}"))?;
        assert_eq!(source.bytes().as_slice(), unhex(&info["bytes"])?);
        let bytes = unhex(&info["certificate"])?;
        match verify_certificate(source, &bytes) {
            Ok((c, _)) => {
                assert_eq!(
                    hex(&c.record().id()),
                    info["certificate_id"].as_str().ok_or("FixtureId")?
                );
                certificates.push(c);
            }
            Err(f) => {
                return Ok(json!({"phase":"registration","decision":format!("{:?}",f.cause)}))
            }
        }
    }
    let handles: Vec<_> = certificates.iter().collect();
    let opening_bytes: Vec<_> = array(&case["openings"])?
        .iter()
        .map(unhex)
        .collect::<Result<_, _>>()?;
    let openings: Vec<_> = opening_bytes.iter().map(Vec::as_slice).collect();
    let mut verifier = Transcript::new(b"certified stacked wire oracle").expect("public input");
    let (record, observed) = match verify_stacked_sources(
        &mut verifier,
        s,
        &handles,
        proof,
        &openings,
        limits,
    ) {
        Ok(value) => value,
        Err(f) => {
            return Ok(
                json!({"phase":"stage","decision":format!("{:?}",f.cause),"usage":usage(f.usage)}),
            )
        }
    };
    // Matrices are producer witness material only. Acceptance above used only
    // independently selected contexts, verified handles and proof messages.
    let messages: Vec<Vec<M31>> = infos
        .iter()
        .map(|info| {
            array(&info["matrix"])?
                .iter()
                .flat_map(|row| match array(row) {
                    Ok(values) => values
                        .iter()
                        .map(|v| {
                            number(v).and_then(|v| {
                                u32::try_from(v)
                                    .ok()
                                    .and_then(M31::from_canonical)
                                    .ok_or("NoncanonicalField".into())
                            })
                        })
                        .collect::<Vec<_>>(),
                    Err(e) => vec![Err(e)],
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, String>>()?;
    let mut material = Vec::new();
    let mut registrations = Vec::new();
    for (info, message) in infos.iter().zip(&messages) {
        let source = PreparedSource::<K>::new(
            number(&info["id"])?,
            number(&info["ell"])?
                .try_into()
                .map_err(|_| "FixtureShape")?,
            number(&info["m"])?.try_into().map_err(|_| "FixtureShape")?,
            number(&info["blowup"])?
                .try_into()
                .map_err(|_| "FixtureShape")?,
            message,
            &mut HashUsage::default(),
        )
        .map_err(|e| format!("producer source: {e:?}"))?;
        assert_eq!(source.source().bytes().as_slice(), unhex(&info["bytes"])?);
        let (bytes, _) = source
            .certificate()
            .map_err(|e| format!("producer certificate: {e:?}"))?;
        assert_eq!(bytes, unhex(&info["certificate"])?);
        registrations.push(hex(&bytes));
        material.push(source);
    }
    let material_refs: Vec<_> = material.iter().collect();
    let mut producer = Transcript::new(b"certified stacked wire oracle").expect("public input");
    let (native, produced) =
        prove_stacked_sources(&mut producer, s, &material_refs, &handles, limits)
            .map_err(|e| format!("native certified producer: {e:?}"))?;
    assert_eq!(&native.sumcheck, proof);
    assert_eq!(native.openings, opening_bytes);
    assert_eq!(produced.transcript, observed.transcript);
    assert_eq!(produced.non_transcript, HashUsage::default());
    let prepared = Prepared::for_certified_sources(s, limits).map_err(|e| format!("{e:?}"))?;
    let mut sources = vec![1, 1];
    sources.extend_from_slice(&s.id.to_le_bytes());
    sources.extend_from_slice(&(handles.len() as u32).to_le_bytes());
    for c in &certificates {
        sources.extend_from_slice(&c.record().source().bytes());
        sources.extend_from_slice(&c.record().id());
    }
    // Diagnostic replay reports restored claims only; it never feeds the actual
    // producer or any opening, and its usage is excluded from stage observations.
    let mut diagnostic = Transcript::new(b"certified stacked wire oracle").expect("public input");
    diagnostic
        .absorb(AbsorbLabel::StackSources, &sources)
        .expect("sources");
    let (reduction, _) = prepared
        .verify_reduction(&mut diagnostic, proof)
        .expect("kernel");
    assert_eq!(&reduction.sc, record.sc());
    let records: Vec<_> = record.openings().iter().map(|opening| {
        let c = opening.certificate();
        let p = c.parameters();
        json!({"id":opening.id(),"queries":opening.queries(),"kind":format!("{:?}",opening.kind()),
            "certificate":{"id":hex(&c.id()),"source":hex(&c.source().bytes()),"ell":c.ell(),
                "degree":c.degree(),"kind":format!("{:?}",c.kind()),"length":p.length,"distance":p.distance,
                "radius":p.radius,"certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries}})
    }).collect();
    let sc = record.sc();
    let next = verifier
        .challenge(ChallengeLabel::Sumcheck)
        .expect("continuation");
    assert_eq!(
        next,
        producer
            .challenge(ChallengeLabel::Sumcheck)
            .expect("producer continuation")
    );
    Ok(
        json!({"phase":"stage","decision":"accept","stack":hex(prepared.bytes()),
        "sources":hex(&sources),"instance":hex(&prepared.instance().encode().expect("instance")),
        "proof":wire(&native.sumcheck,s.id,s.inputs.len()+1),
        "openings":native.openings.iter().map(|p|hex(p)).collect::<Vec<_>>(),"registrations":registrations,
        "point":reduction.point.iter().map(|x|hex(x.to_le_bytes().as_ref())).collect::<Vec<_>>(),
        "claims":reduction.claims.iter().map(|(id,x)|json!([id,hex(x.to_le_bytes().as_ref())])).collect::<Vec<_>>(),
        "sc":{"id":sc.id,"m":sc.m,"degree":sc.degree,"field_degree":sc.field_degree,"numerator":sc.numerator},
        "records":records,"usage":usage(observed),"producer_usage":usage(produced),
        "continuation":hex(next.to_le_bytes().as_ref())}),
    )
}
fn check<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    case: &Value,
) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let s = &case["statement"];
    let c = &s["coefficient"];
    let o = &s["output"];
    let layout = axes(&s["layout"])?;
    let output_layout = axes(&o["layout"])?;
    let output_point = fields::<K>(&o["point"])?;
    let inputs: Vec<_> = array(&s["inputs"])?
        .iter()
        .map(number)
        .collect::<Result<_, _>>()?;
    let terms: Vec<_> = array(&s["terms"])?
        .iter()
        .map(|t| {
            Ok(Term {
                coefficient: field::<K>(&t[0])?,
                factors: array(&t[1])?
                    .iter()
                    .map(|v| number(v)?.try_into().map_err(|_| "InvalidStacked".into()))
                    .collect::<Result<_, String>>()?,
            })
        })
        .collect::<Result<_, String>>()?;
    let selector_values: Vec<Option<Vec<K>>> = array(&c["selectors"])?
        .iter()
        .map(|v| {
            if v.is_null() {
                Ok(None)
            } else {
                fields(v).map(Some)
            }
        })
        .collect::<Result<_, _>>()?;
    let selectors: Vec<_> = selector_values.iter().map(|v| v.as_deref()).collect();
    let chosen: Vec<usize> = array(&c["axes"])?
        .iter()
        .map(|v| number(v)?.try_into().map_err(|_| "InvalidStacked".into()))
        .collect::<Result<_, String>>()?;
    let values: Vec<_> = array(&c["values"])?
        .iter()
        .map(number)
        .collect::<Result<_, _>>()?;
    let base_values: Vec<_> = if number(&c["kind"])? == 5 {
        values
            .iter()
            .map(|v| {
                u32::try_from(*v)
                    .ok()
                    .and_then(M31::from_canonical)
                    .ok_or("NoncanonicalField".into())
            })
            .collect::<Result<_, String>>()?
    } else {
        vec![]
    };
    let pair = || -> Result<(usize, usize), String> {
        if chosen.len() != 2 {
            Err("InvalidStacked".into())
        } else {
            Ok((chosen[0], chosen[1]))
        }
    };
    let kind = match number(&c["kind"])? {
        0 => Kind::Eq,
        1 => {
            let (row, column) = pair()?;
            Kind::CausalMask { row, column }
        }
        2 => {
            let (row, column) = pair()?;
            Kind::WindowMask {
                row,
                column,
                width: number(&c["width"])?,
            }
        }
        3 => {
            let (row, column) = pair()?;
            Kind::OnehotSparse {
                row,
                column,
                indices: &values,
            }
        }
        4 => {
            let (head, group) = pair()?;
            Kind::GqaBroadcast { head, group }
        }
        5 => Kind::RopeTables {
            axes: &chosen,
            values: &base_values,
        },
        _ => return Err("InvalidStacked".into()),
    };
    let statement = Statement {
        id: number(&s["id"])?,
        axes: &layout,
        order: match number(&s["order"])? {
            0 => Order::LayerFirst,
            1 => Order::LayerLast,
            _ => return Err("InvalidStacked".into()),
        },
        output: Claim {
            id: number(&o["id"])?,
            axes: &output_layout,
            point: &output_point,
            value: field(&o["value"])?,
        },
        coefficient_id: number(&s["coefficient_id"])?,
        inputs: &inputs,
        terms: &terms,
        selectors: &selectors,
        kind,
        source_id: if c["source_id"].is_null() {
            None
        } else {
            Some(number(&c["source_id"])?)
        },
    };
    let proof = Proof {
        rounds: array(&case["proof"]["rounds"])?
            .iter()
            .map(fields::<K>)
            .collect::<Result<_, _>>()?,
        final_values: fields(&case["proof"]["final"])?,
    };
    let limits = Limits {
        descriptor_bytes: 1 << 20,
        proof_bytes: 1 << 20,
        prepared_entries: 1 << 16,
        partial_entries: 1 << 12,
        axis_entries: 1 << 12,
    };
    if case["mode"] == "certified" {
        return certified(case, &statement, &proof, limits);
    }
    let owned: Vec<Vec<K>> = array(&case["tables"])?
        .iter()
        .map(fields::<K>)
        .collect::<Result<_, _>>()?;
    let tables: Vec<_> = owned.iter().map(Vec::as_slice).collect();
    let mut verifier = Transcript::new(b"stacked wire oracle").expect("public input");
    let (record, usage) =
        match stacked::verify_public(&mut verifier, &statement, &proof, &tables, limits) {
            Ok(value) => value,
            Err(failure) => return Ok(json!({"decision":format!("{:?}",failure.cause)})),
        };
    let mut prover = Transcript::new(b"stacked wire oracle").expect("public input");
    let native = stacked::prove_public(&mut prover, &statement, &tables, limits)
        .map_err(|e| format!("native producer: {e:?}"))?;
    assert_eq!(native, proof);
    assert_eq!(prover.usage(), usage);
    let next = verifier
        .challenge(ChallengeLabel::Sumcheck)
        .expect("continuation");
    assert_eq!(
        next,
        prover
            .challenge(ChallengeLabel::Sumcheck)
            .expect("continuation")
    );
    let prepared = Prepared::new(&statement, limits).map_err(|e| format!("{e:?}"))?;
    let sc = record.sc();
    Ok(
        json!({"decision":"accept","stack":hex(prepared.bytes()),"sources":hex(&prepared.source_bytes(&tables).expect("public sources")),"instance":hex(&prepared.instance().encode().expect("A1 descriptor")),
        "proof":wire(&native,statement.id,inputs.len()+1),"point":record.point().iter().map(|x|hex(x.to_le_bytes().as_ref())).collect::<Vec<_>>(),
        "claims":record.claims().iter().map(|(id,x)|json!([id,hex(x.to_le_bytes().as_ref())])).collect::<Vec<_>>(),
        "sc":{"id":sc.id,"m":sc.m,"degree":sc.degree,"field_degree":sc.field_degree,"numerator":sc.numerator},"continuation":hex(next.to_le_bytes().as_ref())}),
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.expect("line")).expect("fixture JSON");
        let result = match value["statement"]["field"].as_u64() {
            Some(4) => check::<QM31>(&value),
            Some(8) => check::<OM31>(&value),
            _ => Err("InvalidStacked".into()),
        };
        println!(
            "{}",
            result.unwrap_or_else(|error| json!({"phase":"fixture","decision":error}))
        );
    }
}
