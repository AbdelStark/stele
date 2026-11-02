//! RFC-0024 §§2–5: public-request adapter to the actual closed native consumers.
use super::{records, LIMITS, MATMUL};
use records::{fields, hashes, hex, sc, usage};
use serde_json::{json, Value};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_pcs::{verify_certificate, CodeField, ProofKind, Source};
use stele_reductions::{
    byte_range, integer_linear as linear, lookup,
    requant::{EmbeddedSchema, Format},
};
use stele_sumcheck::{Instance, Proof, Term};

#[path = "integer_linear_record.rs"]
mod record;
pub(super) use record::record;

fn keys(v: &Value, names: &str) -> Result<(), String> {
    let object = v.as_object().ok_or("RequestObject")?;
    let expected: Vec<_> = names.split_whitespace().collect();
    if object.len() != expected.len() || object.keys().any(|k| !expected.contains(&k.as_str())) {
        return Err("RequestKeys".into());
    }
    Ok(())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("RequestInteger".into())
}
fn byte(v: &Value) -> Result<u8, String> {
    number(v)?.try_into().map_err(|_| "RequestByte".into())
}
fn array(v: &Value, count: usize) -> Result<&[Value], String> {
    v.as_array()
        .filter(|v| v.len() == count)
        .map(Vec::as_slice)
        .ok_or("RequestShape".into())
}
fn unhex(v: &Value) -> Result<Vec<u8>, String> {
    let raw = v.as_str().ok_or("RequestHex")?.as_bytes();
    if !raw.len().is_multiple_of(2)
        || raw
            .iter()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
    {
        return Err("RequestHex".into());
    }
    raw.chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(core::str::from_utf8(b).map_err(|_| "RequestHex")?, 16)
                .map_err(|_| "RequestHex".into())
        })
        .collect()
}
fn decode<K: ChallengeField>(bytes: &[u8]) -> Result<K, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    K::from_le_bytes(K::Bytes::try_from(bytes).map_err(|_| "RequestField")?)
        .ok_or("RequestField".into())
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut raw = Vec::new();
    for limb in array(v, K::DEGREE)? {
        raw.extend_from_slice(
            &u32::try_from(number(limb)?)
                .map_err(|_| "RequestField")?
                .to_le_bytes(),
        );
    }
    decode::<K>(&raw)
}
fn source<K: ChallengeField + CodeField>(v: &Value) -> Result<Source<K>, String> {
    let raw = unhex(v)?;
    if raw.len() != 105 {
        return Err("RequestSource".into());
    }
    let prefix = b"stele/v0.1/field-source".len();
    let id = u64::from_le_bytes(
        raw[prefix + 2..prefix + 10]
            .try_into()
            .map_err(|_| "RequestSource")?,
    );
    let code = prefix + 11 + b"stele/circle-m31/v1".len();
    let s = Source::<K>::new(
        id,
        raw[prefix + 10],
        raw[code],
        raw[code + 1],
        raw[73..].try_into().map_err(|_| "RequestSource")?,
    )
    .map_err(|e| format!("Source({e:?})"))?;
    if raw != s.bytes() {
        return Err("RequestSource".into());
    }
    Ok(s)
}

pub(super) fn verify<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    v: &Value,
) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    keys(v, "degree stage dims parameters repetitions advice_blowup point value public_hex originals proof_hex following_hex")?;
    if number(&v["degree"])? != <K as CodeField>::DEGREE as u64 {
        return Err("RequestField".into());
    }
    let stage: u32 = number(&v["stage"])?
        .try_into()
        .map_err(|_| "RequestStage")?;
    let dims = array(&v["dims"], 4)?;
    let bits = [
        byte(&dims[0])?,
        byte(&dims[1])?,
        byte(&dims[2])?,
        byte(&dims[3])?,
    ];
    let m = bits[0]
        .checked_add(bits[1])
        .and_then(|m| m.checked_add(bits[3]))
        .ok_or("RequestDimensions")?;
    keys(&v["parameters"], "mantissa shift bits")?;
    let mantissa = number(&v["parameters"]["mantissa"])?
        .try_into()
        .map_err(|_| "RequestMantissa")?;
    let shift = number(&v["parameters"]["shift"])?
        .try_into()
        .map_err(|_| "RequestShift")?;
    let format = match number(&v["parameters"]["bits"])? {
        8 => Format::Int8,
        16 => Format::Int16,
        _ => return Err("RequestFormat".into()),
    };
    let schema = EmbeddedSchema::new(bits[2], mantissa, shift, format)
        .map_err(|e| format!("Schema({e:?})"))?;
    let repetitions = byte(&v["repetitions"])?;
    let point: Vec<K> = array(&v["point"], usize::from(m))?
        .iter()
        .map(field::<K>)
        .collect::<Result<_, _>>()?;
    let value = field::<K>(&v["value"])?;
    let infos = array(&v["originals"], 2)?;
    let mut owners = Vec::new();
    let mut mu_ids = Vec::new();
    let mut range_proofs = Vec::new();
    let mut imports =
        json!({"originals":[],"original_multiplicities":[],"advice":null,"multiplicities":null});
    let mut original_imports = Vec::new();
    for (index, info) in infos.iter().enumerate() {
        keys(
            info,
            "source_hex certificate_hex lookup_id mu_ids range_proof_hex",
        )?;
        match verify_certificate(
            source::<K>(&info["source_hex"])?,
            &unhex(&info["certificate_hex"])?,
        ) {
            Ok((owner, observed)) => {
                owners.push(owner);
                original_imports.push(usage(observed));
            }
            Err(f) => {
                original_imports.push(usage(f.usage));
                imports["originals"] = json!(original_imports);
                return Ok(
                    json!({"decision":format!("{:?}", f.cause),"phase":"original-import","index":index,"imports":imports,"record":null}),
                );
            }
        }
        mu_ids.push(
            array(&info["mu_ids"], usize::from(repetitions))?
                .iter()
                .map(number)
                .collect::<Result<Vec<_>, _>>()?,
        );
        range_proofs.push(unhex(&info["range_proof_hex"])?);
    }
    imports["originals"] = json!(original_imports);
    let mut descriptors = Vec::new();
    let mut range_mu = Vec::new();
    let mut range_imports = Vec::new();
    for index in 0..2 {
        let d = byte_range::Descriptor::new(
            &owners[index],
            number(&infos[index]["lookup_id"])?,
            &mu_ids[index],
            LIMITS,
        )
        .map_err(|e| format!("RangeStatement({e:?})"))?;
        match d.register_multiplicities(&range_proofs[index], LIMITS.public_bytes) {
            Ok((owners, observed)) => {
                range_mu.push(owners);
                range_imports.push(observed.map(|u| u.map(usage)));
            }
            Err(f) => {
                range_imports.push(f.registrations.map(|u| u.map(usage)));
                imports["original_multiplicities"] = json!(range_imports);
                return Ok(
                    json!({"decision":format!("{:?}", f.cause),"phase":"original-multiplicity-import","index":index,"imports":imports,"record":null}),
                );
            }
        }
        descriptors.push(d);
    }
    imports["original_multiplicities"] = json!(range_imports);
    let mut ranges = Vec::new();
    for index in 0..2 {
        match descriptors[index].verify(
            &range_mu[index].iter().collect::<Vec<_>>(),
            &range_proofs[index],
        ) {
            Ok(record) => ranges.push(record),
            Err(f) => {
                return Ok(
                    json!({"decision":format!("{:?}",f.cause),"phase":"original-range","index":index,"imports":imports,"usage":usage(f.usage),"record":null}),
                )
            }
        }
    }
    let wire = unhex(&v["proof_hex"])?;
    let root = wire
        .get(2..34)
        .ok_or("RequestProofShape")?
        .try_into()
        .map_err(|_| "RequestProofShape")?;
    let advice_source = Source::<K>::new(
        (u64::from(stage) << 40) + 2,
        schema.rows().trailing_zeros() as u8,
        m,
        byte(&v["advice_blowup"])?,
        root,
    )
    .map_err(|e| format!("AdviceSource({e:?})"))?;
    let count = advice_source
        .proof_size(ProofKind::Certificate)
        .map_err(|e| format!("AdviceSource({e:?})"))?;
    let advice = match verify_certificate(
        advice_source,
        wire.get(34..34 + count).ok_or("RequestProofShape")?,
    ) {
        Ok((owner, observed)) => {
            imports["advice"] = usage(observed);
            owner
        }
        Err(f) => {
            imports["advice"] = usage(f.usage);
            return Ok(
                json!({"decision":format!("{:?}", f.cause),"phase":"advice-import","imports":imports,"record":null}),
            );
        }
    };
    let d = linear::Descriptor::new(
        linear::Statement {
            stage,
            bits,
            mantissa,
            shift,
            format,
            repetitions,
            advice_blowup: byte(&v["advice_blowup"])?,
            point: &point,
            value,
            originals: [&ranges[0], &ranges[1]],
        },
        &advice,
        LIMITS,
        MATMUL,
    )
    .map_err(|e| format!("Statement({e:?})"))?;
    let mu = match d.register_multiplicities(&wire, LIMITS.public_bytes) {
        Ok((owners, observed)) => {
            imports["multiplicities"] = json!(observed.map(|u| u.map(usage)));
            owners
        }
        Err(f) => {
            imports["multiplicities"] = json!(f.registrations.map(|u| u.map(usage)));
            return Ok(
                json!({"decision":format!("{:?}",f.cause),"phase":"multiplicity-import","imports":imports,"record":null}),
            );
        }
    };
    let mut t = Transcript::<K>::new(&unhex(&v["public_hex"])?)
        .map_err(|e| format!("Transcript({e:?})"))?;
    let (r, observed) = match d.verify(&mut t, &mu.iter().collect::<Vec<_>>(), &wire) {
        Ok(result) => result,
        Err(f) => {
            return Ok(
                json!({"decision":format!("{:?}",f.cause),"phase":"outer","imports":imports,"usage":usage(f.usage),"record":null}),
            )
        }
    };
    let original_ranges: Vec<_> = ranges
        .iter()
        .map(|r| json!({"record":records::lookup(r.lookup()),"usage":usage(*r.usage())}))
        .collect();
    let mut out = json!({"decision":"accept","imports":imports,"original_ranges":original_ranges,"usage":usage(observed),"record":record(&r)});
    let raw = unhex(&v["following_hex"])?;
    let width = 4 * <K as CodeField>::DEGREE as usize;
    if raw.len() != 3 * width {
        return Err("RequestFollowingShape".into());
    }
    let values: Vec<K> = raw
        .chunks_exact(width)
        .map(decode::<K>)
        .collect::<Result<_, _>>()?;
    let next = Instance {
        id: (u64::from(stage) << 40) + (1 << 29),
        num_vars: 1,
        inputs: vec![(u64::from(stage) << 40) + (1 << 29) + 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(3),
    };
    let proof = Proof {
        rounds: vec![values[..2].to_vec()],
        final_values: vec![values[2]],
    };
    out["continuation"] = match stele_sumcheck::verify_public(
        &next,
        &proof,
        &[vec![K::from_i64(1), K::from_i64(2)]],
        &mut t,
    ) {
        Ok(r) => {
            let observed = t.usage();
            let probe = t
                .challenge(ChallengeLabel::Sumcheck)
                .map_err(|e| format!("Probe({e:?})"))?;
            json!({"record":{"point":fields(&r.point),"sc":sc(&r.sc)},"usage":hashes(observed),"probe":hex(probe.to_le_bytes().as_ref())})
        }
        Err(e) => json!({"decision":format!("{e:?}"),"usage":hashes(t.usage()),"record":null}),
    };
    Ok(out)
}
