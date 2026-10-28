//! RFC-0008 A3 / RFC-0018 §1: complete conditional public CPU operation.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{mem::size_of, time::Instant};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{Descriptor, LeafDescriptor, Proof, SelectedProduct};
use stele_sumcheck::ScRecord;

fn error(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}
fn ns(start: Instant) -> Result<u64, String> {
    start.elapsed().as_nanos().try_into().map_err(error)
}
fn record(r: &ScRecord) -> Value {
    json!({"id":r.id,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
}
fn parameters(m: u32, mode: &str) -> Result<(u32, usize), String> {
    if m > 18 {
        return Err("unsupported benchmark depth".into());
    }
    match mode {
        "ordinary" => Ok((m, 0)),
        "weighted" => Ok((m / 2, 0)),
        "selected1" => Ok((m, 1)),
        "selected3zero" => Ok((m, 3)),
        _ => Err("unsupported benchmark mode".into()),
    }
}
fn operation<K: ChallengeField + Eq>(m: u32, mode: &str) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let start = Instant::now();
    let (b, c) = parameters(m, mode)?;
    let n = 1usize << m;
    let mut fixture = Transcript::<K>::new(b"fraction synthetic fixture/v1").map_err(error)?;
    let coefficient = fixture.challenge(ChallengeLabel::Sumcheck).map_err(error)?;
    let theta = vec![coefficient; (m - b) as usize];
    let d = Descriptor::new(307, m, b, [11, 12], &theta).map_err(error)?;
    let ids: Vec<_> = (0..c).map(|i| 91 + i as u64).collect();
    let sigma: Vec<_> = if c == 0 {
        vec![]
    } else {
        (0..n).map(|i| K::from_i64(i64::from(i % 3 != 0))).collect()
    };
    let xs: Vec<Vec<K>> = (0..c)
        .map(|j| {
            (0..n)
                .map(|i| coefficient * K::from_i64(((i * 73 + j * 19) % 31) as i64 - 15))
                .collect()
        })
        .collect();
    let alpha = coefficient + K::from_i64(19);
    let beta = if c == 3 { K::from_i64(0) } else { coefficient };
    let leaves: Vec<[K; 2]> = (0..n)
        .map(|i| {
            if c == 0 {
                [
                    coefficient * K::from_i64((i % 31) as i64 - 15),
                    coefficient + K::from_i64(i as i64 + 1),
                ]
            } else {
                let mut z = K::from_i64(0);
                let mut power = K::from_i64(1);
                for col in &xs {
                    z = z + power * col[i];
                    power = power * beta;
                }
                [
                    sigma[i],
                    K::from_i64(1) + sigma[i] * (alpha - K::from_i64(1) - z),
                ]
            }
        })
        .collect();
    // Public synthetic recipe, parameters and descriptor are fixed before proof challenges.
    let mut public = b"fraction synthetic pipeline/v1".to_vec();
    public.extend(d.encode().map_err(error)?);
    public.extend_from_slice(mode.as_bytes());
    let original_capacity_bytes = leaves.capacity() * size_of::<[K; 2]>()
        + sigma.capacity() * size_of::<K>()
        + xs.capacity() * size_of::<Vec<K>>()
        + xs.iter()
            .map(|x| x.capacity() * size_of::<K>())
            .sum::<usize>();
    let preparation_ns = ns(start)?;

    let start = Instant::now();
    let mut pt = Transcript::new(&public).map_err(error)?;
    let (proof, original) = d.prove(&leaves, &mut pt).map_err(error)?;
    let tree_prover_ns = ns(start)?;
    let start = Instant::now();
    let leaf = if c > 0 {
        Some(
            SelectedProduct::new(
                LeafDescriptor::new(&d, &ids).map_err(error)?,
                &original,
                &sigma,
                alpha,
                beta,
            )
            .map_err(error)?
            .prove(&xs, &mut pt)
            .map_err(error)?,
        )
    } else {
        None
    };
    let leaf_prover_ns = if c > 0 { ns(start)? } else { 0 };

    let start = Instant::now();
    let encoded = proof.encode(&d).map_err(error)?;
    let leaf_bytes = if let Some((p, _)) = &leaf {
        LeafDescriptor::new(&d, &ids)
            .map_err(error)?
            .encode(p)
            .map_err(error)?
    } else {
        vec![]
    };
    let encode_ns = ns(start)?;
    let start = Instant::now();
    let decoded = Proof::decode(&d, &encoded).map_err(error)?;
    let mut vt = Transcript::new(&public).map_err(error)?;
    let consumed = d.verify_public(&decoded, &leaves, &mut vt).map_err(error)?;
    let tree_consumer_ns = ns(start)?;
    let start = Instant::now();
    let selected = if c > 0 {
        let ld = LeafDescriptor::new(&d, &ids).map_err(error)?;
        let decoded = ld.decode(&leaf_bytes).map_err(error)?;
        Some(
            SelectedProduct::new(ld, &consumed, &sigma, alpha, beta)
                .map_err(error)?
                .verify_public(&decoded, &xs, &mut vt)
                .map_err(error)?,
        )
    } else {
        None
    };
    let leaf_consumer_ns = if c > 0 { ns(start)? } else { 0 };
    if original != consumed || leaf.as_ref().map(|(_, r)| r) != selected.as_ref() {
        return Err("receipt mismatch".into());
    }
    let next = pt.challenge(ChallengeLabel::Sumcheck).map_err(error)?;
    if next != vt.challenge(ChallengeLabel::Sumcheck).map_err(error)? {
        return Err("continuation mismatch".into());
    }
    let canonical: String = encoded
        .iter()
        .chain(&leaf_bytes)
        .chain(next.to_le_bytes().as_ref())
        .map(|b| format!("{b:02x}"))
        .collect();
    let a = &consumed.accounting;
    Ok(
        json!({"m":m,"b":b,"columns":c,"points":n,"field_degree":K::DEGREE,
        "preparation_ns":preparation_ns,"tree_prover_ns":tree_prover_ns,"leaf_prover_ns":leaf_prover_ns,
        "encode_ns":encode_ns,"tree_consumer_ns":tree_consumer_ns,"leaf_consumer_ns":leaf_consumer_ns,
        "original_capacity_bytes":original_capacity_bytes,
        "tree_proof_bytes":encoded.len(),"leaf_proof_bytes":leaf_bytes.len(),
        "encoded_capacity_bytes":encoded.capacity()+leaf_bytes.capacity(),"canonical":canonical,
        "tree_claim_ids":consumed.claims.map(|c| c.0),
        "accounting":{"tree_id":a.tree_id,"field_degree":a.field_degree,"gamma":a.gamma,"fold":a.fold,
            "layers":a.layers.iter().map(record).collect::<Vec<_>>()},
        "leaf_claim_ids":selected.as_ref().map(|r| r.claims.iter().map(|c| c.0).collect::<Vec<_>>()),
        "leaf_sc":selected.as_ref().map(|r| record(&r.sc))}),
    )
    // All preparation, sources, internal copies, proofs and receipts drop before complete_ns ends.
}
fn measure<K: ChallengeField + Eq>(m: u32, mode: &str) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let start = Instant::now();
    let mut result = operation::<K>(m, mode)?;
    result["complete_ns"] = json!(ns(start)?);
    Ok(result)
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("expected QM31|OM31 m ordinary|weighted|selected1|selected3zero".into());
    }
    let m = args[1].parse().map_err(error)?;
    let result = match args[0].as_str() {
        "QM31" => measure::<QM31>(m, &args[2])?,
        "OM31" => measure::<OM31>(m, &args[2])?,
        _ => return Err("unsupported field".into()),
    };
    println!("{result}");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn check<K: ChallengeField + Eq>()
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        for m in [0, 1, 3] {
            for mode in ["ordinary", "weighted", "selected1", "selected3zero"] {
                let result = measure::<K>(m, mode).expect("complete public operation");
                let repeated = measure::<K>(m, mode).expect("repeat");
                assert_eq!(result["canonical"], repeated["canonical"]);
                assert_eq!(result["tree_claim_ids"], json!([11, 12]));
                assert_eq!(result["accounting"]["gamma"], m);
                assert_eq!(result["accounting"]["fold"], m);
                assert_eq!(
                    result["tree_proof_bytes"],
                    4 * K::DEGREE * (2 + 2 * m as usize * m as usize + 3 * m as usize)
                );
                let stages: u64 = [
                    "preparation_ns",
                    "tree_prover_ns",
                    "leaf_prover_ns",
                    "encode_ns",
                    "tree_consumer_ns",
                    "leaf_consumer_ns",
                ]
                .iter()
                .map(|k| result[k].as_u64().expect("time"))
                .sum();
                assert!(result["complete_ns"].as_u64().expect("complete") >= stages);
            }
        }
    }
    #[test]
    fn accepts_fraction_benchmark_original_consumers() {
        check::<QM31>();
        check::<OM31>();
    }
    #[test]
    fn rejects_fraction_benchmark_shapes() {
        assert!(measure::<QM31>(19, "ordinary").is_err());
        assert!(measure::<OM31>(0, "unknown").is_err());
    }
}
