//! RFC-0006 A5 / RFC-0018 §1: separately measured prover and actual public consumer.
use serde_json::{json, Value};
use std::{hint::black_box, io::Read, time::Instant};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{prove, verify_public, Dense, Instance, Proof, Small, SmallTable, Term};

fn fixture<K: ChallengeField>(
    degree: usize,
    m: u32,
    k: u8,
) -> Result<(Instance<K>, Vec<SmallTable>), String> {
    if degree > 4
        || !(2..=18).contains(&m)
        || (k != 0 && (!(2..=4).contains(&k) || u32::from(k) > m))
    {
        return Err("invalid benchmark shape".into());
    }
    let n = 1usize << m;
    let left: Vec<i16> = (0..n).map(|j| ((j * 73 + 19) % 15) as i16 - 7).collect();
    let right = left
        .iter()
        .map(|v| i16::try_from(i32::from(*v).pow(degree as u32)).expect("degree<=4 and |x|<=7"))
        .collect();
    let unused = (0..n)
        .map(|j| u16::try_from((j * 8191) % 65536).expect("bounded unsigned"))
        .collect();
    let tables = vec![
        SmallTable::Signed(left.clone()),
        SmallTable::Signed(right),
        SmallTable::Unsigned(unused),
        SmallTable::Signed(left),
    ];
    let terms = if degree == 0 {
        vec![Term {
            coefficient: K::from_i64(5),
            factors: vec![],
        }]
    } else {
        vec![
            Term {
                coefficient: K::from_i64(1),
                factors: vec![0; degree],
            },
            Term {
                coefficient: K::from_i64(-1),
                factors: vec![1],
            },
        ]
    };
    Ok((
        Instance {
            id: 204,
            num_vars: m,
            inputs: vec![11, 12, 13, 14],
            terms,
            claimed_sum: K::from_i64(if degree == 0 { 5 * n as i64 } else { 0 }),
        },
        tables,
    ))
}
fn expand<K: ChallengeField>(source: &[SmallTable]) -> Vec<Vec<K>> {
    source
        .iter()
        .map(|table| match table {
            SmallTable::Signed(v) => v.iter().map(|v| K::from_i64(i64::from(*v))).collect(),
            SmallTable::Unsigned(v) => v.iter().map(|v| K::from_i64(i64::from(*v))).collect(),
        })
        .collect()
}
fn transcript<K: ChallengeField>() -> Result<Transcript<K>, String> {
    Transcript::new(b"synthetic small-value baseline").map_err(|e| format!("{e:?}"))
}
fn encode<K: ChallengeField>(proof: &Proof<K>) -> Vec<u8> {
    proof
        .rounds
        .iter()
        .flatten()
        .chain(&proof.final_values)
        .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
        .collect()
}
fn decode<K: ChallengeField>(bytes: &[u8], m: u32, degree: usize) -> Result<Proof<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let wire = K::from_i64(0).to_le_bytes().as_ref().len();
    if bytes.len() != (m as usize * (degree + 1) + 4) * wire {
        return Err("ProofShape".into());
    }
    let values = bytes
        .chunks_exact(wire)
        .map(|raw| {
            K::from_le_bytes(raw.to_vec().try_into().map_err(|_| "NoncanonicalField")?)
                .ok_or("NoncanonicalField")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let split = m as usize * (degree + 1);
    Ok(Proof {
        rounds: values[..split]
            .chunks_exact(degree + 1)
            .map(|v| v.to_vec())
            .collect(),
        final_values: values[split..].to_vec(),
    })
}
fn produce<K: ChallengeField + Eq>(degree: usize, m: u32, k: u8) -> Result<Value, String> {
    let (i, source) = fixture::<K>(degree, m, k)?;
    let (mut proofs, mut continuations, mut times) = (vec![], vec![], vec![]);
    for iteration in 0..4 {
        let start = Instant::now();
        let mut pt = transcript::<K>()?;
        let proof = if k == 0 {
            prove(
                black_box(&i),
                Dense::new(&i, expand(black_box(&source))).map_err(|e| format!("{e:?}"))?,
                &mut pt,
            )
        } else {
            prove(
                black_box(&i),
                Small::new(&i, black_box(&source).clone(), k).map_err(|e| format!("{e:?}"))?,
                &mut pt,
            )
        }
        .map_err(|e| format!("{e:?}"))?;
        black_box(&proof);
        let elapsed = u64::try_from(start.elapsed().as_nanos()).map_err(|_| "time overflow")?;
        if iteration > 0 {
            times.push(elapsed);
        }
        let encoded = encode(&proof);
        if let Some(first) = proofs.first() {
            assert_eq!(first, &encoded);
        }
        proofs.push(encoded);
        continuations.push(
            pt.challenge(ChallengeLabel::Sumcheck)
                .map_err(|e| format!("{e:?}"))?
                .to_le_bytes()
                .as_ref()
                .to_vec(),
        );
    }
    Ok(
        json!({"prover_ns":times,"proofs":proofs,"continuations":continuations,
        "descriptor":i.encode().map_err(|e| format!("{e:?}"))?, "m":m,"degree":degree,"k":k,
        "caller_input_payload_bytes":4*(1usize<<m)*2}),
    )
}
fn consume<K: ChallengeField + Eq>(
    degree: usize,
    m: u32,
    k: u8,
    data: &Value,
) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let (i, source) = fixture::<K>(degree, m, k)?;
    if data["descriptor"] != json!(i.encode().map_err(|e| format!("{e:?}"))?)
        || data["m"] != m
        || data["degree"] != degree
        || data["k"] != k
    {
        return Err("descriptor mismatch".into());
    }
    let proofs: Vec<Vec<u8>> =
        serde_json::from_value(data["proofs"].clone()).map_err(|e| e.to_string())?;
    let next: Vec<Vec<u8>> =
        serde_json::from_value(data["continuations"].clone()).map_err(|e| e.to_string())?;
    if proofs.len() != 4 || next.len() != 4 {
        return Err("expected warmup and three proofs".into());
    }
    let (mut times, mut sc) = (vec![], json!(null));
    for (iteration, (bytes, continuation)) in proofs.iter().zip(&next).enumerate() {
        let proof = decode::<K>(bytes, m, degree)?;
        let start = Instant::now();
        let tables = expand(black_box(&source));
        let mut vt = transcript::<K>()?;
        let result = verify_public(
            black_box(&i),
            black_box(&proof),
            black_box(&tables),
            &mut vt,
        )
        .map_err(|e| format!("{e:?}"))?;
        black_box(&result);
        drop(tables);
        let elapsed = u64::try_from(start.elapsed().as_nanos()).map_err(|_| "time overflow")?;
        if iteration > 0 {
            times.push(elapsed);
        }
        assert_eq!(result.claims.len(), 4);
        assert_eq!(result.sc.numerator, u64::from(m) * degree as u64);
        let actual = vt
            .challenge(ChallengeLabel::Sumcheck)
            .map_err(|e| format!("{e:?}"))?;
        if actual.to_le_bytes().as_ref() != continuation {
            return Err("continuation mismatch".into());
        }
        sc = json!({"id":result.sc.id,"m":result.sc.m,"degree":result.sc.degree,"field_degree":result.sc.field_degree,"numerator":result.sc.numerator});
    }
    Ok(
        json!({"consumer_ns":times,"sc":sc,"verified_proofs":proofs.len(),"claims":4,"proof_payload_bytes":proofs[0].len()}),
    )
}
fn run<K: ChallengeField + Eq>(args: &[String]) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let degree = args[1].parse().map_err(|_| "invalid degree")?;
    let m = args[2].parse().map_err(|_| "invalid dimension")?;
    let k = args[3].parse().map_err(|_| "invalid prefix")?;
    match args[4].as_str() {
        "prove" => produce::<K>(degree, m, k),
        "consume" => {
            let mut input = String::new();
            std::io::stdin()
                .take((1 << 20) + 1)
                .read_to_string(&mut input)
                .map_err(|e| e.to_string())?;
            if input.len() > 1 << 20 {
                return Err("benchmark proof input too large".into());
            }
            consume::<K>(
                degree,
                m,
                k,
                &serde_json::from_str(&input).map_err(|e| e.to_string())?,
            )
        }
        _ => Err("expected prove|consume".into()),
    }
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        return Err("expected QM31|OM31 degree m k prove|consume (k=0 selects Dense)".into());
    }
    let output = match args[0].as_str() {
        "QM31" => run::<QM31>(&args)?,
        "OM31" => run::<OM31>(&args)?,
        _ => return Err("invalid field".into()),
    };
    println!("{output}");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn check<K: ChallengeField + Eq>()
    where
        K::Bytes: TryFrom<Vec<u8>>,
    {
        for degree in 0..=4 {
            let dense = produce::<K>(degree, 4, 0).expect("dense");
            for k in [0, 2, 3, 4] {
                let small = produce::<K>(degree, 4, k).expect("small");
                assert_eq!(dense["proofs"], small["proofs"]);
                assert_eq!(dense["continuations"], small["continuations"]);
                let result = consume::<K>(degree, 4, k, &small).expect("all four proofs consumed");
                assert_eq!(result["verified_proofs"], 4);
            }
        }
    }
    #[test]
    fn matches_reference_small_benchmark_pipeline() {
        check::<QM31>();
        check::<OM31>();
    }
    #[test]
    fn rejects_small_benchmark_false_final_and_missing_proof() {
        let data = produce::<QM31>(1, 4, 2).expect("proofs");
        let mut bad = data.clone();
        let final_byte = bad["proofs"][0].as_array().expect("proof").len() - 32;
        bad["proofs"][0][final_byte] =
            json!(bad["proofs"][0][final_byte].as_u64().expect("byte") ^ 1);
        assert_eq!(consume::<QM31>(1, 4, 2, &bad), Err("ClaimMismatch".into()));
        bad = data.clone();
        bad["proofs"].as_array_mut().expect("proofs").pop();
        assert!(consume::<QM31>(1, 4, 2, &bad).is_err());
        bad = data;
        bad["continuations"][0][0] = json!(255);
        assert!(consume::<QM31>(1, 4, 2, &bad).is_err());
        for (d, m, k) in [(5, 4, 2), (1, 1, 0), (1, 19, 0), (1, 2, 3), (1, 4, 1)] {
            assert!(fixture::<QM31>(d, m, k).is_err());
        }
    }
}
