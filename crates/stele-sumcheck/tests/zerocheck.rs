//! RFC-0006 A3: both-field protocol bytes, every slice claim and phased SC records.
use serde_json::Value;
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    zerocheck::{Proof, Zerocheck},
    Error, Instance, Term,
};
pub mod support;
use support::{array, field, number, values};

#[cfg(feature = "controls")]
fn forged_finals<K: ChallengeField + Eq + core::fmt::Debug>() {
    use stele_hash::AbsorbLabel;
    for (m, skip) in [(0, 0), (2, 0), (2, 1)] {
        let one = K::from_i64(1);
        let instance = Instance {
            id: 2302,
            num_vars: m,
            inputs: vec![7, 8],
            terms: vec![
                Term {
                    coefficient: one,
                    factors: vec![0, 0],
                },
                Term {
                    coefficient: -one,
                    factors: vec![1],
                },
            ],
            claimed_sum: K::from_i64(0),
        };
        let x: Vec<_> = (0..1 << m).map(K::from_i64).collect();
        let tables = vec![x.clone(), x.iter().map(|v| *v * *v).collect()];
        let z = Zerocheck {
            instance: &instance,
            skip,
        };
        let (mut ordinary_t, mut restored_t) = (transcript(), transcript());
        let ordinary = z
            .prove_with_point(&tables, &mut ordinary_t)
            .expect("honest");
        let restored = z
            .prove_forged_finals(&tables, &tables, &mut restored_t)
            .expect("restored");
        assert_eq!(
            ordinary, restored,
            "same tables retain every proof value and point"
        );
        assert_eq!(ordinary_t.usage(), restored_t.usage());
        assert_eq!(
            ordinary_t.challenge(ChallengeLabel::Sumcheck),
            restored_t.challenge(ChallengeLabel::Sumcheck)
        );
        let honest = z
            .verify_public(&restored.0, &tables, &mut transcript())
            .expect("honest source claims");
        assert_eq!(honest.claims.len(), tables.len() * (1 << skip));

        let mut changed = tables.clone();
        changed[1][0] = changed[1][0] + one;
        assert_eq!(
            changed
                .iter()
                .flatten()
                .zip(tables.iter().flatten())
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        let mut producer = transcript();
        let (proof, tail) = z
            .prove_forged_finals(&tables, &changed, &mut producer)
            .expect("adversary emits genuine finals");
        assert_eq!(proof.skip_values, ordinary.0.skip_values);
        assert_eq!(proof.rounds, ordinary.0.rounds);
        assert_eq!(tail, ordinary.1);
        assert_ne!(proof.final_values, ordinary.0.final_values);
        assert_eq!(
            z.verify(&proof, &mut transcript()).err(),
            Some(Error::FinalEvaluationMismatch)
        );
        let slices = 1 << skip;
        for (i, table) in changed.iter().enumerate() {
            for b in 0..slices {
                let mut point: Vec<_> = (0..skip)
                    .map(|bit| K::from_i64(((b >> (skip - bit - 1)) & 1) as i64))
                    .collect();
                point.extend_from_slice(&tail);
                let weights = stele_poly::eq_table(&point).expect("point");
                let actual = table
                    .iter()
                    .zip(weights)
                    .fold(K::from_i64(0), |v, (x, w)| v + *x * w);
                assert_eq!(
                    proof.final_values[i * slices + b],
                    actual,
                    "true changed-table evaluation"
                );
            }
        }
        // RFC-0006 A3: independently replay the emitted frames, including changed finals.
        let mut replay = transcript::<K>();
        replay
            .absorb(AbsorbLabel::Zero, &z.encode().expect("descriptor"))
            .expect("zero");
        for _ in 0..m - u32::from(skip) {
            replay.challenge(ChallengeLabel::ZeroWeight).expect("alpha");
        }
        if skip > 0 {
            let bytes = stele_sumcheck::message_bytes(
                instance.id,
                proof.skip_values.len() as u32,
                &proof.skip_values,
            )
            .expect("skip");
            replay.absorb(AbsorbLabel::ZeroSkip, &bytes).expect("skip");
            replay.challenge(ChallengeLabel::Sumcheck).expect("u");
        }
        for (h, row) in proof.rounds.iter().enumerate() {
            let bytes = stele_sumcheck::message_bytes(instance.id, h as u32, row).expect("row");
            replay.absorb(AbsorbLabel::Round, &bytes).expect("row");
            assert_eq!(
                replay.challenge(ChallengeLabel::Sumcheck).expect("tail"),
                tail[h]
            );
        }
        let mut finals = instance.id.to_le_bytes().to_vec();
        finals.extend_from_slice(&(tables.len() as u32).to_le_bytes());
        finals.extend_from_slice(&(slices as u32).to_le_bytes());
        for value in &proof.final_values {
            finals.extend_from_slice(value.to_le_bytes().as_ref());
        }
        replay
            .absorb(AbsorbLabel::ZeroFinal, &finals)
            .expect("finals");
        assert_eq!(producer.usage(), replay.usage());
        assert_eq!(
            producer.challenge(ChallengeLabel::Sumcheck),
            replay.challenge(ChallengeLabel::Sumcheck)
        );

        let mut missing_table = tables.clone();
        missing_table.pop();
        let mut short_table = tables.clone();
        short_table[0].pop();
        for bad in [missing_table, short_table] {
            for (rounds, finals) in [(&bad, &tables), (&tables, &bad)] {
                let mut rejected = transcript::<K>();
                assert_eq!(
                    z.prove_forged_finals(rounds, finals, &mut rejected).err(),
                    Some(Error::PublicShape)
                );
                assert_eq!(
                    rejected.usage(),
                    transcript::<K>().usage(),
                    "shape rejected before transcript work"
                );
            }
        }
    }
}

#[cfg(feature = "controls")]
#[test]
fn rejects_forged_finals_from_one_changed_table_entry() {
    forged_finals::<QM31>();
    forged_finals::<OM31>();
}

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"zerocheck").expect("public")
}
fn rows<K: ChallengeField>(v: &Value) -> Vec<Vec<K>>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    v.as_array().expect("fixture").iter().map(values).collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(v: &Value)
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let i = &v["instance"];
    let instance = support::zerocheck_instance::<K>(i);
    let z = Zerocheck {
        instance: &instance,
        skip: number(&i["k"]) as u8,
    };
    let tables = rows::<K>(&v["tables"]);
    let expected = Proof {
        skip_values: values(&v["proof"]["skip"]),
        rounds: rows(&v["proof"]["rounds"]),
        final_values: rows::<K>(&v["proof"]["final"])
            .into_iter()
            .flatten()
            .collect(),
    };
    let new = transcript::<K>;
    let mut pt = new();
    let proof = z.prove(&tables, &mut pt).expect("fixture");
    assert_eq!(proof, expected);
    assert_eq!(
        hex(&z.encode().expect("fixture")),
        v["descriptor_hex"].as_str().expect("fixture")
    );
    let mut vt = new();
    let result = z.verify_public(&proof, &tables, &mut vt).expect("fixture");
    assert_eq!(result.claims.len(), array(&v["receipt"]["claims"]).len());
    for (actual, expected) in result.claims.iter().zip(array(&v["receipt"]["claims"])) {
        assert_eq!(actual.tensor, number(&expected[0]));
        assert_eq!(actual.point, values(&expected[1]));
        assert_eq!(actual.value, field(&expected[2]));
    }
    for (phase, (record, expected)) in result.sc.iter().zip(array(&v["receipt"]["sc"])).enumerate()
    {
        assert_eq!(number(&expected["phase"]), phase as u64);
        assert_eq!(record.id, instance.id);
        assert_eq!(record.m as u64, number(&expected["m"]));
        assert_eq!(record.degree as u64, number(&expected["degree"]));
        assert_eq!(record.field_degree as u64, number(&v["field"]));
        assert_eq!(record.numerator, number(&expected["numerator"]));
    }
    for t in [&mut pt, &mut vt] {
        assert_eq!(
            hex(t
                .challenge(ChallengeLabel::Sumcheck)
                .expect("fixture")
                .to_le_bytes()
                .as_ref()),
            v["continuation_challenge"].as_str().expect("fixture")
        );
    }
    let mut bad = proof.clone();
    *bad.final_values.last_mut().expect("fixture") =
        *bad.final_values.last().expect("fixture") + K::from_i64(1);
    assert!(z.verify(&bad, &mut new()).is_ok());
    assert_eq!(
        z.verify_public(&bad, &tables, &mut new()).err(),
        Some(Error::ClaimMismatch)
    );
    for part in 0..3 {
        let mut bad = proof.clone();
        match part {
            0 => bad.skip_values.push(K::from_i64(0)),
            1 => bad.rounds.push(vec![]),
            _ => bad.final_values.pop().map(|_| ()).expect("fixture"),
        }
        let mut t = new();
        assert_eq!(z.verify(&bad, &mut t).err(), Some(Error::ProofShape));
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck).expect("fixture"),
            new().challenge(ChallengeLabel::Sumcheck).expect("fixture")
        );
    }
}
#[test]
fn matches_reference_zerocheck_bytes_and_accounting() {
    let lines = include_str!("../../../research/zerocheck/vectors.jsonl");
    assert_eq!(lines.lines().count(), 130);
    for line in lines.lines() {
        let v: Value = serde_json::from_str(line).expect("fixture");
        if v["field"] == 4 {
            check::<QM31>(&v)
        } else {
            check::<OM31>(&v)
        }
    }
}

fn retained_point<K: ChallengeField + Eq + core::fmt::Debug>() {
    for (m, skip) in [(0, 0), (2, 0), (2, 1)] {
        let zero = K::from_i64(0);
        let one = K::from_i64(1);
        let instance = Instance {
            id: 2301,
            num_vars: m,
            inputs: vec![7, 8],
            terms: vec![
                Term {
                    coefficient: one,
                    factors: vec![0, 0],
                },
                Term {
                    coefficient: -one,
                    factors: vec![1],
                },
            ],
            claimed_sum: zero,
        };
        let values: Vec<_> = (0..1 << m).map(K::from_i64).collect();
        let mut tables = vec![values.clone(), values.iter().map(|v| *v * *v).collect()];
        let z = Zerocheck {
            instance: &instance,
            skip,
        };
        let (mut a, mut b) = (transcript(), transcript());
        let ordinary = z.prove(&tables, &mut a).expect("honest relation");
        let (retained, tail) = z
            .prove_with_point(&tables, &mut b)
            .expect("honest relation");
        assert_eq!(ordinary, retained);
        assert_eq!(a.usage(), b.usage());
        assert_eq!(
            a.challenge(ChallengeLabel::Sumcheck),
            b.challenge(ChallengeLabel::Sumcheck)
        );
        let reduction = z
            .verify_public(&retained, &tables, &mut transcript())
            .expect("actual source consumers");
        assert_eq!(tail.len(), m as usize - usize::from(skip));
        for claim in reduction.claims {
            assert_eq!(&claim.point[usize::from(skip)..], tail);
        }
        tables[1][0] = tables[1][0] + one;
        let (mut a, mut b) = (transcript(), transcript());
        let old = z.prove(&tables, &mut a).expect_err("one false row");
        let new = z
            .prove_with_point(&tables, &mut b)
            .expect_err("one false row");
        assert_eq!(old, new);
        assert_eq!(a.usage(), b.usage());
    }
}

#[test]
fn matches_reference_retained_tail_and_failed_prefix() {
    retained_point::<QM31>();
    retained_point::<OM31>();
}

#[test]
fn rejects_invalid_zero_descriptors_and_accepts_empty_relations() {
    use stele_field::Field;
    let (zero, one) = (QM31::from_i64(0), QM31::from_i64(1));
    for m in [0, 2] {
        let mut i = Instance {
            id: 1,
            num_vars: m,
            inputs: vec![],
            terms: vec![],
            claimed_sum: zero,
        };
        let z = Zerocheck {
            instance: &i,
            skip: 0,
        };
        let p = z
            .prove(&[], &mut transcript())
            .expect("empty zero relation");
        let r = z
            .verify_public(&p, &[], &mut transcript())
            .expect("closed empty relation");
        assert!(r.claims.is_empty());
        assert_eq!(r.sc.map(|r| r.numerator), [u64::from(m), 0, 0]);
        for skip in [1, 3, 5] {
            assert_eq!(
                Zerocheck { instance: &i, skip }.encode(),
                Err(Error::InvalidZerocheck)
            );
        }
        i.terms.push(Term {
            coefficient: one,
            factors: vec![],
        });
        let expected = if m == 0 {
            Error::FinalEvaluationMismatch
        } else {
            Error::RoundSumMismatch
        };
        assert_eq!(
            Zerocheck {
                instance: &i,
                skip: 0
            }
            .prove(&[], &mut transcript()),
            Err(expected)
        );
        i.claimed_sum = one;
        assert_eq!(
            Zerocheck {
                instance: &i,
                skip: 0
            }
            .encode(),
            Err(Error::InvalidZerocheck)
        );
    }
}
