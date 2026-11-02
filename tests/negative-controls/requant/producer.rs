//! RFC-0023 §6: native production from original inputs, compared to frozen bytes.
use super::*;
use stele_pcs::PreparedSource;
use stele_reductions::requant::{Error, ProducerLimits};

pub(super) fn frozen<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    kind: &str,
    c: &Value,
    schema: &Schema,
    descriptor: &Descriptor<'_, '_, K>,
    input: &VerifiedCertificate<K>,
    advice: &VerifiedCertificate<K>,
) -> Vec<u8>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let inputs: &[i32] = match kind {
        "scalar" => &[-128],
        "wide" => &[i32::MIN, i32::MAX],
        "shift62" => &[i32::MIN, 0],
        "ties" => &[-1, 1],
        "padded" => &[-1, 0, 1],
        _ => unreachable!("only five honest frozen cases"),
    };
    let n = inputs.len().next_power_of_two();
    let saved: Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/requant-production/usage.json"),
        )
        .expect("saved producer observations"),
    )
    .expect("saved producer observations");
    let saved = &saved[format!("{kind}-K{}", <K as CodeField>::DEGREE)];
    let witness = schema
        .witness(inputs, (4 + schema.rows()) * n)
        .expect("valid fixed fixture");
    let mut preparation = [HashUsage::default(); 2];
    let sources = [
        PreparedSource::<K>::new(
            73,
            2,
            n.ilog2() as u8,
            1,
            witness.input(),
            &mut preparation[0],
        )
        .expect("valid fixed fixture"),
        PreparedSource::<K>::new(
            (31u64 << 40) + 2,
            schema.rows().ilog2() as u8,
            n.ilog2() as u8,
            c["blowup"].as_u64().expect("valid fixed fixture") as u8,
            witness.advice(),
            &mut preparation[1],
        )
        .expect("valid fixed fixture"),
    ];
    assert_eq!(sources[0].source().bytes(), input.record().source().bytes());
    assert_eq!(
        sources[1].source().bytes(),
        advice.record().source().bytes()
    );
    let (input_packet, input_usage) = sources[0].certificate().expect("actual input production");
    assert_eq!(
        hashes(preparation[0]),
        saved["input_production"]["non_transcript"]
    );
    assert_eq!(
        hashes(input_usage),
        saved["input_production"]["created_transcripts"][0]
    );
    assert_eq!(
        hashes(preparation[1]),
        saved["advice_production"][0]["non_transcript"]
    );
    assert_eq!(
        input_packet,
        fixture(
            c["input_certificate"]
                .as_str()
                .expect("valid fixed fixture")
        )
    );
    let (packet, advice_usage) = sources[1].certificate().expect("actual advice production");
    assert_eq!(
        hashes(advice_usage),
        saved["advice_production"][1]["created_transcripts"][0]
    );
    let (registered, imported) =
        verify_certificate(*sources[1].source(), &packet).expect("actual advice import");
    assert_eq!(
        hashes(imported.transcript),
        saved["advice_production"][2]["created_transcripts"][0]
    );
    assert_eq!(
        hashes(imported.non_transcript),
        saved["advice_production"][2]["non_transcript"]
    );
    assert_eq!(registered.record().id(), advice.record().id());
    let public = unhex(&c["public_hex"]);
    let limits = ProducerLimits {
        public_bytes: descriptor
            .producer_public_bytes()
            .expect("valid fixed fixture"),
        dense_elements: descriptor
            .producer_dense_elements()
            .expect("valid fixed fixture"),
    };
    let mut transcript = Transcript::new(&public).expect("valid fixed fixture");
    let (wire, usage, work) = descriptor
        .prove_measured(&mut transcript, [&sources[0], &sources[1]], &packet, limits)
        .expect("valid fixed fixture");
    let width = core::mem::size_of::<K>();
    assert!(work.proof_bytes >= wire.len());
    assert!(work.aggregate_tables_bytes >= (5 + schema.rows()) * n * width);
    assert!(work.output_tables_bytes >= (2 + schema.values()[2].value().len()) * n * width);
    assert!(work.aggregate_point_bytes >= n.ilog2() as usize * width);
    assert!(work.output_point_bytes >= n.ilog2() as usize * width);
    for (actual, (rows, count)) in work.group_coefficients_bytes.iter().zip([
        (4, 4),
        (schema.rows(), schema.rows()),
        (schema.rows(), 1 + schema.values()[2].value().len()),
    ]) {
        assert!(actual[0] >= rows * width && actual[1] >= n * width && actual[2] >= count * width);
    }
    assert_eq!(usage.transcript, transcript.usage());
    assert_eq!(observed(usage), saved["usage"]);
    assert_eq!(hashes(usage.transcript), c["expected"]["records"]["usage"]);
    for roster in usage.registrations {
        assert_eq!(
            roster.iter().filter(|r| r.is_some()).count(),
            c["repetitions"].as_u64().expect("valid fixed fixture") as usize
        );
    }
    let expected = &c["expected"]["following_a1"];
    let next = stele_sumcheck::Instance {
        id: (31u64 << 40) + (1 << 29),
        num_vars: 1,
        inputs: vec![(31u64 << 40) + (1 << 29) + 1],
        terms: vec![stele_sumcheck::Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(3),
    };
    let proof = stele_sumcheck::prove(
        &next,
        stele_sumcheck::Dense::new(&next, vec![vec![K::from_i64(1), K::from_i64(2)]])
            .expect("valid fixed fixture"),
        &mut transcript,
    )
    .expect("valid fixed fixture");
    assert_eq!(fields(&proof.final_values), expected["proof"]["final"]);
    assert_eq!(
        proof.rounds.iter().map(|r| fields(r)).collect::<Vec<_>>(),
        expected["proof"]["rounds"]
            .as_array()
            .expect("valid fixed fixture")
            .clone()
    );
    assert_eq!(
        hex(transcript
            .challenge(ChallengeLabel::Sumcheck)
            .expect("valid fixed fixture")
            .to_le_bytes()
            .as_ref()),
        expected["continuation"]
    );
    if kind == "scalar" {
        for (cap, cause) in [
            (
                ProducerLimits {
                    public_bytes: limits.public_bytes - 1,
                    ..limits
                },
                Error::ResourceLimit,
            ),
            (
                ProducerLimits {
                    dense_elements: limits.dense_elements - 1,
                    ..limits
                },
                Error::ResourceLimit,
            ),
        ] {
            let mut t = Transcript::new(&public).expect("valid fixed fixture");
            let before = t.usage();
            let f = descriptor
                .prove(&mut t, [&sources[0], &sources[1]], &packet, cap)
                .expect_err("invalid fixed input");
            assert_eq!(f.cause, cause);
            assert_eq!(f.usage.transcript, before);
            assert_eq!(f.usage.non_transcript, HashUsage::default());
            assert_eq!(f.usage.registrations, [[None; 2]; 2]);
        }
        let mut t = Transcript::new(&public).expect("valid fixed fixture");
        let before = t.usage();
        let f = descriptor
            .prove(&mut t, [&sources[1], &sources[0]], &packet, limits)
            .expect_err("invalid fixed input");
        assert_eq!(f.cause, Error::CertificateContext);
        assert_eq!(t.usage(), before);
        let mut changed = packet.clone();
        *changed.last_mut().expect("valid fixed fixture") ^= 1;
        let f = descriptor
            .prove(&mut t, [&sources[0], &sources[1]], &changed, limits)
            .expect_err("invalid fixed input");
        assert_eq!(f.cause, Error::CertificateIdentity);
        assert_eq!(t.usage(), before);
        assert_eq!(
            f.usage.non_transcript,
            HashUsage {
                hash_evaluations: 1,
                ..HashUsage::default()
            }
        );
    }
    wire
}

fn observed(u: stele_reductions::requant::ProverUsage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript),
        "registrations":u.registrations.map(|rs| rs.map(|r| r.map(|r| json!({"production":hashes(r.production),"verification":super::usage(r.verification)}))))})
}
