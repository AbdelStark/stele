//! RFC-0010 A9 §4: the complete response block binds a real following A1 proof.
use crate::{
    check_proof_control,
    sumcheck::{instance, produce, Change},
};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_opening, Error, Failure, Functional, PreparedSource, ProofKind,
    Source, VerifiedCertificate,
};

fn check<K: ChallengeField + Eq + core::fmt::Debug>(
    certify: impl Fn(Source<K>, &[u8]) -> Result<VerifiedCertificate<K>, Error>,
    verify: impl Fn(
        &mut Transcript<K>,
        &VerifiedCertificate<K>,
        Functional<'_, K>,
        &[u8],
    ) -> Result<(), Failure>,
) -> Result<(), String> {
    let message = [M31::from_i64(6)];
    let prepared = PreparedSource::<K>::new(41, 0, 0, 2, &message, &mut HashUsage::default())
        .map_err(|e| format!("{e:?}"))?;
    let (bytes, _) = prepared.certificate().map_err(|e| format!("{e:?}"))?;
    let certificate = certify(*prepared.source(), &bytes).map_err(|e| format!("{e:?}"))?;
    let (a, b) = ([K::from_i64(1)], [K::from_i64(0)]);
    let functional = Functional {
        id: 12,
        a: &a,
        b: &b,
        value: K::from_i64(0),
    };
    let transcript = || Transcript::<K>::new(b"opening response continuation");
    let (opening, _) = prepared
        .opening(
            &mut transcript().map_err(|e| format!("{e:?}"))?,
            &certificate,
            functional,
        )
        .map_err(|e| format!("{e:?}"))?;
    let next = instance::<K>(88, false);
    let honest = || -> Result<_, String> {
        let mut t = transcript().map_err(|e| format!("{e:?}"))?;
        let (proof, _) = prepared
            .opening(&mut t, &certificate, functional)
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(proof, opening);
        Ok(vec![produce(&next, &mut t).map_err(|e| format!("{e:?}"))?])
    };
    let baseline = honest()?;
    let replay = |omit: bool| -> Result<_, String> {
        let mut t = transcript().map_err(|e| format!("{e:?}"))?;
        let mut frame = functional.id.to_le_bytes().to_vec();
        frame.extend_from_slice(&prepared.source().bytes());
        frame.extend_from_slice(&certificate.record().id());
        for value in [a[0], b[0], functional.value] {
            frame.extend_from_slice(value.to_le_bytes().as_ref());
        }
        let wire = prepared
            .source()
            .parse(ProofKind::Opening, &opening)
            .map_err(|e| format!("{e:?}"))?;
        t.absorb(AbsorbLabel::Opening, &frame)
            .map_err(|e| format!("{e:?}"))?;
        t.absorb(AbsorbLabel::OpeningRow, wire.row_bytes())
            .map_err(|e| format!("{e:?}"))?;
        for _ in 0..prepared.source().queries(ProofKind::Opening) {
            t.opening_column(4).map_err(|e| format!("{e:?}"))?;
        }
        if !omit {
            t.absorb(AbsorbLabel::OpeningColumns, wire.response_bytes())
                .map_err(|e| format!("{e:?}"))?;
        }
        produce(&next, &mut t).map_err(|e| format!("{e:?}"))
    };
    assert_eq!(replay(false)?, baseline[0]);
    let wrong = replay(true)?;
    assert_eq!(wrong.rounds, baseline[0].rounds);
    check_proof_control(
        honest,
        &Change {
            round: false,
            value: wrong.final_values[0],
        },
        |proofs| -> Result<(), String> {
            let mut t = transcript().map_err(|e| format!("{e:?}"))?;
            verify(&mut t, &certificate, functional, &opening)
                .map_err(|e| format!("{:?}", e.cause))?;
            stele_sumcheck::verify_public(
                &next,
                &proofs[0],
                &[vec![K::from_i64(3), K::from_i64(5)]],
                &mut t,
            )
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
        },
        "FinalEvaluationMismatch".to_owned(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// NC-0802: one next-instance final from an omitted OpeningColumns absorb.
pub fn run() -> Result<(), String> {
    check::<QM31>(
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|_| ()),
    )?;
    check::<OM31>(
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|_| ()),
    )
}

#[test]
fn rejects_opening_missing_response_continuation() {
    run().expect("the real next A1 verifier rejects the changed final");
}
