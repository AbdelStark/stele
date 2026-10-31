//! RFC-0010 A9 §5: actual A1 originals, including unused and zero-coefficient inputs.
use crate::{check_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, Functional, PreparedSource, VerifiedCertificate};
use stele_reductions::{verify_field_sources, Error};
use stele_sumcheck::{Dense, Instance, Proof, Term};

const PUBLIC: &[u8] = b"A1 closed source oracle";

fn bundle<K: ChallengeField>(id: u64, certificates: &[VerifiedCertificate<K>]) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(certificates.len() as u32).to_le_bytes());
    for certificate in certificates {
        bytes.extend_from_slice(&certificate.record().source().bytes());
        bytes.extend_from_slice(&certificate.record().id());
    }
    bytes
}
fn bind<K: ChallengeField>(
    t: &mut Transcript<K>,
    id: u64,
    certificates: &[VerifiedCertificate<K>],
) {
    t.absorb(AbsorbLabel::FieldSources, &bundle(id, certificates))
        .expect("bundle");
}

fn opening<K: ChallengeField>(
    t: &mut Transcript<K>,
    prepared: &PreparedSource<'_, K>,
    certificate: &VerifiedCertificate<K>,
    point: &[K],
    value: K,
) -> Vec<u8> {
    let source = prepared.source();
    let row_vars = source.rows().trailing_zeros() as usize;
    assert_eq!(
        point.len(),
        row_vars + source.columns().trailing_zeros() as usize
    );
    // Independent MSB weights for the tiny fixture, including empty row/column points.
    let weights = |point: &[K]| {
        point.iter().fold(vec![K::from_i64(1)], |values, r| {
            values
                .into_iter()
                .flat_map(|v| [v * (K::from_i64(1) - *r), v * *r])
                .collect::<Vec<_>>()
        })
    };
    let (rows, columns) = point.split_at(row_vars);
    prepared
        .opening(
            t,
            certificate,
            Functional {
                id: prepared.source().descriptor().id,
                a: &weights(rows),
                b: &weights(columns),
                value,
            },
        )
        .expect("opening")
        .0
}

struct Fixture<K: ChallengeField> {
    instance: Instance<K>,
    certificates: Vec<VerifiedCertificate<K>>,
    proof: Proof<K>,
    openings: Vec<Vec<u8>>,
    #[cfg(test)]
    usage: HashUsage,
    #[cfg(test)]
    wire: Vec<String>,
}
fn fixture<K: ChallengeField + CodeField + Eq>(zero: bool, ell: u8, m: u8) -> Fixture<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let messages = [[2, 3, 5, 7], [11, 13, 17, 19]].map(|r| r.map(M31::from_i64));
    // The zero-variable case also exercises a single original source.
    let messages = &messages[..if ell + m == 0 { 1 } else { 2 }];
    let size = 1usize << (ell + m);
    let prepared: Vec<_> = messages
        .iter()
        .enumerate()
        .map(|(n, message)| {
            PreparedSource::<K>::new(
                41 + n as u64,
                ell,
                m,
                1,
                &message[..size],
                &mut HashUsage::default(),
            )
            .expect("source")
        })
        .collect();
    let certificate_bytes: Vec<_> = prepared
        .iter()
        .map(|s| s.certificate().expect("certificate").0)
        .collect();
    let certificates: Vec<_> = prepared
        .iter()
        .zip(&certificate_bytes)
        .map(|(source, bytes)| {
            verify_certificate(*source.source(), bytes)
                .expect("verified certificate")
                .0
        })
        .collect();
    let coefficient = i64::from(!zero);
    let instance = Instance {
        id: 71,
        num_vars: u32::from(ell + m),
        inputs: (0..messages.len()).map(|n| 41 + n as u64).collect(),
        terms: vec![Term {
            coefficient: K::from_i64(coefficient),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(
            messages[0][..size]
                .iter()
                .map(|x| i64::from(x.as_u32()))
                .sum::<i64>()
                * coefficient,
        ),
    };
    let tables = messages
        .iter()
        .map(|row| {
            row[..size]
                .iter()
                .map(|x| K::from_i64(i64::from(x.as_u32())))
                .collect()
        })
        .collect();
    let mut t = Transcript::<K>::new(PUBLIC).expect("transcript");
    bind(&mut t, instance.id, &certificates);
    let proof = stele_sumcheck::prove(
        &instance,
        Dense::new(&instance, tables).expect("dense"),
        &mut t,
    )
    .expect("A1 proof");
    // Obtain the actual prover point by a full replay, without a randomness hook.
    let mut replay = Transcript::<K>::new(PUBLIC).expect("replay");
    bind(&mut replay, instance.id, &certificates);
    let reduction = stele_sumcheck::verify(&instance, &proof, &mut replay).expect("A1 replay");
    assert_eq!(t.usage(), replay.usage());
    let openings: Vec<_> = prepared
        .iter()
        .zip(&certificates)
        .zip(&reduction.claims)
        .map(|((source, certificate), (_, value))| {
            opening(&mut t, source, certificate, &reduction.point, *value)
        })
        .collect();
    #[cfg(test)]
    let usage = t.usage();
    #[cfg(test)]
    let wire = {
        let mut bytes = vec![bundle(instance.id, &certificates)];
        bytes.extend(certificate_bytes);
        bytes.push(instance.encode().expect("instance"));
        for (n, values) in proof.rounds.iter().enumerate() {
            bytes
                .push(stele_sumcheck::message_bytes(instance.id, n as u32, values).expect("round"));
        }
        bytes.push(
            stele_sumcheck::message_bytes(
                instance.id,
                instance.inputs.len() as u32,
                &proof.final_values,
            )
            .expect("final"),
        );
        bytes.extend(openings.iter().cloned());
        bytes.push(
            t.challenge(stele_hash::ChallengeLabel::Sumcheck)
                .expect("continuation")
                .to_le_bytes()
                .as_ref()
                .to_vec(),
        );
        core::iter::once(<K as CodeField>::DEGREE.to_string())
            .chain(bytes.iter().map(|b| hex(b)))
            .collect()
    };
    Fixture {
        instance,
        certificates,
        proof,
        openings,
        #[cfg(test)]
        usage,
        #[cfg(test)]
        wire,
    }
}

struct Change;
impl ProverHook<bool> for Change {
    fn tamper(&self, changed: &mut bool) {
        *changed = true;
    }
}
fn control<K: ChallengeField + CodeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let f = fixture::<K>(false, 1, 1);
    let certificates: Vec<_> = f.certificates.iter().collect();
    let message = [2, 3, 5, 7].map(M31::from_i64);
    let prepared =
        PreparedSource::<K>::new(41, 1, 1, 1, &message, &mut HashUsage::default()).expect("source");
    check_control(
        &false,
        &Change,
        |changed| {
            let mut proof = f.proof.clone();
            if *changed {
                proof.final_values[1] = proof.final_values[1] + K::from_i64(1);
            }
            assert_eq!(proof.rounds, f.proof.rounds);
            assert_eq!(
                proof
                    .final_values
                    .iter()
                    .zip(&f.proof.final_values)
                    .filter(|(a, b)| a != b)
                    .count(),
                usize::from(*changed)
            );
            let mut t = Transcript::<K>::new(PUBLIC).expect("transcript");
            bind(&mut t, f.instance.id, &f.certificates);
            let reduction = stele_sumcheck::verify(&f.instance, &proof, &mut t)
                .expect("unused final passes A1");
            // Refresh the preceding opening after the changed Final; keep the unused source proof fixed.
            let first = opening(
                &mut t,
                &prepared,
                &f.certificates[0],
                &reduction.point,
                reduction.claims[0].1,
            );
            if !*changed {
                assert_eq!(first, f.openings[0]);
            }
            Ok::<_, Error>((proof, first))
        },
        |(proof, first)| {
            let mut t = Transcript::<K>::new(PUBLIC).expect("transcript");
            let result = verify_field_sources(
                &mut t,
                &f.instance,
                &certificates,
                proof,
                &[first, &f.openings[1]],
            );
            if proof != &f.proof {
                let failed = result.as_ref().err().expect("unused final rejects");
                let source = f.certificates[0].record().source();
                assert_eq!(
                    failed.usage.non_transcript.hash_evaluations,
                    u64::from(source.parameters().opening_queries)
                        * (1 + source.path_height() as u64)
                );
                assert_eq!(
                    failed.usage.transcript.column_attempts,
                    u64::from(source.parameters().opening_queries)
                );
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        Error::Pcs(stele_pcs::Error::ValueMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

/// NC-0609 changes one unused A1 final, then reaches its actual terminal opening.
pub fn run() -> Result<(), String> {
    control::<QM31>()?;
    control::<OM31>()
}

#[cfg(test)]
fn contract<K: ChallengeField + CodeField + Eq>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for (ell, m, zero) in [(1, 1, false), (1, 1, true), (0, 0, false), (2, 0, false)] {
        let f = fixture::<K>(zero, ell, m);
        let certificates: Vec<_> = f.certificates.iter().collect();
        let openings: Vec<_> = f.openings.iter().map(Vec::as_slice).collect();
        let (record, usage) = {
            let mut t = Transcript::<K>::new(PUBLIC).expect("transcript");
            let proof = f.proof.clone();
            let result =
                verify_field_sources(&mut t, &f.instance, &certificates, &proof, &openings)
                    .expect("closed A1");
            let continuation = t
                .challenge(stele_hash::ChallengeLabel::Sumcheck)
                .expect("continuation");
            assert_eq!(
                hex(continuation.to_le_bytes().as_ref()),
                *f.wire.last().expect("wire")
            );
            result
        };
        assert_eq!(record.sc().id, 71);
        assert_eq!(record.sc().numerator, u64::from(f.instance.num_vars)); // Zero coefficients keep the degree.
        assert_eq!(record.openings().len(), f.certificates.len());
        let mut hashes = 0;
        for (opening, certificate) in record.openings().iter().zip(&f.certificates) {
            assert!(core::ptr::eq(opening.certificate(), certificate.record()));
            assert_eq!(opening.id(), certificate.record().source().descriptor().id);
            hashes += u64::from(opening.queries())
                * (1 + certificate.record().source().path_height() as u64);
        }
        assert_eq!(usage.non_transcript.hash_evaluations, hashes);
        assert_eq!(usage.transcript, f.usage);
        if f.instance.num_vars == 0 {
            assert_eq!(hashes, 2);
        }
    }
    let instance = Instance::<K> {
        id: 72,
        num_vars: 2,
        inputs: vec![],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![],
        }],
        claimed_sum: K::from_i64(4),
    };
    let mut t = Transcript::<K>::new(PUBLIC).expect("transcript");
    bind(&mut t, instance.id, &[]);
    let proof = stele_sumcheck::prove(
        &instance,
        Dense::new(&instance, vec![]).expect("constant"),
        &mut t,
    )
    .expect("proof");
    let mut verifier = Transcript::<K>::new(PUBLIC).expect("transcript");
    let (record, usage) =
        verify_field_sources(&mut verifier, &instance, &[], &proof, &[]).expect("empty originals");
    assert_eq!(record.sc().numerator, 0);
    assert!(record.openings().is_empty());
    assert_eq!(usage.transcript, t.usage());
    assert_eq!(usage.non_transcript, HashUsage::default());
}
#[test]
fn accepts_qm31_closed_originals() {
    contract::<QM31>();
}
#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn matches_reference_closed_a1_bytes() {
    let expected = include_str!("../fixtures/field-sources.txt");
    let actual = [
        fixture::<QM31>(false, 1, 1).wire.join("|"),
        fixture::<OM31>(false, 1, 1).wire.join("|"),
    ]
    .join("\n")
        + "\n";
    assert_eq!(actual, expected);
}
#[test]
fn accepts_om31_closed_originals() {
    contract::<OM31>();
}

#[cfg(test)]
fn failures<K: ChallengeField + CodeField + Eq>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let f = fixture::<K>(false, 1, 1);
    let certificates: Vec<_> = f.certificates.iter().collect();
    let openings: Vec<_> = f.openings.iter().map(Vec::as_slice).collect();
    for case in 0..10 {
        let (mut instance, mut proof) = (f.instance.clone(), f.proof.clone());
        let mut roster = certificates.clone();
        let mut bytes = f.openings.clone();
        let mut cause = Error::SourceRoster;
        match case {
            0 => roster.clear(),
            1 => roster.reverse(),
            2 => roster[1] = roster[0],
            3 => {
                bytes.pop();
            }
            4 => bytes.push(f.openings[1].clone()),
            5 => instance.inputs[1] = 43,
            6 => {
                instance.num_vars += 1;
                proof.rounds.push(proof.rounds[0].clone());
            }
            7 => {
                proof.rounds[0].pop();
                cause = Error::Sumcheck(stele_sumcheck::Error::ProofShape);
            }
            8 => {
                bytes[1].pop();
                cause = Error::Pcs(stele_pcs::Error::ProofShape);
            }
            9 => {
                bytes[1][1..5].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
                cause = Error::Pcs(stele_pcs::Error::NoncanonicalField);
            }
            _ => unreachable!("fixed case inventory"),
        }
        let bytes: Vec<_> = bytes.iter().map(Vec::as_slice).collect();
        let mut t = Transcript::<K>::new(PUBLIC).expect("fresh attempt");
        let before = t.usage();
        let failure = verify_field_sources(&mut t, &instance, &roster, &proof, &bytes)
            .err()
            .expect("preflight rejection");
        assert_eq!(failure.cause, cause, "case {case}");
        assert_eq!(
            failure.usage,
            stele_pcs::Usage {
                transcript: before,
                non_transcript: HashUsage::default(),
            }
        );
        assert_eq!(t.usage(), before);
    }
    let mut path = f.openings[1].clone();
    path[1 + 2 * 4 * usize::from(<K as CodeField>::DEGREE) + 8] ^= 1;
    let mut t = Transcript::<K>::new(PUBLIC).expect("fresh attempt");
    let failure = verify_field_sources(
        &mut t,
        &f.instance,
        &certificates,
        &f.proof,
        &[&f.openings[0], &path],
    )
    .err()
    .expect("later Merkle path");
    assert_eq!(
        failure.cause,
        Error::Pcs(stele_pcs::Error::Merkle(
            stele_hash::merkle::Error::RootMismatch
        ))
    );
    assert_eq!(failure.usage.non_transcript.hash_evaluations, 130 * 3 + 3);
    assert_eq!(failure.usage.transcript.column_attempts, 131);
    assert_eq!(failure.usage.transcript, t.usage());
    for point in [vec![], vec![K::from_i64(0); 3]] {
        let mut t = Transcript::<K>::new(PUBLIC).expect("fresh attempt");
        let before = t.usage();
        let failure = stele_pcs::verify_point(
            &mut t,
            certificates[0],
            41,
            &point,
            K::from_i64(0),
            openings[0],
        )
        .err()
        .expect("point shape");
        assert_eq!(failure.cause, stele_pcs::Error::FunctionalShape);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        assert_eq!(t.usage(), before);
    }
}
#[test]
fn rejects_qm31_later_source_and_roster() {
    failures::<QM31>();
}
#[test]
fn rejects_om31_later_source_and_roster() {
    failures::<OM31>();
}
