//! RFC-0008 A5 §§3–6: actual producer registrations and failed-attempt observations.
use core::fmt::Debug;
use stele_cqis::tables::TableField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind, VerifiedCertificate};
use stele_reductions::lookup::{
    Descriptor, Error, Layout, Limits, ProducerLimits, ProverFailure, Statement, Table,
    TableDescriptor,
};

const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"native lookup producer integration").expect("fixed fixture prefix")
}
fn certify<K: ChallengeField + CodeField>(p: &PreparedSource<'_, K>) -> VerifiedCertificate<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (bytes, _) = p.certificate().expect("actual original certificate");
    verify_certificate(*p.source(), &bytes)
        .expect("actual original verification")
        .0
}
fn registrations<K: ChallengeField + CodeField + TableField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let cases = [
        (Table::range(8).expect("range"), 0u8, 0u8, 1usize, false),
        (
            Table::generate(TableDescriptor::new("exp_q/hi", 1, &[7, 0, 0, 6]).expect("shape"))
                .expect("partial prefix"),
            2,
            0,
            2,
            false,
        ),
        (
            Table::generate(TableDescriptor::new("exp_q/direct", 1, &[7, 0, 0]).expect("shape"))
                .expect("signed rows"),
            2,
            2,
            2,
            false,
        ),
        (Table::range(8).expect("zero selector"), 2, 1, 2, true),
    ];
    for (table, m, b, repetitions, zero) in cases {
        let shape = table.descriptor().shape();
        let c = usize::from(shape.columns());
        let real = shape.rows() as usize;
        let rows = [0, real / 2, real - 1, 0];
        let messages: Vec<Vec<_>> = (0..c)
            .map(|column| {
                rows[..1 << m]
                    .iter()
                    .map(|row| {
                        M31::from_i64(if zero {
                            256
                        } else {
                            i64::from(table.entries()[row * c + column])
                        })
                    })
                    .collect()
            })
            .collect();
        let prepared: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(i, values)| {
                let ell = if i == 0 { m } else { 0 };
                PreparedSource::<K>::new(
                    2 + i as u64,
                    ell,
                    m - ell,
                    1,
                    values,
                    &mut HashUsage::default(),
                )
                .expect("actual original preparation")
            })
            .collect();
        let certificates: Vec<_> = prepared.iter().map(certify).collect();
        let originals: Vec<_> = certificates.iter().collect();
        let material: Vec<_> = prepared.iter().collect();
        let selector = vec![u8::from(!zero); 1 << m];
        let layouts = [
            Layout {
                id: 10,
                ell: 1,
                blowup: 1,
            },
            Layout {
                id: 11,
                ell: 0,
                blowup: 2,
            },
        ];
        let descriptor = Descriptor::new(
            Statement {
                id: 7,
                m,
                b,
                table: &table,
                selector: &selector,
                originals: &originals,
                multiplicities: &layouts[..repetitions],
            },
            LIMITS,
        )
        .expect("checked immutable statement");
        let mut t = transcript();
        let limits = ProducerLimits {
            public_bytes: descriptor
                .producer_public_bytes()
                .expect("complete public bound"),
            dense_elements: descriptor
                .producer_dense_elements()
                .expect("dense admission bound"),
        };
        let (proof, usage) = descriptor
            .prove(&mut t, &material, limits)
            .expect("actual producer");
        assert_eq!(proof.len(), descriptor.proof_size());
        descriptor
            .preflight(&proof)
            .expect("complete canonical untrusted wire");
        assert_eq!(usage.transcript, t.usage());
        assert!(usage.non_transcript.hash_evaluations > 1);
        assert_eq!(usage.non_transcript.xof_requests, 0);
        let mut cursor = 2;
        for j in 0..repetitions {
            let root = proof[cursor..cursor + 32].try_into().expect("root");
            cursor += 32;
            let source = descriptor
                .multiplicity_source(j, root)
                .expect("expected source");
            let length = source
                .proof_size(ProofKind::Certificate)
                .expect("certificate length");
            let (handle, actual) = verify_certificate(source, &proof[cursor..cursor + length])
                .expect("real certificate embedded in producer output");
            cursor += length;
            assert_eq!(handle.record().source().bytes(), source.bytes());
            let observed = usage.registrations[j]
                .as_ref()
                .expect("executed registration");
            assert_eq!(observed.production, actual.transcript);
            assert_eq!(observed.verification, actual);
        }
        assert!(usage.registrations[repetitions..]
            .iter()
            .all(Option::is_none));
        // Registration alone accepts no lookup; independent complete-wire parity follows.
        assert!(cursor < proof.len());
        let mut measured = transcript();
        let (same, observed, work) = descriptor
            .prove_measured(&mut measured, &material, limits)
            .expect("same actual producer with capacity observations");
        assert_eq!(same, proof);
        assert_eq!(observed, usage);
        assert_eq!(work.proof_bytes, same.capacity());
        assert!(
            work.peak_observed_bytes
                >= work.proof_bytes + work.mu_values_bytes + work.mu_limbs_bytes
        );
        assert!(work.units_bytes >= repetitions * usize::from(m - b) * core::mem::size_of::<K>());
        for j in 0..repetitions {
            let source = descriptor.multiplicity_source(j, [0; 32]).expect("shape");
            let preparation = work.preparations[j].expect("actual mu preparation");
            assert_eq!(
                preparation.borrowed_message_bytes,
                source.rows() * source.columns() * core::mem::size_of::<M31>()
            );
            assert!(preparation.encoded_columns_bytes > 0 && preparation.merkle_nodes_bytes > 0);
            let phases = work.repetitions[j].expect("actual reductions");
            assert!(phases.lookup.levels_bytes > 0 && phases.table.levels_bytes > 0);
            assert!(phases.selected.dense_bytes > 0);
        }
        assert!(work.preparations[repetitions..].iter().all(Option::is_none));
        assert!(work.repetitions[repetitions..].iter().all(Option::is_none));
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck),
            measured.challenge(ChallengeLabel::Sumcheck)
        );
        assert_eq!(t.usage(), measured.usage());
    }
}
fn unchanged<K: ChallengeField + Eq + Debug>(
    t: &mut Transcript<K>,
    before: HashUsage,
    f: ProverFailure,
    cause: Error,
) {
    assert_eq!(f.cause, cause);
    assert_eq!(f.usage.transcript, before);
    assert_eq!(f.usage.non_transcript, HashUsage::default());
    assert!(f.usage.registrations.iter().all(Option::is_none));
    assert_eq!(t.usage(), before);
    assert_eq!(
        t.challenge(ChallengeLabel::Sumcheck).expect("next"),
        transcript::<K>()
            .challenge(ChallengeLabel::Sumcheck)
            .expect("untouched next")
    );
}
fn admission<K: ChallengeField + CodeField + TableField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [M31::from_i64(3)];
    let different = [M31::from_i64(4)];
    let p =
        PreparedSource::<K>::new(2, 0, 0, 1, &message, &mut HashUsage::default()).expect("source");
    let wrong = PreparedSource::<K>::new(2, 0, 0, 1, &different, &mut HashUsage::default())
        .expect("different root");
    let handle = certify(&p);
    let originals = [&handle];
    let table = Table::range(8).expect("range");
    let layouts = [Layout {
        id: 10,
        ell: 1,
        blowup: 1,
    }];
    let descriptor = Descriptor::new(
        Statement {
            id: 7,
            m: 0,
            b: 0,
            table: &table,
            selector: &[1],
            originals: &originals,
            multiplicities: &layouts,
        },
        LIMITS,
    )
    .expect("statement");
    let exact = ProducerLimits {
        public_bytes: descriptor.producer_public_bytes().expect("public bound"),
        dense_elements: descriptor.producer_dense_elements().expect("dense bound"),
    };
    for (sources, limits, cause) in [
        (vec![], exact, Error::SourceRoster),
        (
            vec![&wrong],
            exact,
            Error::Pcs(stele_pcs::Error::CertificateContext),
        ),
        (
            vec![&p],
            ProducerLimits {
                dense_elements: exact.dense_elements - 1,
                ..exact
            },
            Error::ResourceLimit,
        ),
        (
            vec![&p],
            ProducerLimits {
                public_bytes: exact.public_bytes - 1,
                ..exact
            },
            Error::ResourceLimit,
        ),
    ] {
        let mut t = transcript();
        let before = t.usage();
        let failure = descriptor
            .prove(&mut t, &sources, limits)
            .expect_err("admission rejection");
        let mut measured = transcript();
        assert_eq!(
            descriptor
                .prove_measured(&mut measured, &sources, limits)
                .expect_err("same admission"),
            failure
        );
        assert_eq!(measured.usage(), t.usage());
        unchanged(&mut t, before, failure, cause);
    }
}
fn late_failure<K: ChallengeField + CodeField + TableField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [M31::from_i64(256)];
    let prepared = PreparedSource::<K>::new(2, 0, 0, 1, &message, &mut HashUsage::default())
        .expect("fixed out-of-table source");
    let certificate = certify(&prepared);
    let originals = [&certificate];
    let table = Table::range(8).expect("range");
    let layouts = [
        Layout {
            id: 10,
            ell: 4,
            blowup: 1,
        },
        Layout {
            id: 11,
            ell: 4,
            blowup: 1,
        },
    ];
    let descriptor = Descriptor::new(
        Statement {
            id: 7,
            m: 0,
            b: 0,
            table: &table,
            selector: &[1],
            originals: &originals,
            multiplicities: &layouts,
        },
        LIMITS,
    )
    .expect("statement");
    let limits = ProducerLimits {
        public_bytes: descriptor.producer_public_bytes().expect("public bound"),
        dense_elements: descriptor.producer_dense_elements().expect("dense bound"),
    };
    let mut t = transcript();
    let before = t.usage();
    let failure = descriptor
        .prove(&mut t, &[&prepared], limits)
        .expect_err("actual nonpole roots disagree");
    let mut measured = transcript();
    assert_eq!(
        descriptor
            .prove_measured(&mut measured, &[&prepared], limits)
            .expect_err("same genuine late failure"),
        failure
    );
    assert_eq!(measured.usage(), t.usage());
    assert_eq!(
        failure.cause,
        Error::Fraction(stele_lookup::fraction::Error::RootMismatch)
    );
    assert_eq!(failure.usage.transcript, t.usage());
    assert!(failure.usage.transcript.state_updates > before.state_updates);
    let hashes = 1
        + (0..layouts.len())
            .map(|j| {
                2 * descriptor
                    .multiplicity_source(j, [0; 32])
                    .expect("shape")
                    .code()
                    .codeword_len() as u64
                    - 1
            })
            .sum::<u64>();
    assert_eq!(
        failure.usage.non_transcript,
        HashUsage {
            hash_evaluations: hashes,
            ..HashUsage::default()
        }
    );
    for registration in failure.usage.registrations {
        let registration =
            registration.expect("both genuine registrations precede the failing trees");
        assert_eq!(
            registration.production,
            registration.verification.transcript
        );
        assert!(registration.verification.non_transcript.hash_evaluations > 0);
    }
    // This producer failure is not a negative control through a lookup verifier.
}
#[test]
fn accepts_qm31_lookup_producer_registrations() {
    registrations::<QM31>();
}
#[test]
fn accepts_om31_lookup_producer_registrations() {
    registrations::<OM31>();
}
#[test]
fn rejects_qm31_lookup_producer_before_mutation() {
    admission::<QM31>();
}
#[test]
fn rejects_om31_lookup_producer_before_mutation() {
    admission::<OM31>();
}
#[test]
fn rejects_qm31_lookup_producer_after_registration() {
    late_failure::<QM31>();
}
#[test]
fn rejects_om31_lookup_producer_after_registration() {
    late_failure::<OM31>();
}
