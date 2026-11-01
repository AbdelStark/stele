//! RFC-0008 A5 §§3–7: actual closed consumers, import failures and terminal tampering.
use core::fmt::Debug;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{merkle, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::lookup::{
    Descriptor, Error, Layout, Limits, ProducerLimits, Statement, Table, TableDescriptor,
    TableField,
};

const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"closed native lookup verification/v1").expect("fixed prefix")
}
fn mutate<K: ChallengeField>(proof: &mut [u8], offset: usize)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let width = 4 * K::DEGREE;
    let value = K::from_le_bytes(
        K::Bytes::try_from(&proof[offset..offset + width])
            .ok()
            .expect("width"),
    )
    .expect("canonical fixture");
    proof[offset..offset + width].copy_from_slice((value + K::from_i64(1)).to_le_bytes().as_ref());
}
fn run<K: ChallengeField + CodeField + TableField + Eq + Debug>(negative: bool)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let cases = [
        (Table::range(8).expect("full"), 0u8, 0u8, 1usize, false),
        (
            Table::generate(TableDescriptor::new("exp_q/hi", 1, &[7, 0, 0, 6]).expect("shape"))
                .expect("partial"),
            2,
            0,
            2,
            false,
        ),
        (
            Table::generate(TableDescriptor::new("exp_q/direct", 1, &[7, 0, 0]).expect("shape"))
                .expect("signed"),
            2,
            2,
            2,
            false,
        ),
        (Table::range(8).expect("zero"), 2, 1, 2, true),
    ];
    for (table, m, b, r, zero) in cases {
        let (real, n, c) = (
            table.descriptor().shape().rows() as usize,
            table.descriptor().shape().padded() as usize,
            table.descriptor().shape().columns() as usize,
        );
        let rows = [0, real / 2, real - 1, 0];
        let messages: Vec<Vec<_>> = (0..c)
            .map(|a| {
                rows[..1 << m]
                    .iter()
                    .map(|i| {
                        M31::from_i64(if zero {
                            256
                        } else {
                            i64::from(table.entries()[i * c + a])
                        })
                    })
                    .collect()
            })
            .collect();
        let prepared: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(a, message)| {
                let ell = if a == 0 { m } else { 0 };
                PreparedSource::<K>::new(
                    10 + a as u64,
                    ell,
                    m - ell,
                    1,
                    message,
                    &mut HashUsage::default(),
                )
                .expect("original")
            })
            .collect();
        let certificates: Vec<_> = prepared
            .iter()
            .map(|p| {
                verify_certificate(
                    *p.source(),
                    &p.certificate().expect("produce registration").0,
                )
                .expect("register original")
                .0
            })
            .collect();
        let originals: Vec<_> = certificates.iter().collect();
        let material: Vec<_> = prepared.iter().collect();
        let selector = vec![u8::from(!zero); 1 << m];
        let layouts = [
            Layout {
                id: 20,
                ell: if n == 4 { 1 } else { 4 },
                blowup: 1,
            },
            Layout {
                id: 21,
                ell: if n == 4 { 0 } else { 4 },
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
                multiplicities: &layouts[..r],
            },
            LIMITS,
        )
        .expect("descriptor");
        let producer_limits = ProducerLimits {
            public_bytes: descriptor.producer_public_bytes().expect("public"),
            dense_elements: descriptor.producer_dense_elements().expect("dense"),
        };
        let import_limit = (producer_limits.public_bytes - descriptor.public_bytes()) / 2;
        let mut pt = transcript();
        let (proof, produced) = descriptor
            .prove(&mut pt, &material, producer_limits)
            .expect("honest producer");
        let (mu, registrations) = descriptor
            .register_multiplicities(&proof, import_limit)
            .expect("actual imports");
        assert!(registrations[r..].iter().all(Option::is_none));
        for (j, registration) in registrations.iter().enumerate().take(r) {
            assert_eq!(
                *registration,
                Some(produced.registrations[j].expect("registered").verification)
            );
        }
        let multiplicities: Vec<_> = mu.iter().collect();
        let mut vt = transcript();
        // Neither temporary wire nor roster slices own the accepting record.
        let (record, usage) = {
            let temporary = proof.clone();
            let refs = multiplicities.clone();
            descriptor
                .verify(&mut vt, &refs, &temporary)
                .expect("honest verification")
        };
        assert_eq!(usage.transcript, produced.transcript);
        assert_eq!(
            usage.non_transcript,
            HashUsage {
                hash_evaluations: descriptor.max_local_hashes(),
                ..HashUsage::default()
            }
        );
        assert_eq!(
            pt.challenge(ChallengeLabel::Sumcheck),
            vt.challenge(ChallengeLabel::Sumcheck)
        );
        let params = record.parameters();
        assert_eq!(
            (
                params.id,
                params.degree,
                params.positions,
                params.table_rows,
                params.columns
            ),
            (7, <K as CodeField>::DEGREE, 1u64 << m, real as u32, c as u8)
        );
        assert_eq!(
            (
                params.group_bits,
                params.unit_bits,
                params.repetitions,
                params.identity_numerator
            ),
            (
                b,
                m - b,
                r as u8,
                u64::from(m - b) + (1u64 << m) + (c * real) as u64 - 1
            )
        );
        assert_eq!(record.repetitions().len(), r);
        let width = 4 * usize::from(<K as CodeField>::DEGREE);
        let mut packets = Vec::new();
        let mut cursor = 2;
        for handle in &mu {
            let source = handle.record().source();
            let bytes = source
                .proof_size(ProofKind::Certificate)
                .expect("certificate size");
            packets.push(cursor + 32);
            cursor += 32 + bytes;
        }
        let k = n.trailing_zeros() as usize;
        let tree = |v: usize| width * (2 + 2 * v * v + 3 * v);
        cursor += tree(m as usize) + tree(k) + width * (4 * m as usize + c + 2);
        let original_start = cursor;
        for handle in &certificates {
            cursor += handle
                .record()
                .source()
                .proof_size(ProofKind::Opening)
                .expect("original size");
        }
        let value_start = cursor;
        for (j, repetition) in record.repetitions().iter().enumerate() {
            assert_eq!(repetition.originals().len(), c);
            assert_eq!(repetition.selected_product().claims.len(), c);
            assert_eq!(repetition.lookup_tree().point.len(), m as usize);
            assert_eq!(repetition.table_tree().point.len(), k);
            let row_width = n >> layouts[j].ell;
            let expected_pieces: Vec<_> = [
                (0, real / row_width > 0),
                (1, !real.is_multiple_of(row_width)),
            ]
            .into_iter()
            .filter(|(_, present)| *present)
            .map(|(id, _)| id)
            .collect();
            assert_eq!(
                repetition
                    .multiplicities()
                    .iter()
                    .map(|p| p.id())
                    .collect::<Vec<_>>(),
                expected_pieces
            );
            for (opening, original) in repetition.originals().iter().zip(&certificates) {
                assert_eq!(opening.certificate().id(), original.record().id());
                assert_eq!(
                    opening.queries(),
                    original.record().source().queries(ProofKind::Opening)
                );
            }
            for opening in repetition.multiplicities() {
                assert_eq!(opening.certificate().id(), mu[j].record().id());
                assert_eq!(
                    opening.queries(),
                    mu[j].record().source().queries(ProofKind::Opening)
                );
            }
        }
        if !negative {
            continue;
        }
        let reject =
            |bytes: &[u8], handles: &[&stele_pcs::VerifiedCertificate<K>], expected, local| {
                let mut t = transcript();
                let before = t.usage();
                let failure = descriptor
                    .verify(&mut t, handles, bytes)
                    .err()
                    .expect("tamper rejected");
                assert_eq!(failure.cause, expected);
                assert_eq!(failure.usage.transcript, t.usage());
                assert_eq!(failure.usage.non_transcript.hash_evaluations, local);
                if matches!(
                    expected,
                    Error::ProofShape | Error::CertificateContext | Error::CertificateIdentity
                ) {
                    assert_eq!(t.usage(), before);
                }
                failure.usage
            };
        reject(
            &proof[..proof.len() - 1],
            &multiplicities,
            Error::ProofShape,
            0,
        );
        reject(&proof, &[], Error::CertificateContext, 0);
        let mut changed = proof.clone();
        mutate::<K>(&mut changed, packets[0] + 1);
        descriptor
            .preflight(&changed)
            .expect("canonical changed packet");
        reject(&changed, &multiplicities, Error::CertificateIdentity, 1);
        // Genuine different-root handle; no caller-created certificate or digest.
        let first = mu[0].record().source();
        let different: Vec<_> = (0..first.rows() * first.columns())
            .map(|_| M31::from_i64(17))
            .collect();
        let p = PreparedSource::<K>::new(
            20,
            layouts[0].ell,
            first.columns().trailing_zeros() as u8,
            layouts[0].blowup,
            &different,
            &mut HashUsage::default(),
        )
        .expect("different mu");
        let other = verify_certificate(
            *p.source(),
            &p.certificate().expect("different certificate").0,
        )
        .expect("genuine different handle")
        .0;
        assert_ne!(other.record().source().root(), first.root());
        let mut swapped = multiplicities.clone();
        swapped[0] = &other;
        reject(&proof, &swapped, Error::CertificateContext, 0);
        if r == 2 {
            // Finish every context check before hashing even an earlier bad packet.
            let mut later = multiplicities.clone();
            later[1] = &other;
            reject(&changed, &later, Error::CertificateContext, 0);
        }
        let earlier_hashes = 1
            + r as u64
            + certificates
                .iter()
                .map(|v| {
                    let s = v.record().source();
                    u64::from(s.queries(ProofKind::Opening)) * (1 + s.path_height() as u64)
                })
                .sum::<u64>();
        let mut changed = proof.clone();
        mutate::<K>(&mut changed, value_start);
        reject(
            &changed,
            &multiplicities,
            Error::PieceSumMismatch,
            earlier_hashes,
        );
        let pieces = record.repetitions()[0].multiplicities().len();
        let opening_start = value_start + pieces * width;
        // The first expected column coefficient is nonzero at this actual point.
        let coefficient = record.repetitions()[0].table_tree().point[layouts[0].ell as usize..]
            .iter()
            .fold(K::from_i64(1), |a, x| a * (K::from_i64(1) - *x));
        assert_ne!(coefficient, K::from_i64(0));
        let mut changed = proof.clone();
        mutate::<K>(&mut changed, opening_start + 1);
        descriptor
            .preflight(&changed)
            .expect("canonical one-value mu-row tamper");
        let failed = reject(
            &changed,
            &multiplicities,
            Error::Pcs(stele_pcs::Error::ValueMismatch),
            earlier_hashes,
        );
        assert!(failed.transcript.state_updates > transcript::<K>().usage().state_updates);
        let mut changed = proof.clone();
        let path = opening_start + 1 + width * first.columns() + 4 * first.rows();
        changed[path] ^= 1;
        reject(
            &changed,
            &multiplicities,
            Error::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch)),
            earlier_hashes + 1 + first.path_height() as u64,
        );
        if m == 0 || zero {
            let mut changed = proof.clone();
            mutate::<K>(&mut changed, original_start + 1);
            reject(
                &changed,
                &multiplicities,
                Error::Pcs(stele_pcs::Error::ValueMismatch),
                1 + r as u64,
            );
        }
        for (bytes, limit, expected) in [
            (&proof[..], import_limit - 1, Error::ResourceLimit),
            (&proof[..proof.len() - 1], import_limit, Error::ProofShape),
        ] {
            let failure = descriptor
                .register_multiplicities(bytes, limit)
                .err()
                .expect("bad import rejected");
            assert_eq!(failure.cause, expected);
            assert!(failure.registrations.iter().all(Option::is_none));
        }
        // Corrupt exactly one path digest in the last registration. Earlier usages survive.
        let j = r - 1;
        let source = mu[j].record().source();
        let path = packets[j] + 1 + width * source.columns() + 4 * source.rows();
        let mut changed = proof.clone();
        changed[path] ^= 1;
        let failure = descriptor
            .register_multiplicities(&changed, import_limit)
            .err()
            .expect("bad registration rejected");
        assert_eq!(
            failure.cause,
            Error::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch))
        );
        for (actual, expected) in failure.registrations[..j].iter().zip(&registrations[..j]) {
            assert_eq!(actual, expected);
        }
        let observed = failure.registrations[j].expect("attempted registration");
        assert_eq!(
            observed.non_transcript.hash_evaluations,
            1 + source.path_height() as u64
        );
        assert_ne!(observed.transcript, HashUsage::default());
        assert!(failure.registrations[r..].iter().all(Option::is_none));
    }
}
#[test]
fn accepts_qm31_closed_lookup() {
    run::<QM31>(false);
}
#[test]
fn accepts_om31_closed_lookup() {
    run::<OM31>(false);
}
#[test]
fn rejects_qm31_closed_lookup_tampers() {
    run::<QM31>(true);
}
#[test]
fn rejects_om31_closed_lookup_tampers() {
    run::<OM31>(true);
}
