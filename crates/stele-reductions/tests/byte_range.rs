//! RFC-0024 §1.1: the fixed complete A5 attempt owns byte-range authority.
use core::fmt::Debug;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, Usage};
use stele_reductions::{byte_range, lookup};

const PREFIX: &[u8] = b"stele/v0.1/integer-linear/byte-range/v1";
const LIMITS: lookup::Limits = lookup::Limits {
    positions: 16,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};

fn exercise<K: ChallengeField + CodeField + lookup::TableField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for (ell, m, r) in [(0, 0, 1), (1, 1, 2)] {
        let message: Vec<_> = [0, 7, 128, 255][..1 << (ell + m)]
            .iter()
            .map(|v| M31::from_i64(*v))
            .collect();
        let prepared = PreparedSource::<K>::new(
            10,
            ell,
            m,
            if ell == 0 { 1 } else { 2 },
            &message,
            &mut HashUsage::default(),
        )
        .expect("valid fixed fixture");
        let original = verify_certificate(
            *prepared.source(),
            &prepared
                .certificate()
                .expect("produce genuine certificate")
                .0,
        )
        .expect("valid fixed fixture")
        .0;
        let ids = [20, 21];
        let d = byte_range::Descriptor::new(&original, 7, &ids[..r], LIMITS)
            .expect("valid fixed fixture");
        // RFC-0008 A2 item 2: only (standard, QM31, r=1) and (treaty, OM31, r=2) admit.
        for profile in [lookup::Profile::Standard, lookup::Profile::Treaty] {
            let derived = match profile {
                lookup::Profile::Standard => (1, 4),
                lookup::Profile::Treaty => (2, 8),
            };
            assert_eq!(
                d.admit(profile),
                if derived == (r, usize::from(<K as CodeField>::DEGREE)) {
                    Ok(())
                } else {
                    Err(lookup::Error::Statement)
                }
            );
        }
        let table = lookup::Table::range(8).expect("valid fixed fixture");
        let selector = vec![1; message.len()];
        let originals = [&original];
        let layouts = [20, 21].map(|id| lookup::Layout {
            id,
            ell: 0,
            blowup: 1,
        });
        let expected = lookup::Descriptor::new(
            lookup::Statement {
                id: 7,
                m: ell + m,
                b: ell + m,
                table: &table,
                selector: &selector,
                originals: &originals,
                multiplicities: &layouts[..r],
            },
            LIMITS,
        )
        .expect("valid fixed fixture");
        assert_eq!(d.public_bytes(), PREFIX.len() + expected.public_bytes());
        assert_eq!(d.proof_size(), expected.proof_size());
        let limits = lookup::ProducerLimits {
            public_bytes: d.producer_public_bytes().expect("public admission"),
            dense_elements: d.producer_dense_elements().expect("dense admission"),
        };
        let (proof, produced) = d.prove(&prepared, limits).expect("valid fixed fixture");
        let mut pt = Transcript::new(PREFIX).expect("valid fixed fixture");
        let (reference, reference_usage) = expected
            .prove(
                &mut pt,
                &[&prepared],
                lookup::ProducerLimits {
                    public_bytes: limits.public_bytes - PREFIX.len(),
                    ..limits
                },
            )
            .expect("valid fixed fixture");
        assert_eq!(proof, reference);
        assert_eq!(produced, reference_usage);
        let import_cap = (limits.public_bytes - d.public_bytes()) / 2;
        let (owners, imports) = d
            .register_multiplicities(&proof, import_cap)
            .expect("valid fixed fixture");
        assert!(imports[r..].iter().all(Option::is_none));
        let refs: Vec<_> = owners.iter().collect();
        let mut vt = Transcript::new(PREFIX).expect("valid fixed fixture");
        let (conditional, usage) = expected
            .verify(&mut vt, &refs, &proof)
            .expect("valid fixed fixture");
        let accepted = {
            let temporary = byte_range::Descriptor::new(&original, 7, &ids[..r], LIMITS)
                .expect("valid fixed fixture");
            let packet = proof.clone();
            let references = refs.clone();
            temporary
                .verify(&references, &packet)
                .expect("valid fixed fixture")
        };
        assert_eq!(accepted.usage(), &usage);
        assert_eq!(accepted.lookup().parameters(), conditional.parameters());
        assert!(core::ptr::eq(accepted.original(), &original));
        assert_eq!(accepted.limits(), LIMITS);
        for (a, b) in accepted.multiplicities().iter().zip(&refs) {
            assert!(core::ptr::eq(*a, *b));
        }
        // Independent complete verification is a distinct evidence object/event.
        let second = d.verify(&refs, &proof).expect("valid fixed fixture");
        assert!(!core::ptr::eq(&accepted, &second));
        assert_eq!(second.usage(), accepted.usage());
        let exact = lookup::Limits {
            public_bytes: d.public_bytes(),
            proof_bytes: d.proof_size(),
            ..LIMITS
        };
        assert!(byte_range::Descriptor::new(&original, 7, &ids[..r], exact).is_ok());
        for cap in [
            lookup::Limits {
                public_bytes: exact.public_bytes - 1,
                ..exact
            },
            lookup::Limits {
                proof_bytes: exact.proof_bytes - 1,
                ..exact
            },
            lookup::Limits {
                positions: message.len() as u64 - 1,
                ..exact
            },
        ] {
            assert!(matches!(
                byte_range::Descriptor::new(&original, 7, &ids[..r], cap),
                Err(lookup::Error::ResourceLimit)
            ));
        }
        for short in [
            lookup::ProducerLimits {
                public_bytes: limits.public_bytes - 1,
                ..limits
            },
            lookup::ProducerLimits {
                dense_elements: limits.dense_elements - 1,
                ..limits
            },
        ] {
            let failure = d
                .prove(&prepared, short)
                .expect_err("resource cap rejected");
            assert_eq!(failure.cause, lookup::Error::ResourceLimit);
            assert_eq!(failure.usage, lookup::ProverUsage::default());
        }
        let failure = d
            .register_multiplicities(&proof, import_cap - 1)
            .err()
            .expect("valid fixed fixture");
        assert_eq!(failure.cause, lookup::Error::ResourceLimit);
        assert_eq!(failure.registrations, [None; 2]);
        // A5 malformed-wire failure still charges the actual fixed constructor.
        let failure = d
            .verify(&refs, &proof[..proof.len() - 1])
            .err()
            .expect("valid fixed fixture");
        assert_eq!(failure.cause, lookup::Error::ProofShape);
        assert_eq!(
            failure.usage,
            Usage {
                transcript: Transcript::<K>::new(PREFIX)
                    .expect("valid fixed fixture")
                    .usage(),
                non_transcript: HashUsage::default(),
            }
        );
        let failure = d.verify(&[], &proof).err().expect("valid fixed fixture");
        assert_eq!(failure.cause, lookup::Error::CertificateContext);
        assert_eq!(
            failure.usage.transcript,
            Transcript::<K>::new(PREFIX)
                .expect("valid fixed fixture")
                .usage()
        );
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        for bad in [&[][..], &[10][..], &[20, 20][..], &[20, 21, 22][..]] {
            assert!(byte_range::Descriptor::new(&original, 7, bad, LIMITS).is_err());
        }
    }
}

#[test]
fn matches_reference_complete_byte_range() {
    exercise::<QM31>();
    exercise::<OM31>();
    rejects_empty_predicate::<QM31>();
    rejects_empty_predicate::<OM31>();
}

fn rejects_empty_predicate<K: ChallengeField + CodeField + lookup::TableField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [M31::from_i64(256)];
    let p = PreparedSource::<K>::new(10, 0, 0, 1, &message, &mut HashUsage::default())
        .expect("actual out-of-range source");
    let c = verify_certificate(*p.source(), &p.certificate().expect("certificate").0)
        .expect("genuine false-byte authority")
        .0;
    let table = lookup::Table::range(8).expect("range8");
    let originals = [&c];
    let layouts = [lookup::Layout {
        id: 20,
        ell: 0,
        blowup: 1,
    }];
    let statement = lookup::Statement {
        id: 7,
        m: 0,
        b: 0,
        table: &table,
        selector: &[0],
        originals: &originals,
        multiplicities: &layouts,
    };
    let empty = lookup::Descriptor::new(statement, LIMITS).expect("zero selector allowed by A5");
    let limits = lookup::ProducerLimits {
        public_bytes: 16_000_000,
        dense_elements: 16_000_000,
    };
    let (wire, _) = empty
        .prove(&mut Transcript::new(PREFIX).expect("prefix"), &[&p], limits)
        .expect("unselected 256 proves no byte membership");
    let (owners, _) = empty
        .register_multiplicities(&wire, LIMITS.public_bytes)
        .expect("imports");
    let refs: Vec<_> = owners.iter().collect();
    let _conditional = empty
        .verify(&mut Transcript::new(PREFIX).expect("prefix"), &refs, &wire)
        .expect("ordinary zero-selector lookup accepts");
    let range = byte_range::Descriptor::new(&c, 7, &[20], LIMITS).expect("expected range");
    let full = lookup::Descriptor::new(
        lookup::Statement {
            selector: &[1],
            ..statement
        },
        LIMITS,
    )
    .expect("independently derived full predicate");
    let failure = range
        .verify(&refs, &wire)
        .err()
        .expect("zero-selector packet has no range authority");
    let expected = full
        .verify(&mut Transcript::new(PREFIX).expect("prefix"), &refs, &wire)
        .err()
        .expect("actual all-one consumer rejects");
    assert_eq!(failure, expected);
    let failed = range
        .prove(&p, limits)
        .expect_err("ordinary false-byte producer fails");
    let expected = full
        .prove(&mut Transcript::new(PREFIX).expect("prefix"), &[&p], limits)
        .expect_err("same actual A5 failure");
    assert_eq!(failed, expected);
    assert_eq!(
        failed.cause,
        lookup::Error::Fraction(stele_lookup::fraction::Error::RootMismatch)
    );
    assert!(failed.usage.registrations[0].is_some());
    assert!(failed.usage.registrations[1].is_none());
}
