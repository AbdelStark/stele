//! RFC-0023 §§2.3-2.4: independent frames and untrusted canonical-shape packets.
use super::*;
use alloc::vec;
use stele_cqis::Format;
use stele_field::{Field, OM31, QM31};
use stele_hash::HashUsage;
use stele_lookup::fraction;
use stele_pcs::{verify_certificate, CodeField, PreparedSource};

const LIMITS: Limits = Limits {
    positions: 4096,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(core::str::from_utf8(b).expect("ASCII hex fixture"), 16)
                .expect("hex byte")
        })
        .collect()
}
fn registered<K: ChallengeField + CodeField>(
    id: u64,
    ell: u8,
    m: u8,
    blowup: u8,
) -> VerifiedCertificate<K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let message = vec![M31::from_i64(0); 1 << (ell + m)];
    let p = PreparedSource::<K>::new(id, ell, m, blowup, &message, &mut HashUsage::default())
        .expect("valid fixture");
    let (wire, _) = p.certificate().expect("valid fixture");
    verify_certificate(*p.source(), &wire)
        .expect("valid fixture")
        .0
}

fn numbers(s: &str) -> Vec<u64> {
    s.split_whitespace()
        .map(|v| v.parse().expect("fixture integer"))
        .collect()
}
// Independent Python grammar supplies every byte and each one-value decision.
// These zero response packets have canonical shape only, never proof validity.
fn check_wire<K: ChallengeField>(d: &Descriptor<'_, '_, K>, program: &str, mutations: &str) {
    let program = numbers(program);
    let mut bytes = vec![0; program[0] as usize];
    assert_eq!((program.len() - 1) % 2, 0);
    for pair in program[1..].chunks_exact(2) {
        bytes[pair[0] as usize] = pair[1] as u8;
    }
    assert_eq!(bytes.len(), d.proof_size());
    assert_eq!(d.preflight(&bytes), Ok(()));
    let causes = [
        None,
        Some(Error::ProofShape),
        Some(Error::NoncanonicalField),
        Some(Error::Pcs(stele_pcs::Error::ProofShape)),
        Some(Error::Pcs(stele_pcs::Error::NoncanonicalField)),
        Some(Error::Lookup(lookup::Error::ProofShape)),
        Some(Error::Lookup(lookup::Error::Fraction(
            fraction::Error::NoncanonicalField,
        ))),
        Some(Error::Lookup(lookup::Error::Pcs(
            stele_pcs::Error::ProofShape,
        ))),
        Some(Error::Lookup(lookup::Error::Pcs(
            stele_pcs::Error::NoncanonicalField,
        ))),
    ];
    let mutations = numbers(mutations);
    assert_eq!(mutations.len() % 3, 0);
    for change in mutations.chunks_exact(3) {
        let (operation, at, cause) = (change[0], change[1] as usize, change[2] as usize);
        let mut changed = bytes.clone();
        match operation {
            0 => changed[at] = 0,
            1 => changed[at..at + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes()),
            2 => {
                changed.pop();
            }
            3 => changed.push(0),
            _ => {
                assert_eq!(operation, 4, "known fixture mutation");
                changed[at] = if bytes[at] == 4 { 8 } else { 4 };
            }
        }
        assert_eq!(
            d.preflight(&changed),
            causes[cause].map_or(Ok(()), Err),
            "change {change:?}"
        );
    }
}

fn parity<K: ChallengeField + CodeField + Eq + core::fmt::Debug>()
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let lines: Vec<_> = include_str!("../tests/fixtures/requant-codec.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 56);
    for fixture in lines.chunks_exact(7) {
        let p = numbers(fixture[0]);
        if p[0] != <K as CodeField>::DEGREE as u64 {
            continue;
        }
        let [_, stage, n, mantissa, shift, bits, r, ab, ib]: [u64; 9] =
            p.try_into().expect("valid fixture");
        let schema = Schema::new(
            mantissa as u32,
            shift as u32,
            if bits == 8 {
                Format::Int8
            } else {
                Format::Int16
            },
        )
        .expect("valid fixture");
        let m = n.next_power_of_two().trailing_zeros() as u8;
        let input = registered::<K>(13, 2, m, ib as u8);
        let expected_source = schema
            .advice_source::<K>(stage as u32, n, ab as u8, [0; 32])
            .expect("valid fixture");
        let advice = registered::<K>(
            expected_source.descriptor().id,
            expected_source.rows().trailing_zeros() as u8,
            m,
            ab as u8,
        );
        let mut expected = hex(fixture[1]);
        let at = 23 + schema.bounds().as_bytes().len();
        for (i, c) in [&input, &advice].into_iter().enumerate() {
            expected[at + 137 * i..at + 137 * i + 105]
                .copy_from_slice(&c.record().source().bytes());
            expected[at + 137 * i + 105..at + 137 * (i + 1)].copy_from_slice(&c.record().id());
        }
        let values: Vec<K> = expected[at + 274..]
            .chunks_exact(4 * usize::from(<K as CodeField>::DEGREE))
            .map(|b| {
                K::from_le_bytes(b.try_into().ok().expect("valid fixture")).expect("valid fixture")
            })
            .collect();
        let s = Statement {
            stage: stage as u32,
            n,
            schema: &schema,
            repetitions: r as u8,
            advice_blowup: ab as u8,
            point: &values[..m as usize],
            value: values[m as usize],
            input: &input,
        };
        let d = Descriptor::new(s, &advice, LIMITS).expect("valid fixture");
        assert_eq!(d.encode().expect("valid fixture"), expected);
        assert_eq!(d.statement_size(), expected.len());
        let constraints = hex(fixture[2]);
        assert_eq!(d.encode_constraints().expect("valid fixture"), constraints);
        assert_eq!(d.constraints_size(), constraints.len());
        assert_eq!(d.output.encode().expect("valid fixture"), hex(fixture[3]));
        let sizes = numbers(fixture[4]);
        let children = [
            d.lookup(0).expect("valid fixture"),
            d.lookup(1).expect("valid fixture"),
        ];
        assert_eq!(
            d.proof_size() - children.iter().map(|v| v.proof_size()).sum::<usize>(),
            sizes[1] as usize
        );
        assert_eq!(
            d.public_bytes() - children.iter().map(|v| v.public_bytes()).sum::<usize>(),
            sizes[2] as usize
        );
        assert_eq!(
            d.max_local_hashes() - children.iter().map(|v| v.max_local_hashes()).sum::<u64>(),
            sizes[3]
        );
        assert_eq!(sizes[0], ((4 + schema.rows()) << m) as u64);
        check_wire(&d, fixture[5], fixture[6]);
        let exact = Limits {
            positions: sizes[0],
            public_bytes: d.public_bytes(),
            proof_bytes: d.proof_size(),
        };
        assert!(Descriptor::new(s, &advice, exact).is_ok());
        for lower in [
            Limits {
                positions: exact.positions - 1,
                ..exact
            },
            Limits {
                public_bytes: exact.public_bytes - 1,
                ..exact
            },
            Limits {
                proof_bytes: exact.proof_bytes - 1,
                ..exact
            },
        ] {
            assert!(matches!(
                Descriptor::new(s, &advice, lower),
                Err(Error::ResourceLimit)
            ));
        }
    }
}
#[test]
fn matches_reference_qm31_codec() {
    parity::<QM31>();
}
#[test]
fn matches_reference_om31_codec() {
    parity::<OM31>();
}

#[test]
fn rejects_codec_statement_and_sources() {
    rejected_sources::<QM31>();
    rejected_sources::<OM31>();
}
fn rejected_sources<K: ChallengeField + CodeField>()
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let schema = Schema::new(1, 0, Format::Int8).expect("valid fixture");
    let input = registered::<K>(13, 2, 0, 1);
    let advice = registered::<K>((1 << 40) + 2, 7, 0, 1);
    let s = Statement {
        stage: 1,
        n: 1,
        schema: &schema,
        repetitions: 1,
        advice_blowup: 1,
        point: &[],
        value: K::from_i64(0),
        input: &input,
    };
    for bad in [
        Statement { stage: 0, ..s },
        Statement {
            stage: 1 << 20,
            ..s
        },
        Statement { n: 0, ..s },
        Statement {
            repetitions: 0,
            ..s
        },
        Statement {
            repetitions: 3,
            ..s
        },
        Statement {
            advice_blowup: 0,
            ..s
        },
        Statement {
            advice_blowup: 3,
            ..s
        },
    ] {
        assert!(matches!(
            Descriptor::new(bad, &advice, LIMITS),
            Err(Error::Statement)
        ));
    }
    assert!(matches!(
        Descriptor::new(
            Statement {
                point: &[K::from_i64(0)],
                ..s
            },
            &advice,
            LIMITS
        ),
        Err(Error::Statement)
    ));
    for (id, ell, m, blowup) in [
        (1, 2, 0, 1),
        (1 << 40, 2, 0, 1),
        (13, 1, 0, 1),
        (13, 2, 1, 1),
    ] {
        let bad = registered::<K>(id, ell, m, blowup);
        assert!(matches!(
            Descriptor::new(Statement { input: &bad, ..s }, &advice, LIMITS),
            Err(Error::SourceRoster)
        ));
    }
    for (id, ell, m, blowup) in [
        ((1 << 40) + 3, 7, 0, 1),
        ((1 << 40) + 2, 6, 0, 1),
        ((1 << 40) + 2, 7, 1, 1),
        ((1 << 40) + 2, 7, 0, 2),
    ] {
        let bad = registered::<K>(id, ell, m, blowup);
        assert!(matches!(
            Descriptor::new(s, &bad, LIMITS),
            Err(Error::SourceRoster)
        ));
    }
    assert!(schema.advice_source::<K>(1, 1 << 30, 1, [0; 32]).is_err());
    assert!(matches!(
        schema.advice_source::<K>(1, u64::MAX, 1, [0; 32]),
        Err(Error::Capacity)
    ));
    assert_eq!(sum(&[usize::MAX, 1]), Err(Error::Capacity));
    assert_eq!(addressable::<K>(usize::MAX), Err(Error::Capacity));
}
