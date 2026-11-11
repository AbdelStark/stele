//! RFC-0008 A8: the standard-profile (β, α) nonce on the A5 consumer. The grind
//! bits and wire are pinned by research/fs-pcs/check_lu_grind.py; controls are NC-0814..0816.
use core::fmt::Debug;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource};
use stele_reductions::lookup::{
    lu_grind_bits, Descriptor, Layout, Limits, ProducerLimits, Statement, Table, TableDescriptor,
    TableField,
};

const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 64_000_000,
    proof_bytes: 64_000_000,
};

/// Prove and verify one standard lookup; return (grind bits, proof bytes, dev proof bytes).
fn round_trip<K: ChallengeField + CodeField + TableField + Eq + Debug>(
    table: &Table,
    r: usize,
) -> (u8, usize, usize)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let c = usize::from(table.descriptor().shape().columns());
    let messages: Vec<Vec<M31>> = (0..c)
        .map(|a| vec![M31::from_i64(i64::from(table.entries()[c + a]))])
        .collect();
    let prepared: Vec<_> = messages
        .iter()
        .enumerate()
        .map(|(a, message)| {
            PreparedSource::<K>::new(10 + a as u64, 0, 0, 1, message, &mut HashUsage::default())
                .expect("original")
        })
        .collect();
    let certificates: Vec<_> = prepared
        .iter()
        .map(|p| {
            verify_certificate(*p.source(), &p.certificate().expect("certificate").0)
                .expect("register original")
                .0
        })
        .collect();
    let originals: Vec<_> = certificates.iter().collect();
    let material: Vec<_> = prepared.iter().collect();
    let k = table.descriptor().shape().padded().trailing_zeros() as u8;
    let layouts = [
        Layout {
            id: 20,
            ell: k / 2,
            blowup: 1,
        },
        Layout {
            id: 21,
            ell: k / 2,
            blowup: 2,
        },
    ];
    let statement = Statement {
        id: 7,
        m: 0,
        b: 0,
        table,
        selector: &[1],
        originals: &originals,
        multiplicities: &layouts[..r],
    };
    let development = Descriptor::new(statement, LIMITS).expect("development descriptor");
    assert_eq!(development.grind_bits(), 0);
    let descriptor = Descriptor::standard(statement, LIMITS).expect("standard descriptor");
    let limits = ProducerLimits {
        public_bytes: descriptor.producer_public_bytes().expect("public"),
        dense_elements: descriptor.producer_dense_elements().expect("dense"),
    };
    let mut pt = Transcript::<K>::new(b"standard lookup").expect("prefix");
    let (proof, _) = descriptor
        .prove(&mut pt, &material, limits)
        .expect("honest producer");
    let (mu, _) = descriptor
        .register_multiplicities(&proof, usize::MAX)
        .expect("Policy 2 multiplicity certificates");
    let handles: Vec<_> = mu.iter().collect();
    let mut vt = Transcript::<K>::new(b"standard lookup").expect("prefix");
    let _accepted = descriptor
        .verify(&mut vt, &handles, &proof)
        .expect("honest standard verification");
    assert_eq!(
        pt.challenge(ChallengeLabel::Sumcheck),
        vt.challenge(ChallengeLabel::Sumcheck)
    );
    // A development proof is not a standard proof: other mu policy, no nonce.
    let mut dt = Transcript::<K>::new(b"standard lookup").expect("prefix");
    assert!(descriptor.preflight(&proof).is_ok());
    assert!(development.verify(&mut dt, &handles, &proof).is_err());
    (
        descriptor.grind_bits(),
        proof.len(),
        development.proof_size(),
    )
}

#[test]
fn accepts_standard_lookup_with_least_grind_bits() {
    let sigmoid = Table::generate(TableDescriptor::new("sigmoid_q", 1, &[0, 0]).expect("shape"))
        .expect("sigmoid");
    let range = Table::range(8).expect("range");
    // c = 2, N = 1, t = 2^16: a = 2^17 + 1, so k = 2 in QM31 and 0 in OM31.
    assert_eq!(round_trip::<QM31>(&sigmoid, 1).0, 2);
    assert_eq!(round_trip::<QM31>(&sigmoid, 2).0, 2);
    assert_eq!(round_trip::<OM31>(&sigmoid, 1).0, 0);
    assert_eq!(round_trip::<QM31>(&range, 1).0, 0);
}

#[test]
fn matches_reference_lu_grind_bits() {
    // Rows "c N t d k" recomputed from the exact (C1) inequality; k = "none" above 32.
    let text = include_str!("fixtures/lu-grind-bits.txt");
    let mut rows = 0;
    for line in text.lines() {
        let v: Vec<&str> = line.split(' ').collect();
        let n = |i: usize| v[i].parse::<u64>().expect("fixture number");
        let expected = v[4].parse::<u8>().ok();
        assert_eq!(
            lu_grind_bits(n(0) as usize, n(1), n(2) as usize, n(3) as usize),
            expected,
            "{line}"
        );
        rows += 1;
    }
    assert!(rows > 100);
}

/// Hex of `bytes`, for comparison with the Python oracle's rows.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn standard_wire<K: ChallengeField + CodeField + TableField + Eq + Debug>(line: &str)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    // degree table value k offset nonces bytes blake3 continuation
    let v: Vec<&str> = line.split(' ').collect();
    let table =
        Table::range(v[1].trim_start_matches("range_").parse().expect("width")).expect("range");
    let value: i64 = v[2].parse().expect("value");
    let message = [M31::from_i64(value)];
    let prepared = PreparedSource::<K>::new(10, 0, 0, 1, &message, &mut HashUsage::default())
        .expect("original");
    let certificate = verify_certificate(*prepared.source(), &prepared.certificate().expect("c").0)
        .expect("register original")
        .0;
    let layouts = [Layout {
        id: 20,
        ell: 4,
        blowup: 1,
    }];
    let originals = [&certificate];
    let descriptor = Descriptor::standard(
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
    .expect("standard descriptor");
    assert_eq!(descriptor.grind_bits().to_string(), v[3], "{line}");
    let limits = ProducerLimits {
        public_bytes: descriptor.producer_public_bytes().expect("public"),
        dense_elements: descriptor.producer_dense_elements().expect("dense"),
    };
    let mut t = Transcript::<K>::new(b"conditional lookup producer corpus/v1").expect("prefix");
    let (proof, _) = descriptor
        .prove(&mut t, &[&prepared], limits)
        .expect("honest producer");
    let at: usize = v[4].parse().expect("offset");
    if v[5] != "-" {
        let nonce = u64::from_le_bytes(proof[at..at + 8].try_into().expect("nonce"));
        assert_eq!(nonce.to_string(), v[5], "{line}");
    }
    assert_eq!(proof.len().to_string(), v[6], "{line}");
    assert_eq!(blake3::hash(&proof).to_hex().as_str(), v[7], "{line}");
    let continuation = t.challenge(ChallengeLabel::Sumcheck).expect("continuation");
    assert_eq!(hex(continuation.to_le_bytes().as_ref()), v[8], "{line}");
}

#[test]
fn matches_reference_standard_lookup_wire() {
    // research/fs-pcs/check_lu_grind.py: the independent A5 producer with A8 applied.
    let text = include_str!("fixtures/lu-standard-wire.txt");
    for line in text.lines() {
        if line.starts_with("4 ") {
            standard_wire::<QM31>(line);
        } else {
            assert!(line.starts_with("8 "), "fixture degree: {line}");
            standard_wire::<OM31>(line);
        }
    }
    assert_eq!(text.lines().count(), 3);
}
