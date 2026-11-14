//! E8-02d parity for the PCS consumer. Fixtures:
//! - Policy 1: the six full-byte A9 cases of `crates/stele-pcs/tests/fixtures/field-wire.jsonl`
//!   (the Python oracle's bytes, also read by `stele-pcs`'s own tests);
//! - Policy 2: the four full-byte A14 cases of `tests/fixtures/policy2-full.jsonl`, from
//!   `research/merkle-oracle/dump_policy2_full.py`. One case grinds the tensor round.
//!
//! Each certificate must verify with the oracle's certificate ID. Each opening must
//! verify, and under Policy 2 leave the same continuation challenge. Each tamper must
//! give its exact error, and each wire must be refused one byte longer or shorter.
use serde_json::Value;
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_verifier::pcs::{verify_certificate, verify_opening, Error, Source};

const POLICY1: &str = include_str!("../../stele-pcs/tests/fixtures/field-wire.jsonl");
const POLICY2: &str = include_str!("fixtures/policy2-full.jsonl");

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn values<K: ChallengeField>(raw: &[u8]) -> Vec<K>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    raw.chunks_exact(4 * K::DEGREE)
        .map(|c| K::from_le_bytes(K::Bytes::try_from(c).ok().expect("width")).expect("canonical"))
        .collect()
}

fn source(c: &Value, policy: u8) -> Source {
    let bytes = hex(&c["source"]);
    let n = |k: &str| c[k].as_u64().expect(k) as u8;
    let s = Source {
        degree: n("degree"),
        id: 41,
        ell: n("ell"),
        m: n("m"),
        blowup: n("blowup"),
        policy,
        root: bytes[bytes.len() - 32..].try_into().expect("root"),
    };
    assert_eq!(s.bytes().expect("source"), bytes, "source bytes");
    s
}

/// The certificate and opening of `c` verify; returns the continuation challenge.
fn honest<K: ChallengeField + Eq>(c: &Value, s: &Source) -> Vec<u8>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let cert = verify_certificate::<K>(s, &hex(&c["certificate"])).expect("certificate");
    assert_eq!(cert.id().to_vec(), hex(&c["certificate_id"]));
    let (a, b) = (values::<K>(&hex(&c["a"])), values::<K>(&hex(&c["b"])));
    let v = values::<K>(&hex(&c["value"]))[0];
    let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
    verify_opening(&mut t, 12, &cert, &a, &b, v, &hex(&c["opening"])).expect("opening");
    let next = t.challenge(ChallengeLabel::Sumcheck).expect("continuation");
    next.to_le_bytes().as_ref().to_vec()
}

/// The tampers of `c` each give their exact error.
fn tampers<K: ChallengeField + Eq>(c: &Value, s: &Source)
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let cert = hex(&c["certificate"]);
    let verify = |bytes: &[u8], s: &Source| verify_certificate::<K>(s, bytes).map(|_| ());
    // One byte shorter or longer, and another version byte: ProofShape.
    for bad in [
        &cert[..cert.len() - 1],
        &[cert.as_slice(), &[0]].concat(),
        &[&[2][..], &cert[1..]].concat(),
    ] {
        assert_eq!(verify(bad, s), Err(Error::ProofShape));
    }
    // The last path byte: the Merkle path no longer reaches the root.
    let mut bad = cert.clone();
    *bad.last_mut().expect("byte") ^= 1;
    assert!(matches!(verify(&bad, s), Err(Error::Merkle(_))));
    // Another root. It changes the source bytes the transcript starts from: under
    // Policy 1 the paths miss the root; under Policy 2 a nonce fails its predicate first.
    let mut other = *s;
    other.root[0] ^= 1;
    let expected = |e: &Error| match s.policy {
        1 => matches!(e, Error::Merkle(_)),
        _ => *e == Error::Transcript(stele_hash::Error::GrindMismatch),
    };
    assert!(verify(&cert, &other).is_err_and(|e| expected(&e)));
    let honest = verify_certificate::<K>(s, &cert).expect("certificate");
    let opening = hex(&c["opening"]);
    let (a, b) = (values::<K>(&hex(&c["a"])), values::<K>(&hex(&c["b"])));
    let v = values::<K>(&hex(&c["value"]))[0];
    let open = |bytes: &[u8], v: K, a: &[K]| {
        let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        verify_opening(&mut t, 12, &honest, a, &b, v, bytes)
    };
    for bad in [
        &opening[..opening.len() - 1],
        &[opening.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(open(bad, v, &a), Err(Error::ProofShape));
    }
    assert_eq!(
        open(&opening, v + K::from_i64(1), &a),
        Err(Error::ValueMismatch)
    );
    assert_eq!(open(&opening, v, &a[1..]), Err(Error::FunctionalShape));
}

#[test]
fn matches_reference_policy1_certificates_and_openings() {
    let mut count = 0;
    for line in POLICY1.lines() {
        let c: Value = serde_json::from_str(line).expect("case");
        let s = source(&c, 1);
        if s.degree == 4 {
            honest::<QM31>(&c, &s);
            tampers::<QM31>(&c, &s);
        } else {
            honest::<OM31>(&c, &s);
            tampers::<OM31>(&c, &s);
        }
        count += 1;
    }
    assert_eq!(count, 6);
}

#[test]
fn matches_reference_policy2_certificates_openings_and_continuations() {
    let mut count = 0;
    for line in POLICY2.lines() {
        let c: Value = serde_json::from_str(line).expect("case");
        let s = source(&c, 2);
        let p = s.parameters().expect("parameters");
        assert_eq!(
            u64::from(p.tensor_bits),
            c["tensor_bits"].as_u64().expect("bits")
        );
        let next = if s.degree == 4 {
            tampers::<QM31>(&c, &s);
            honest::<QM31>(&c, &s)
        } else {
            tampers::<OM31>(&c, &s);
            honest::<OM31>(&c, &s)
        };
        assert_eq!(next, hex(&c["continuation"]), "continuation");
        count += 1;
    }
    assert_eq!(count, 4);
}

/// A14 items 3–4: a column or tensor nonce that fails the predicate is GrindMismatch.
/// The prover sends the least valid nonce, so `n − 1` fails whenever `n > 0`.
#[test]
fn rejects_failing_nonces() {
    let mut tensor_checked = false;
    for line in POLICY2.lines() {
        let c: Value = serde_json::from_str(line).expect("case");
        if c["degree"] != 4 {
            continue;
        }
        let s = source(&c, 2);
        let p = s.parameters().expect("parameters");
        let cert = hex(&c["certificate"]);
        let tensor = usize::from(p.tensor_bits > 0) * 8;
        let at = 1 + tensor + 16 * (1usize << s.m);
        let try_nonce = |at: usize| {
            let n = u64::from_le_bytes(cert[at..at + 8].try_into().expect("nonce"));
            if n == 0 {
                return;
            }
            let mut bad = cert.clone();
            bad[at..at + 8].copy_from_slice(&(n - 1).to_le_bytes());
            assert_eq!(
                verify_certificate::<QM31>(&s, &bad).map(|_| ()),
                Err(Error::Transcript(stele_hash::Error::GrindMismatch))
            );
        };
        try_nonce(at);
        if tensor > 0 {
            try_nonce(1);
            tensor_checked = true;
        }
    }
    assert!(tensor_checked, "a tensor-grinding case");
}

/// Authentic columns with a row from another matrix: ColumnMismatch. A committed column
/// holding the limb p: NoncanonicalField, after authentication.
#[test]
fn rejects_column_mismatch_and_noncanonical_columns() {
    let c: Value = serde_json::from_str(POLICY2.lines().next().expect("case")).expect("case");
    let s = source(&c, 2);
    assert_eq!(
        verify_certificate::<QM31>(&s, &hex(&c["column_mismatch"])).map(|_| ()),
        Err(Error::ColumnMismatch)
    );
    let mut malformed = s;
    malformed.root = hex(&c["noncanonical_root"]).try_into().expect("root");
    assert_eq!(
        verify_certificate::<QM31>(&malformed, &hex(&c["noncanonical"])).map(|_| ()),
        Err(Error::NoncanonicalField)
    );
}

#[test]
fn rejects_unsupported_sources_and_mismatched_fields() {
    let base = Source {
        degree: 4,
        id: 1,
        ell: 1,
        m: 1,
        blowup: 1,
        policy: 2,
        root: [0; 32],
    };
    for bad in [
        Source { degree: 5, ..base },
        Source { ell: 31, ..base },
        Source { policy: 3, ..base },
        Source { blowup: 3, ..base },
        Source {
            m: 29,
            blowup: 2,
            ..base
        },
    ] {
        assert_eq!(bad.bytes(), Err(Error::UnsupportedSource));
    }
    // A degree-4 source cannot back an OM31 certificate.
    assert_eq!(
        verify_certificate::<OM31>(&base, &[1]).map(|_| ()),
        Err(Error::CertificateContext)
    );
}
