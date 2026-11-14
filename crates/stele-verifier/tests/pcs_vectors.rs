//! E8-02d parity for the PCS consumer. Fixtures:
//! - Policy 1: the six full-byte A9 cases of `crates/stele-pcs/tests/fixtures/field-wire.jsonl`
//!   (the Python oracle's bytes, also read by `stele-pcs`'s own tests);
//! - Policy 2: the four full-byte A14 cases of `tests/fixtures/policy2-full.jsonl`, from
//!   `research/merkle-oracle/dump_policy2_full.py`. One case grinds the tensor round.
//!
//! - `tests/fixtures/pcs-parameters.txt`, `policy1-continuations.txt` and
//!   `single-mismatch.jsonl`, from the same script (see there).
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
const PARAMETERS: &str = include_str!("fixtures/pcs-parameters.txt");
const OPENING_CONTINUATIONS: &str =
    include_str!("../../stele-pcs/tests/fixtures/opening-continuation.txt");
const CONTINUATIONS: &str = include_str!("fixtures/policy1-continuations.txt");
const SINGLE: &str = include_str!("fixtures/single-mismatch.jsonl");

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

/// The certificate and opening of `c` verify; returns the next two challenges.
fn honest<K: ChallengeField + Eq>(c: &Value, s: &Source) -> [Vec<u8>; 2]
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let cert = verify_certificate::<K>(s, &hex(&c["certificate"])).expect("certificate");
    assert_eq!(cert.id().to_vec(), hex(&c["certificate_id"]));
    let (a, b) = (values::<K>(&hex(&c["a"])), values::<K>(&hex(&c["b"])));
    let v = values::<K>(&hex(&c["value"]))[0];
    let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
    verify_opening(&mut t, 12, &cert, &a, &b, v, &hex(&c["opening"])).expect("opening");
    let mut next = || {
        let x = t.challenge(ChallengeLabel::Sumcheck).expect("continuation");
        x.to_le_bytes().as_ref().to_vec()
    };
    [next(), next()]
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
    // The last path byte of the first, middle and last response: that path no longer
    // reaches the root. The block follows every index draw, so the draws are unchanged.
    let p = s.parameters().expect("parameters");
    let count = usize::from(p.certificate_queries);
    let stride = (4usize << s.ell) + 32 * usize::from(s.m + s.blowup);
    let start = cert.len() - count * stride;
    for q in [0, count / 2, count - 1] {
        let mut bad = cert.clone();
        bad[start + (q + 1) * stride - 1] ^= 1;
        assert!(
            matches!(verify(&bad, s), Err(Error::Merkle(_))),
            "response {q}"
        );
    }
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
    let open = |bytes: &[u8], v: K, a: &[K], b: &[K]| {
        let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        verify_opening(&mut t, 12, &honest, a, b, v, bytes)
    };
    for bad in [
        &opening[..opening.len() - 1],
        &[opening.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(open(bad, v, &a, &b), Err(Error::ProofShape));
    }
    assert_eq!(
        open(&opening, v + K::from_i64(1), &a, &b),
        Err(Error::ValueMismatch)
    );
    assert_eq!(open(&opening, v, &a[1..], &b), Err(Error::FunctionalShape));
    assert_eq!(open(&opening, v, &a, &b[1..]), Err(Error::FunctionalShape));
}

#[test]
fn matches_reference_policy1_certificates_and_openings() {
    let mut count = 0;
    let expected = OPENING_CONTINUATIONS.lines().zip(CONTINUATIONS.lines());
    for (line, (first, second)) in POLICY1.lines().zip(expected) {
        let c: Value = serde_json::from_str(line).expect("case");
        let s = source(&c, 1);
        // The oracle's first challenge after the opening (its own replay), and the one
        // drawn from the state it recorded after that first draw.
        let next = if s.degree == 4 {
            tampers::<QM31>(&c, &s);
            honest::<QM31>(&c, &s)
        } else {
            tampers::<OM31>(&c, &s);
            honest::<OM31>(&c, &s)
        };
        assert_eq!(next[0], hex(&Value::from(first)), "continuation");
        assert_eq!(next[1], hex(&Value::from(second)), "recorded state");
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
        assert_eq!(next[0], hex(&c["continuation"]), "continuation");
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

/// A9 §1 / A14 items 2 and 4: (N, D, e, q_c, q_o) for every Circle code under both
/// policies, and k_t for every ell and both fields, equal the oracle's table.
#[test]
fn matches_reference_pcs_parameters() {
    let mut rows = 0;
    for line in PARAMETERS.lines() {
        let f: Vec<u64> = line
            .split(' ')
            .map(|x| x.parse().expect("number"))
            .collect();
        let (policy, m, blowup) = (f[0] as u8, f[1] as u8, f[2] as u8);
        for (i, degree) in [4u8, 8].into_iter().enumerate() {
            for ell in 0..=30u8 {
                let s = Source {
                    degree,
                    id: 41,
                    ell,
                    m,
                    blowup,
                    policy,
                    root: [0; 32],
                };
                let p = s.parameters().expect("parameters");
                let got = [
                    p.n,
                    p.d,
                    p.e,
                    u64::from(p.certificate_queries),
                    u64::from(p.opening_queries),
                    u64::from(p.tensor_bits),
                    u64::from(p.column_bits),
                ];
                let column = if policy == 2 { 16 } else { 0 };
                let want = [
                    f[3],
                    f[4],
                    f[5],
                    f[6],
                    f[7],
                    f[8 + 31 * i + ell as usize],
                    column,
                ];
                assert_eq!(got, want, "{line} degree {degree} ell {ell}");
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 118 * 62);
}

/// A9 §3: a committed matrix that differs from the honest encoding in one limb of one
/// column, drawn exactly once (first query, then last): ColumnMismatch.
#[test]
fn rejects_a_single_mismatched_column_first_and_last() {
    let mut positions = Vec::new();
    for line in SINGLE.lines() {
        let c: Value = serde_json::from_str(line).expect("case");
        let s = source(&c, 1);
        assert_eq!(
            verify_certificate::<QM31>(&s, &hex(&c["certificate"])).map(|_| ()),
            Err(Error::ColumnMismatch)
        );
        positions.push(c["position"].as_str().expect("position").to_string());
    }
    assert_eq!(positions, ["first", "last"]);
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
