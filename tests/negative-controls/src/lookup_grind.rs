//! RFC-0008 A8 and RFC-0012 A17 item 5: the standard-profile LU (β, α) nonce,
//! through the actual A5 lookup verifier (NC-0814..0816).
//!
//! The fixture is a QM31 `sigmoid_q` lookup (c = 2, N = 1, t = 2^16), whose round
//! needs k = 2 bits. Nonce choices come from an independent replay of the A1
//! transcript and the A17 predicate (`pcs_policy2::Replay`), checked first against
//! the honest nonce; every search is capped at 2^20 candidates.
use crate::check_control;
use crate::pcs_policy2::Replay;
use stele_field::{Field, M31, QM31};
use stele_hash::{HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::lookup::{
    Descriptor, Error, Layout, Limits, ProducerLimits, Statement, Table, TableDescriptor,
};

const PUBLIC: &[u8] = b"standard lookup controls";
const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 64_000_000,
    proof_bytes: 64_000_000,
};

#[derive(Clone, PartialEq)]
struct Witness(bool);
struct Tamper;
impl crate::ProverHook<Witness> for Tamper {
    fn tamper(&self, w: &mut Witness) {
        w.0 = true;
    }
}

fn phase(id: u64, j: u8, phase: u8) -> Vec<u8> {
    let mut out = id.to_le_bytes().to_vec();
    out.extend_from_slice(&[j, phase]);
    out
}

/// Execute the actual standard A5 producer and verifier for one control id.
pub fn run(id: u16) -> Result<(), String> {
    let fail = |e: String| format!("NC-{id:04} {e}");
    let table = Table::generate(
        TableDescriptor::new("sigmoid_q", 1, &[0, 0]).map_err(|e| fail(format!("{e:?}")))?,
    )
    .map_err(|e| fail(format!("{e:?}")))?;
    let messages: Vec<Vec<M31>> = (0..2)
        .map(|a| vec![M31::from_i64(i64::from(table.entries()[2 + a]))])
        .collect();
    let prepared = messages
        .iter()
        .enumerate()
        .map(|(a, m)| {
            PreparedSource::<QM31>::new(10 + a as u64, 0, 0, 1, m, &mut HashUsage::default())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| fail(format!("{e:?}")))?;
    let certificates = prepared
        .iter()
        .map(|p| {
            let bytes = p.certificate().map_err(|e| e.cause)?.0;
            verify_certificate(*p.source(), &bytes)
                .map(|v| v.0)
                .map_err(|e| e.cause)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| fail(format!("{e:?}")))?;
    let originals: Vec<_> = certificates.iter().collect();
    let material: Vec<_> = prepared.iter().collect();
    let layouts = [Layout {
        id: 20,
        ell: 8,
        blowup: 1,
    }];
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
    .map_err(|e| fail(format!("{e:?}")))?;
    let bits = descriptor.grind_bits();
    if bits != 2 {
        return Err(fail(format!("fixture needs k = 2, derived {bits}")));
    }
    let limits = ProducerLimits {
        public_bytes: descriptor
            .producer_public_bytes()
            .map_err(|e| fail(format!("{e:?}")))?,
        dense_elements: descriptor
            .producer_dense_elements()
            .map_err(|e| fail(format!("{e:?}")))?,
    };
    let mut pt = Transcript::<QM31>::new(PUBLIC).map_err(|e| fail(format!("{e:?}")))?;
    let honest = descriptor
        .prove(&mut pt, &material, limits)
        .map_err(|e| fail(format!("{:?}", e.cause)))?
        .0;
    let (mu, _) = descriptor
        .register_multiplicities(&honest, usize::MAX)
        .map_err(|e| fail(format!("{:?}", e.cause)))?;
    let source = mu[0].record().source();
    // RFC-0008 A8 item 5: the nonce follows the version, degree and registration.
    let at = 2
        + 32
        + source
            .proof_size(ProofKind::Certificate)
            .map_err(|e| fail(format!("{e:?}")))?;

    // Independent replay of native-lookup §4 steps 1-4 up to the nonce.
    let statement = descriptor
        .encode(&mut HashUsage::default())
        .map_err(|e| fail(format!("{e:?}")))?;
    let mut state = Replay::new(PUBLIC, usize::from(<QM31 as CodeField>::DEGREE));
    state.absorb("stele/v0.1/lookup/statement", &statement);
    state.absorb("stele/v0.1/lookup/units", &phase(7, 0, 0)[..9]);
    let mut bundle = 7u64.to_le_bytes().to_vec();
    bundle.extend_from_slice(&[1, 0]);
    bundle.extend_from_slice(&source.bytes());
    bundle.extend_from_slice(&mu[0].record().id());
    state.absorb("stele/v0.1/lookup/multiplicities", &bundle);
    state.absorb("stele/v0.1/lookup/repetition", &phase(7, 0, 0));
    let nonce = u64::from_le_bytes(
        honest[at..at + 8]
            .try_into()
            .map_err(|_| fail("wire".into()))?,
    );
    if !state.pow(bits, nonce) || (0..nonce).any(|n| state.pow(bits, n)) {
        return Err(fail(
            "independent replay disagrees with the honest least nonce".into(),
        ));
    }

    let expected = match id {
        814 | 815 => Error::Transcript(stele_hash::Error::GrindMismatch),
        // The absorbed nonce changes β and α, so the lookup tree's first round sum fails.
        816 => Error::Fraction(stele_lookup::fraction::Error::Sumcheck(
            stele_sumcheck::Error::RoundSumMismatch,
        )),
        _ => return Err(format!("unknown LU grinding control {id}")),
    };
    check_control(
        &Witness(false),
        &Tamper,
        |w| {
            let mut proof = honest.clone();
            if w.0 {
                let n = match id {
                    // NC-0814: a nonce failing the k-bit predicate, every other byte unchanged.
                    814 => state.search(nonce, |s, n| !s.pow(bits, n)),
                    // NC-0815: a k-1 prover's nonce: valid at k-1 bits, not at k. The
                    // check precedes every draw, so no later byte is read.
                    815 => state.search(0, |s, n| s.pow(bits - 1, n) && !s.pow(bits, n)),
                    // NC-0816: another valid nonce; only the absorbed value changes.
                    _ => state.search(nonce, |s, n| s.pow(bits, n)),
                }
                .map_err(|e| format!("{e:?}"))?;
                proof[at..at + 8].copy_from_slice(&n.to_le_bytes());
            }
            Ok::<_, String>(proof)
        },
        |proof| {
            let handles: Vec<_> = mu.iter().collect();
            let mut t = Transcript::<QM31>::new(PUBLIC).map_err(Error::Transcript)?;
            descriptor
                .verify(&mut t, &handles, proof)
                .map(|_| ())
                .map_err(|e| e.cause)
        },
        expected,
    )
    .map_err(|error| fail(format!("{error:?}")))
}
