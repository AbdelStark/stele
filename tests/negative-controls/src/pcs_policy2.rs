//! RFC-0010 A14 items 3,4,8 and RFC-0012 A17 item 5: Policy 2 nonce and query-count
//! controls through the actual native certificate and opening verifiers (NC-0806..0809,
//! NC-0813).
//!
//! Nonce choices come from an independent replay of the A1 transcript and the A17
//! predicate (`Replay`), never from the transcript under test. Every search is capped,
//! so a verifier that stops checking nonces turns a control red instead of hanging it.
use crate::{check_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{merkle, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_opening, CodeField, Error, Functional, Policy, PreparedSource,
    ProofKind,
};

const PUBLIC: &[u8] = b"stele/v0.1/pcs-certificate/public";
const OPENING: &[u8] = b"policy 2 controls";
/// Cap on every nonce search: 2^20 candidates (expected 2 at 16 bits).
const SEARCH: u64 = 1 << 20;

/// Independent RFC-0012 A1 transcript state and A17 predicate, from the RFC text.
#[derive(Clone)]
pub(crate) struct Replay {
    state: [u8; 32],
    degree: usize,
}
impl Replay {
    fn frame(&self, tag: u8, label: &str, payload: &[u8]) -> blake3::Hasher {
        let mut h = blake3::Hasher::new();
        h.update(&self.state);
        h.update(&[tag]);
        h.update(&(label.len() as u32).to_le_bytes());
        h.update(label.as_bytes());
        h.update(&(payload.len() as u64).to_le_bytes());
        h.update(payload);
        h
    }
    pub(crate) fn new(public: &[u8], degree: usize) -> Self {
        let initial = Self {
            state: *blake3::hash(b"stele/v0.1/transcript/init").as_bytes(),
            degree,
        };
        let state = *initial
            .frame(0, "stele/v0.1/public", public)
            .finalize()
            .as_bytes();
        Self { state, degree }
    }
    pub(crate) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        self.state = *self.frame(0, label, bytes).finalize().as_bytes();
    }
    /// A1 field challenge: rejection-sample d limbs from a 256-byte XOF, then commit.
    fn challenge(&mut self, label: &str) {
        let mut raw = [0; 256];
        self.frame(1, label, &[self.degree as u8])
            .finalize_xof()
            .fill(&mut raw);
        let mut payload = vec![self.degree as u8, 0, 0, 0, 0];
        let mut accepted = 0;
        for (index, word) in raw.chunks_exact(4).enumerate() {
            let limb = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) & 0x7fff_ffff;
            if limb < M31::MODULUS {
                payload.extend_from_slice(&limb.to_le_bytes());
                accepted += 1;
                if accepted == self.degree {
                    payload[1..5].copy_from_slice(&(index as u32 + 1).to_le_bytes());
                    break;
                }
            }
        }
        assert_eq!(accepted, self.degree, "fixture challenge sampled");
        self.state = *self.frame(2, label, &payload).finalize().as_bytes();
    }
    fn grind_payload(bits: u8, nonce: u64) -> [u8; 9] {
        let mut payload = [bits; 9];
        payload[1..].copy_from_slice(&nonce.to_le_bytes());
        payload
    }
    /// A17: u64le of the first 8 bytes of H(frame(S, 3, grind, k||n)) has k trailing zeros.
    pub(crate) fn pow(&self, bits: u8, nonce: u64) -> bool {
        let digest = self
            .frame(3, "stele/v0.1/grind", &Self::grind_payload(bits, nonce))
            .finalize();
        let mut word = [0; 8];
        word.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(word).trailing_zeros() >= u32::from(bits)
    }
    fn absorb_nonce(&mut self, bits: u8, nonce: u64) {
        self.state = *self
            .frame(0, "stele/v0.1/grind", &Self::grind_payload(bits, nonce))
            .finalize()
            .as_bytes();
    }
    /// Least nonce after `from` satisfying `keep`, within the search cap.
    pub(crate) fn search(
        &self,
        from: u64,
        keep: impl Fn(&Self, u64) -> bool,
    ) -> Result<u64, Error> {
        (from + 1..from + 1 + SEARCH)
            .find(|nonce| keep(self, *nonce))
            .ok_or(Error::Capacity)
    }
}

/// Which round the single tamper targets.
#[derive(Clone, Copy, PartialEq)]
enum Target {
    Certificate,
    Opening,
    Tensor,
}
#[derive(Clone, PartialEq)]
struct Witness(Option<Target>);
struct Tamper(Target);
impl ProverHook<Witness> for Tamper {
    fn tamper(&self, w: &mut Witness) {
        w.0 = Some(self.0);
    }
}

fn nonce_at(proof: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&proof[at..at + 8]);
    u64::from_le_bytes(word)
}

fn set_nonce(proof: &mut [u8], at: usize, nonce: u64) {
    proof[at..at + 8].copy_from_slice(&nonce.to_le_bytes());
}

/// Row-major message of an R x C source; small canonical limbs.
fn message(ell: u8, m: u8) -> Vec<M31> {
    (0..1i64 << ell)
        .flat_map(|i| (0..1i64 << m).map(move |j| M31::from_i64((i + 2) * (j + 3))))
        .collect()
}

fn functional<K: ChallengeField>(message: &[M31], ell: u8, m: u8) -> (Vec<K>, Vec<K>, K) {
    let table = |n: u8, offset: i64| {
        stele_poly::eq_table(
            &(0..n)
                .map(|i| K::from_i64(i64::from(i) + offset))
                .collect::<Vec<_>>(),
        )
        .expect("small table")
    };
    let (a, b) = (table(ell, 5), table(m, 11));
    let mut value = K::from_i64(0);
    for (r, weight) in a.iter().enumerate() {
        for (c, coefficient) in b.iter().enumerate() {
            let limb = message[r * b.len() + c].as_u32();
            value = value + *weight * *coefficient * K::from_i64(i64::from(limb));
        }
    }
    (a, b, value)
}

/// Run one control on a Policy 2 source of R = 2^ell rows and C = 2^m columns.
fn check<K: ChallengeField + CodeField>(
    id: u16,
    target: Target,
    (ell, m, blowup): (u8, u8, u8),
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let fail = |e: Error| format!("NC-{id:04} {e:?}");
    let message = message(ell, m);
    let code = [&b"stele/circle-m31/v1"[..], &[m, blowup]].concat();
    let prepared = PreparedSource::<K>::from_code_id_policy(
        41,
        ell,
        &code,
        &message,
        &mut HashUsage::default(),
        Policy::Two,
    )
    .map_err(fail)?;
    let source = *prepared.source();
    let degree = usize::from(<K as CodeField>::DEGREE);
    let (tensor_bits, column_bits) = source.grind_bits(ProofKind::Certificate);
    let row = source.columns() * 4 * degree;
    let tensor = 8 * usize::from(tensor_bits > 0);
    let stride = 4 * source.rows() + 32 * source.path_height();
    let (a, b, value) = functional::<K>(&message, ell, m);
    let f = Functional {
        id: 3,
        a: &a,
        b: &b,
        value,
    };
    let (cert0, open0, cert_id) = (|| {
        let certificate = prepared.certificate().map_err(|e| e.cause)?.0;
        let verified = verify_certificate(source, &certificate)
            .map_err(|e| e.cause)?
            .0;
        let mut t = Transcript::new(OPENING).map_err(Error::Transcript)?;
        let opening = prepared
            .opening(&mut t, &verified, f)
            .map_err(|e| e.cause)?
            .0;
        Ok::<_, Error>((certificate, opening, verified.record().id()))
    })()
    .map_err(fail)?;

    // Independent states at each nonce, from the honest bytes and the RFC schedule.
    let (column_at, open_at) = (1 + tensor + row, 1 + row);
    let mut public = PUBLIC.to_vec();
    public.extend_from_slice(&source.bytes());
    let tensor_state = Replay::new(&public, degree);
    let mut cert_state = tensor_state.clone();
    if tensor_bits > 0 {
        cert_state.absorb_nonce(tensor_bits, nonce_at(&cert0, 1));
    }
    for _ in 0..ell {
        cert_state.challenge("stele/v0.1/pcs/certificate-weight");
    }
    cert_state.absorb(
        "stele/v0.1/pcs/certificate-row",
        &cert0[1 + tensor..column_at],
    );
    let mut open_state = Replay::new(OPENING, degree);
    let mut frame = 3u64.to_le_bytes().to_vec();
    frame.extend_from_slice(&source.bytes());
    frame.extend_from_slice(&cert_id);
    for v in a.iter().chain(&b).chain([&value]) {
        frame.extend_from_slice(v.to_le_bytes().as_ref());
    }
    open_state.absorb("stele/v0.1/pcs/opening", &frame);
    open_state.absorb("stele/v0.1/pcs/opening-row", &open0[1..open_at]);
    // The replay is checked against every honest nonce before it chooses a tamper.
    let replayed = cert_state.pow(column_bits, nonce_at(&cert0, column_at))
        && open_state.pow(column_bits, nonce_at(&open0, open_at))
        && (tensor_bits == 0 || tensor_state.pow(tensor_bits, nonce_at(&cert0, 1)));
    if !replayed {
        return Err(format!(
            "NC-{id:04} independent replay disagrees with honest nonces"
        ));
    }

    let expected = match id {
        806 | 807 | 813 => Error::Transcript(stele_hash::Error::GrindMismatch),
        808 => Error::Merkle(merkle::Error::RootMismatch),
        _ => Error::ProofShape,
    };
    // (proof, offset, state, bits) of the targeted nonce.
    let locate = |target: Target| match target {
        Target::Certificate => (false, column_at, &cert_state, column_bits),
        Target::Opening => (true, open_at, &open_state, column_bits),
        Target::Tensor => (false, 1, &tensor_state, tensor_bits),
    };
    check_control(
        &Witness(None),
        &Tamper(target),
        |w| {
            let (mut cert, mut open) = (cert0.clone(), open0.clone());
            let Some(target) = w.0 else {
                return Ok((cert, open));
            };
            let (opening, at, state, bits) = locate(target);
            let proof = if opening { &mut open } else { &mut cert };
            let honest = nonce_at(proof, at);
            match id {
                // NC-0806: a nonce failing the predicate, every other byte unchanged.
                806 => set_nonce(proof, at, state.search(honest, |s, n| !s.pow(bits, n))?),
                // NC-0808/0813: another nonce that passes; only the absorbed value changes.
                808 | 813 => set_nonce(proof, at, state.search(honest, |s, n| s.pow(bits, n))?),
                // NC-0807: a k_q - 1 prover: valid at 15 bits, not at 16, absorbed at 15,
                // and every response drawn from that state by the real transcript.
                807 => {
                    let n = state.search(0, |s, n| s.pow(bits - 1, n) && !s.pow(bits, n))?;
                    let mut t = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
                    if tensor_bits > 0 {
                        t.verify_grind(tensor_bits, nonce_at(&cert0, 1))
                            .map_err(Error::Transcript)?;
                    }
                    for _ in 0..ell {
                        t.challenge(stele_hash::ChallengeLabel::CertificateWeight)
                            .map_err(Error::Transcript)?;
                    }
                    t.absorb(
                        stele_hash::AbsorbLabel::CertificateRow,
                        &cert0[1 + tensor..column_at],
                    )
                    .map_err(Error::Transcript)?;
                    t.verify_grind(bits - 1, n).map_err(Error::Transcript)?;
                    cert.truncate(column_at);
                    cert.extend_from_slice(&n.to_le_bytes());
                    for _ in 0..source.queries(ProofKind::Certificate) {
                        let index = t
                            .certificate_column(source.descriptor().count)
                            .map_err(Error::Transcript)?;
                        let response = prepared.response(index)?;
                        cert.extend_from_slice(response.payload);
                        for sibling in response.siblings {
                            cert.extend_from_slice(&sibling);
                        }
                    }
                }
                // NC-0809: one response fewer than the Policy 2 count q_c or q_o.
                809 => {
                    let len = proof.len() - stride;
                    proof.truncate(len);
                }
                _ => unreachable!(),
            }
            Ok::<_, Error>((cert, open))
        },
        |(cert, open)| {
            let (verified, _) = verify_certificate(source, cert).map_err(|e| e.cause)?;
            let mut t = Transcript::new(OPENING).map_err(Error::Transcript)?;
            verify_opening(&mut t, &verified, f, open)
                .map(|_| ())
                .map_err(|e| e.cause)
        },
        expected,
    )
    .map_err(|error| format!("NC-{id:04} {error:?}"))
}

const SMALL: (u8, u8, u8) = (1, 1, 1);
// QM31, R = 8, Circle m = 14, b = 2: k_t = 1, the least shape with a tensor nonce.
const TENSOR: (u8, u8, u8) = (3, 14, 2);

/// Execute the actual certificate and opening consumers for one control id.
pub fn run(id: u16) -> Result<(), String> {
    let (small, tensor): (&[Target], bool) = match id {
        806 => (&[Target::Certificate, Target::Opening], true),
        807 => (&[Target::Certificate], false),
        808 => (&[Target::Certificate, Target::Opening], false),
        809 => (&[Target::Certificate, Target::Opening], false),
        813 => (&[], true),
        _ => return Err(format!("unknown Policy 2 control {id}")),
    };
    for &target in small {
        check::<QM31>(id, target, SMALL)?;
        check::<OM31>(id, target, SMALL)?;
    }
    if tensor {
        check::<QM31>(id, Target::Tensor, TENSOR)?;
    }
    Ok(())
}
