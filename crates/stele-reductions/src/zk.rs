//! RFC-0013 A4: the masked A1 sumcheck with its mask bound by a hiding source.
//!
//! Order on the caller's transcript: `Instance`, the mask source bytes
//! (`FieldSources`), `zk/mask-sum`, `zk/mask-weight`, the A1 rounds, `Final`,
//! then one A9 opening of the mask source at `μ = G(ρ)`. The certificate runs on
//! its own A9 transcript and is bound by the opening frame. The returned
//! reduction keeps A1's final obligations; the mask obligation is discharged.
//!
//! [`claims`] composes masked claims, zero-sums and per-source batches (A5).
use alloc::vec::Vec;
use stele_field::{Serialize, M31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    hiding_message, verify_certificate, verify_opening, CodeField, Functional, Policy,
    PreparedSource, Source,
};
use stele_sumcheck::masked::{self, Mask, MaskRecord};
use stele_sumcheck::{Instance, Reduction, Summand};

#[path = "zk_claims.rs"]
pub mod claims;
#[path = "zk_relation.rs"]
pub mod relation;

/// Log blowup of every mask source (Circle rate 1/4).
const BLOWUP: u8 = 2;
/// Least data exponent with `q_c + q_o ≤ C − 1` at blowup 2 (`314 + 130 ≤ 511`).
const MIN_M: u8 = 9;

/// Rejected statement, proof or abort; never partial acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The masked sumcheck failed; its cause is preserved.
    Sumcheck(stele_sumcheck::Error),
    /// The mask source, certificate or opening failed; its cause is preserved.
    Pcs(stele_pcs::Error),
    /// The mask source bytes are not the expected version-3 layout for this instance.
    MaskSource,
    /// `ρ_n ∈ {0, 1/2}`: the producer aborts on this public event (A4 item 5).
    MaskPoint,
    /// A dev-zk statement or witness outside RFC-0013 A5 / RFC-0026 A9's forms.
    Statement,
    /// Producer abort: a claim block's coordinates have rank `< D` (A5 item 4).
    ClaimRank,
    /// Producer abort: `κ(ρ_v) = 0` for a masked occurrence (A5 item 4).
    Vanishing,
    /// Producer abort: a batch's final point has `w* = 0` (A5 item 4).
    BatchPoint,
    /// Producer abort: a zero denominator in a lookup's committed top layer
    /// (RFC-0008 A7 item 3).
    DenominatorZero,
}

/// One bound masked instance: source bytes, certificate, rounds and opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// The mask source's exact version-3 bytes, root included.
    pub source: Vec<u8>,
    /// The mask source's A9 certificate.
    pub certificate: Vec<u8>,
    /// The masked A1 rounds, finals and `μ`.
    pub sumcheck: masked::Proof<K>,
    /// The A9 opening of the mask source at `μ`.
    pub opening: Vec<u8>,
}

/// `(ell, m)` of the mask source: `2D` data rows, `C ≥ n(δ+1) − 1` and the budget.
fn layout<K: ChallengeField + CodeField>(
    i: &Instance<K>,
    degree: usize,
) -> Result<(u8, u8), Error> {
    let width = (i.num_vars as usize)
        .checked_mul(degree + 1)
        .ok_or(Error::MaskSource)?;
    let mut m = MIN_M;
    while (1usize << m) < width {
        m += 1;
        if m >= 30 {
            return Err(Error::MaskSource);
        }
    }
    Ok((
        (2 * (<K as CodeField>::DEGREE as usize)).trailing_zeros() as u8,
        m,
    ))
}

/// A single-use secret seed for one bound masked instance.
///
/// It is neither `Copy` nor `Clone`, and [`prove`] consumes it, so one value
/// cannot be used for two proofs. The caller must fill it from a CSPRNG and must
/// never build two seeds from the same bytes (see [`prove`]'s security notes).
pub struct Seed([u8; 32]);
impl Seed {
    /// Wrap 32 bytes of fresh secret randomness. Each call must use new bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The basis element `e_d` of `K` over M31 (limb `d` set to one).
fn basis<K: ChallengeField + CodeField>(d: usize) -> Result<K, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut limbs = [0u8; 32];
    limbs[4 * d] = 1;
    let bytes = K::Bytes::try_from(&limbs[..4 * (<K as CodeField>::DEGREE as usize)])
        .map_err(|_| Error::MaskSource)?;
    K::from_le_bytes(bytes).ok_or(Error::MaskSource)
}

/// A4 item 4: `a_(b,d) = ℓ_b(ρ_n)·e_d` on the data rows, zero on the mask rows;
/// `b` = the Lagrange weights of every mask column, zero elsewhere.
fn functional<K: ChallengeField + CodeField>(
    i: &Instance<K>,
    degree: usize,
    columns: usize,
    point: &[K],
) -> Result<(Vec<K>, Vec<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let last = *point.last().ok_or(Error::MaskSource)?;
    let weights = [K::from_i64(1) - last, last];
    let mut a = Vec::new();
    for weight in weights {
        for d in 0..(<K as CodeField>::DEGREE as usize) {
            a.push(weight * basis::<K>(d)?);
        }
    }
    a.resize(4 * (<K as CodeField>::DEGREE as usize), K::from_i64(0));
    let mut b =
        masked::column_weights(i.num_vars, degree, point, false).map_err(Error::Sumcheck)?;
    b.resize(columns, K::from_i64(0));
    Ok((a, b))
}

/// Prove one bound masked instance from a fresh secret seed (A4).
///
/// # Security
///
/// Use a seed once per `(seed, instance id)`, across all transcripts. Two
/// proofs that share one reveal the mask's opening row at two points `ρ_n`.
/// Those rows solve for both blocks `g⁰, g¹`, and subtracting `α·G` from the
/// rounds recovers the witness rounds. Nothing in the proof bytes reveals reuse,
/// and the per-object opening counter cannot see it. After `MaskPoint`, or any
/// other error, retry with a fresh seed only if nothing from the failed attempt
/// was published.
pub fn prove<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    summand: impl Summand<K>,
    seed: Seed,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_at(i, summand, &seed.0, t, Policy::One).map(|(proof, _)| proof)
}

/// [`prove`] on borrowed seed bytes, also returning `ρ`; the A5 batch of the
/// shared mask source opens that source at `ρ` (RFC-0013 A5 item 5a). The mask
/// source takes `policy` (RFC-0013 A8: policy 2 under profile byte 4).
fn prove_at<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    summand: impl Summand<K>,
    seed: &[u8; 32],
    t: &mut Transcript<K>,
    policy: Policy,
) -> Result<(Proof<K>, Vec<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let degree = masked::degree(i).map_err(Error::Sumcheck)?;
    let mask = Mask::derive(seed, i).map_err(Error::Sumcheck)?;
    let (ell, m) = layout(i, degree)?;
    let (rows, columns) = (1usize << ell, 1usize << m);
    // Data row b·D + d holds limb d of block b, in canonical column order.
    let mut data = Vec::new();
    data.resize(rows * columns, M31::ZERO);
    for b in 0..2 {
        for (j, value) in mask.columns(b).enumerate() {
            let bytes = value.to_le_bytes();
            for d in 0..(<K as CodeField>::DEGREE as usize) {
                let limb = bytes.as_ref()[4 * d..4 * d + 4]
                    .try_into()
                    .map_err(|_| Error::MaskSource)?;
                data[(b * (<K as CodeField>::DEGREE as usize) + d) * columns + j] =
                    M31::from_le_bytes(limb).ok_or(Error::MaskSource)?;
            }
        }
    }
    let message = hiding_message(i.id, ell, m, &data, seed).map_err(Error::Pcs)?;
    let prepared = PreparedSource::<K>::hiding_mask_with(
        i.id,
        ell,
        m,
        BLOWUP,
        &message,
        seed,
        &mut HashUsage::default(),
        policy,
    )
    .map_err(Error::Pcs)?;
    let certificate = prepared.certificate().map_err(|f| Error::Pcs(f.cause))?.0;
    let verified = verify_certificate(*prepared.source(), &certificate)
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    let source = prepared.source().bytes().to_vec();
    let (sumcheck, point) =
        masked::prove(i, summand, &mask, &source, t).map_err(Error::Sumcheck)?;
    let last = *point.last().ok_or(Error::MaskSource)?;
    // A4 item 5: the mask lemma needs ρ_n ≠ 0 and 2ρ_n ≠ 1; a public abort.
    if last == K::from_i64(0) || last + last == K::from_i64(1) {
        return Err(Error::MaskPoint);
    }
    let (a, b) = functional(i, degree, 2 * columns, &point)?;
    let opening = prepared
        .opening(
            t,
            &verified,
            Functional {
                id: i.id,
                a: &a,
                b: &b,
                value: sumcheck.mask_final,
            },
        )
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((
        Proof {
            source,
            certificate,
            sumcheck,
            opening,
        },
        point,
    ))
}

/// Verify one bound masked instance. The finals remain obligations; `μ` is
/// discharged by the opening. Returns the A1 reduction and its MASK record.
pub fn verify<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<(Reduction<K>, MaskRecord), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    verify_with(i, proof, t, Policy::One)
}

/// [`verify`] with the mask source expected under `policy` (RFC-0013 A8).
fn verify_with<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
    policy: Policy,
) -> Result<(Reduction<K>, MaskRecord), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let degree = masked::degree(i).map_err(Error::Sumcheck)?;
    let (ell, m) = layout(i, degree)?;
    let source = Source::<K>::from_bytes(&proof.source).map_err(Error::Pcs)?;
    let expected = Source::<K>::hiding_with(i.id, ell, m, BLOWUP, source.root(), policy)
        .map_err(Error::Pcs)?;
    if expected.bytes() != source.bytes() {
        return Err(Error::MaskSource);
    }
    let verified = verify_certificate(expected, &proof.certificate)
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    let result = masked::verify(i, &proof.sumcheck, &proof.source, t).map_err(Error::Sumcheck)?;
    let (a, b) = functional(i, degree, expected.columns(), &result.reduction.point)?;
    verify_opening(
        t,
        &verified,
        Functional {
            id: i.id,
            a: &a,
            b: &b,
            value: result.mask_final,
        },
        &proof.opening,
    )
    .map_err(|f| Error::Pcs(f.cause))?;
    Ok((result.reduction, result.mask))
}
