//! RFC-0013 A2 and RFC-0010 A15: hiding-source controls through the actual A9
//! certificate verifier (NC-0902, NC-0903, NC-0906), and masked-sumcheck controls
//! through the actual masked A1 verifier (NC-0904, NC-0905).
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    hiding_message, verify_certificate, verify_point, CodeField, Error, PreparedSource,
    RetainedRow, Source, VerifiedCertificate,
};
use stele_sumcheck::{masked, Dense, Error as SumcheckError, Instance, Term};

const SEED: [u8; 32] = [3; 32];

/// Stand-in mask binding; the RFC-0013 A3 consumer binds real source bytes.
const BINDING: &[u8] = b"test mask binding";

fn layout(degree: u8) -> (u8, u8, u8) {
    // R >= 2D and q_c + q_o <= C - 1 at Circle (10, 2).
    if degree == 8 {
        (4, 9, 2)
    } else {
        (3, 9, 2)
    }
}

fn prepared<K: ChallengeField + CodeField>(
    message: &[M31],
) -> Result<PreparedSource<'_, K>, Error> {
    let (ell, m, b) = layout(<K as CodeField>::DEGREE);
    PreparedSource::<K>::hiding(7, ell, m, b, message, &SEED, &mut HashUsage::default())
}

fn message(degree: u8) -> Vec<M31> {
    let (ell, m, _) = layout(degree);
    let x: Vec<M31> = (0..1i64 << (ell + m))
        .map(|i| M31::from_i64(i % 17 - 8))
        .collect();
    hiding_message(7, ell, m, &x, &SEED).expect("layout")
}

/// Flip one salt byte in the first certificate response.
struct Salt(usize);
impl ProverHook<Vec<u8>> for Salt {
    fn tamper(&self, proof: &mut Vec<u8>) {
        proof[self.0] ^= 1;
    }
}

/// NC-0902: one salt byte changed after the root; the payload no longer
/// authenticates at its derived index.
fn nc_0902<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let source = *p.source();
    // The first response starts after the version byte and the 2C-element row.
    let salt = 1 + source.columns() * 4 * usize::from(<K as CodeField>::DEGREE);
    check_proof_control(
        || p.certificate().map(|(proof, _)| proof).map_err(|f| f.cause),
        &Salt(salt),
        |proof| {
            verify_certificate(source, proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::Merkle(stele_hash::merkle::Error::RootMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

/// A masked point `(κ, ρ_row, 0, ρ_col)` for a hiding source and its value.
fn masked_point<K: ChallengeField>(message: &[M31], source: &Source<K>) -> (Vec<K>, K) {
    let ell = source.rows().trailing_zeros() as usize;
    let m = source.columns().trailing_zeros() as usize;
    // Full extension-field coordinates, so the mask-row coefficients span K.
    let mut draws = stele_hash::Transcript::<K>::new(b"hiding point").expect("transcript");
    let mut point: Vec<K> = (0..ell + m)
        .map(|_| {
            draws
                .challenge(stele_hash::ChallengeLabel::Sumcheck)
                .expect("draw")
        })
        .collect();
    point[ell] = K::from_i64(0); // Y = 0: the data half of the columns.
    let weights = stele_poly::eq_table(&point).expect("eq");
    let value = message
        .iter()
        .zip(&weights)
        .fold(K::from_i64(0), |s, (x, w)| {
            s + *w * K::from_i64(i64::from(x.as_u32()))
        });
    (point, value)
}

fn certified<K: ChallengeField + CodeField>(
    p: &PreparedSource<'_, K>,
) -> Result<VerifiedCertificate<K>, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let proof = p.certificate().map_err(|f| format!("{:?}", f.cause))?.0;
    verify_certificate(*p.source(), &proof)
        .map(|(v, _)| v)
        .map_err(|f| format!("{:?}", f.cause))
}

/// NC-0902, opening half: one salt byte of the first opening response changed.
fn nc_0902_opening<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let verified = certified(&p)?;
    let (point, value) = masked_point(&message, p.source());
    let salt = 1 + p.source().columns() * 4 * usize::from(<K as CodeField>::DEGREE);
    let transcript = || stele_hash::Transcript::<K>::new(b"hiding control").expect("transcript");
    check_proof_control(
        || {
            p.opening_point(&mut transcript(), &verified, 1, &point, value)
                .map(|(proof, _)| proof)
                .map_err(|f| f.cause)
        },
        &Salt(salt),
        |proof| {
            verify_point(&mut transcript(), &verified, 1, &point, value, proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::Merkle(stele_hash::merkle::Error::RootMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

/// NC-0906: a producer refusal, not a verifier binding. After one opening, a
/// second one through the point path or a retained row is refused.
fn nc_0906<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let verified = certified(&p)?;
    let (point, value) = masked_point(&message, p.source());
    let transcript = || stele_hash::Transcript::<K>::new(b"hiding control").expect("transcript");
    p.opening_point(&mut transcript(), &verified, 1, &point, value)
        .map_err(|f| format!("first opening: {:?}", f.cause))?;
    let second = p.opening_point(&mut transcript(), &verified, 2, &point, value);
    if second.err().map(|f| f.cause) != Some(Error::MaskBudget) {
        return Err("second point opening was not refused".to_owned());
    }
    let ell = p.source().rows().trailing_zeros() as usize;
    let a = stele_poly::eq_table(&point[..ell]).map_err(|e| format!("{e:?}"))?;
    let b = stele_poly::eq_table(&point[ell..]).map_err(|e| format!("{e:?}"))?;
    let row = RetainedRow::new(&p, &a).map_err(|e| format!("{e:?}"))?;
    let functional = stele_pcs::Functional {
        id: 3,
        a: &a,
        b: &b,
        value,
    };
    match row.opening(&mut transcript(), &verified, functional) {
        Err(f) if f.cause == Error::MaskBudget => Ok(()),
        _ => Err("second retained-row opening was not refused".to_owned()),
    }
}

/// Replace the expected statement bytes.
struct Replace(Vec<u8>);
impl ProverHook<Vec<u8>> for Replace {
    fn tamper(&self, bytes: &mut Vec<u8>) {
        assert_ne!(*bytes, self.0);
        bytes.clone_from(&self.0);
    }
}

/// NC-0903: a version-3 context with R < 2D, or with q_c + q_o > C - 1, rejects
/// as UnsupportedSource before any transcript work.
fn nc_0903<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let proof = p.certificate().map_err(|f| format!("{:?}", f.cause))?.0;
    let honest = p.source().bytes().to_vec();
    // Version-1 Circle layout: ell at 33, m at 53 (code byte 19).
    for (offset, delta) in [(33usize, 1u8), (53, 1)] {
        let mut changed = honest.clone();
        changed[offset] -= delta;
        check_control(
            &honest,
            &Replace(changed),
            |bytes| Ok::<_, Error>(bytes.clone()),
            |bytes| {
                let source = Source::<K>::from_bytes(bytes)?;
                verify_certificate(source, &proof)
                    .map(|_| ())
                    .map_err(|f| f.cause)
            },
            Error::UnsupportedSource,
        )
        .map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

/// One masked proof value replaced, chosen by the hook.
struct MaskedValue(fn(&mut masked::Proof<QM31>));
impl ProverHook<masked::Proof<QM31>> for MaskedValue {
    fn tamper(&self, proof: &mut masked::Proof<QM31>) {
        (self.0)(proof);
    }
}

/// NC-0904 and NC-0905: an honest masked product sumcheck with `G` or `μ`
/// changed by one; the actual verifier rejects at the first round or at the end.
fn nc_masked(id: u16) -> Result<(), String> {
    let a: Vec<QM31> = (0..16).map(|n| QM31::from_i64(n + 3)).collect();
    let b: Vec<QM31> = (0..16).map(|n| QM31::from_i64(2 * n - 7)).collect();
    let i = Instance {
        id: 5,
        num_vars: 4,
        inputs: vec![11, 12],
        terms: vec![Term {
            coefficient: QM31::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: a
            .iter()
            .zip(&b)
            .fold(QM31::from_i64(0), |s, (x, y)| s + *x * *y),
    };
    let transcript = || Transcript::<QM31>::new(b"masked control").expect("transcript");
    let (hook, expected): (MaskedValue, SumcheckError) = if id == 904 {
        (
            MaskedValue(|p| p.mask_sum = p.mask_sum + QM31::from_i64(1)),
            SumcheckError::RoundSumMismatch,
        )
    } else {
        (
            MaskedValue(|p| p.mask_final = p.mask_final + QM31::from_i64(1)),
            SumcheckError::FinalEvaluationMismatch,
        )
    };
    check_proof_control(
        || {
            let mask = masked::Mask::derive(&SEED, &i)?;
            let dense = Dense::new(&i, vec![a.clone(), b.clone()])?;
            masked::prove(&i, dense, &mask, BINDING, &mut transcript()).map(|(proof, _)| proof)
        },
        &hook,
        |proof| masked::verify(&i, proof, BINDING, &mut transcript()).map(|_| ()),
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}

/// A bound masked product instance of `m` variables and its two witness tables.
fn bound_instance(m: u32, claim_shift: i64) -> (Instance<QM31>, Vec<QM31>, Vec<QM31>) {
    let a: Vec<QM31> = (0..1i64 << m).map(|n| QM31::from_i64(n + 3)).collect();
    let b: Vec<QM31> = (0..1i64 << m).map(|n| QM31::from_i64(2 * n - 7)).collect();
    let sum = a
        .iter()
        .zip(&b)
        .fold(QM31::from_i64(0), |s, (x, y)| s + *x * *y);
    let i = Instance {
        id: 9,
        num_vars: m,
        inputs: vec![11, 12],
        terms: vec![Term {
            coefficient: QM31::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: sum + QM31::from_i64(claim_shift),
    };
    (i, a, b)
}

/// Replace the whole bound proof.
struct BoundProof(stele_reductions::zk::Proof<QM31>);
impl ProverHook<stele_reductions::zk::Proof<QM31>> for BoundProof {
    fn tamper(&self, proof: &mut stele_reductions::zk::Proof<QM31>) {
        assert_ne!(*proof, self.0);
        proof.clone_from(&self.0);
    }
}

/// NC-0907: the mask source (and its certificate) of another seed substituted in
/// an honest bound proof. The source bytes are absorbed before `G`, so `α`
/// moves and the first round check fails.
fn nc_0907() -> Result<(), String> {
    use stele_reductions::zk;
    let (i, a, b) = bound_instance(4, 0);
    let t = || Transcript::<QM31>::new(b"bound control").expect("transcript");
    let dense = || Dense::new(&i, vec![a.clone(), b.clone()]).expect("dense");
    let honest =
        zk::prove(&i, dense(), zk::Seed::new([1; 32]), &mut t()).map_err(|e| format!("{e:?}"))?;
    let other =
        zk::prove(&i, dense(), zk::Seed::new([2; 32]), &mut t()).map_err(|e| format!("{e:?}"))?;
    let mut swapped = honest.clone();
    swapped.source = other.source;
    swapped.certificate = other.certificate;
    check_proof_control(
        || Ok::<_, zk::Error>(honest.clone()),
        &BoundProof(swapped),
        |proof| zk::verify(&i, proof, &mut t()).map(|_| ()),
        zk::Error::Sumcheck(SumcheckError::RoundSumMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

/// NC-0908: the A2 forgery against the bound verifier. A false claimed sum, rounds
/// chosen freely and `μ` solved last, with a genuine mask source, certificate and
/// opening: the actual opening verifier rejects the row against the forged `μ`.
fn nc_0908() -> Result<(), String> {
    use stele_hash::{AbsorbLabel, ChallengeLabel};
    use stele_reductions::zk;
    use stele_sumcheck::message_bytes;
    let m = 3;
    let (true_instance, a, b) = bound_instance(m, 0);
    let (i, _, _) = bound_instance(m, 5);
    let t = || Transcript::<QM31>::new(b"bound control").expect("transcript");
    let honest = zk::prove(
        &true_instance,
        Dense::new(&true_instance, vec![a, b]).expect("dense"),
        zk::Seed::new([3; 32]),
        &mut t(),
    )
    .map_err(|e| format!("{e:?}"))?;
    let mut forged = honest.clone();
    let mut transcript = t();
    let draw = |r: Result<QM31, stele_hash::Error>| r.map_err(|e| format!("{e:?}"));
    let absorb = |r: Result<(), stele_hash::Error>| r.map_err(|e| format!("{e:?}"));
    absorb(transcript.absorb(
        AbsorbLabel::Instance,
        &i.encode().map_err(|e| format!("{e:?}"))?,
    ))?;
    absorb(transcript.absorb(AbsorbLabel::FieldSources, &forged.source))?;
    let mask_sum = forged.sumcheck.mask_sum;
    let bytes = message_bytes(i.id, 0, &[mask_sum]).map_err(|e| format!("{e:?}"))?;
    absorb(transcript.absorb(AbsorbLabel::ZkMaskSum, &bytes))?;
    let alpha = draw(transcript.challenge(ChallengeLabel::ZkMaskWeight))?;
    let mut running = i.claimed_sum + alpha * mask_sum;
    let half = stele_field::Inverse::inverse(QM31::from_i64(2)).ok_or("1/2")?;
    let mut rounds = Vec::new();
    for index in 0..m {
        // p(t) = running·(1−t)(2−t)/2 satisfies p(0) + p(1) = running.
        let values = vec![running, QM31::from_i64(0), QM31::from_i64(0)];
        let bytes = message_bytes(i.id, index, &values).map_err(|e| format!("{e:?}"))?;
        absorb(transcript.absorb(AbsorbLabel::Round, &bytes))?;
        let r = draw(transcript.challenge(ChallengeLabel::Sumcheck))?;
        running = running * (r - QM31::from_i64(1)) * (r - QM31::from_i64(2)) * half;
        rounds.push(values);
    }
    let finals = vec![QM31::from_i64(1), QM31::from_i64(1)];
    let inverse = stele_field::Inverse::inverse(alpha).ok_or("alpha = 0")?;
    forged.sumcheck.rounds = rounds;
    forged.sumcheck.final_values = finals.clone();
    forged.sumcheck.mask_final = (running - finals[0] * finals[1]) * inverse;
    match zk::verify(&i, &forged, &mut t()) {
        Err(zk::Error::Pcs(Error::ValueMismatch)) => Ok(()),
        other => Err(format!(
            "forged mask final not rejected as ValueMismatch: {other:?}"
        )),
    }
}

/// Execute one hiding-source control in both challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    match id {
        907 => nc_0907(),
        908 => nc_0908(),
        904 | 905 => nc_masked(id),
        902 => nc_0902::<QM31>()
            .and_then(|()| nc_0902::<OM31>())
            .and_then(|()| nc_0902_opening::<QM31>())
            .and_then(|()| nc_0902_opening::<OM31>()),
        906 => nc_0906::<QM31>().and_then(|()| nc_0906::<OM31>()),
        903 => nc_0903::<QM31>().and_then(|()| nc_0903::<OM31>()),
        _ => Err(format!("unknown control {id}")),
    }
}
