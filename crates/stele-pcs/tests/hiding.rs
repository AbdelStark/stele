//! RFC-0013 A2 item 1, RFC-0010 A14: hiding sources through the actual A9
//! certificate and opening verifiers, and evidence that opened values are masked.
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    hiding_message, verify_certificate, verify_point, Error, PreparedSource, ProofKind, Source,
};

// QM31 needs R >= 8 (ell = 3); Circle (10, 2) gives q_c + q_o = 444 <= C - 1 = 511.
const ELL: u8 = 3;
const M: u8 = 9;
const B: u8 = 2;

fn data(fill: impl Fn(usize) -> i64) -> Vec<M31> {
    (0..(1usize << (ELL + M)))
        .map(|i| M31::from_i64(fill(i)))
        .collect()
}

fn element<K: ChallengeField + CodeField>(seed: u64) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut limbs = Vec::new();
    for i in 0..u64::from(<K as CodeField>::DEGREE) {
        limbs.extend_from_slice(
            &((seed * 7919 + i * 104_729 + 3) as u32 % 0x7fff_ffff).to_le_bytes(),
        );
    }
    K::from_le_bytes(K::Bytes::try_from(&limbs[..]).ok().expect("width")).expect("canonical")
}

/// The multilinear value of the row-major `rows × columns` matrix at `point`.
fn evaluate<K: ChallengeField>(message: &[M31], point: &[K]) -> K {
    let weights = stele_poly::eq_table(point).expect("eq");
    message
        .iter()
        .zip(&weights)
        .fold(K::from_i64(0), |sum, (x, w)| {
            sum + *w * K::from_i64(i64::from(x.as_u32()))
        })
}

fn round_trip<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (ell, m) = if <K as CodeField>::DEGREE == 8 {
        (ELL + 1, M)
    } else {
        (ELL, M)
    };
    let x: Vec<M31> = (0..(1usize << (ell + m)))
        .map(|i| M31::from_i64(i as i64 % 251 - 125))
        .collect();
    let seed = [9; 32];
    let message = hiding_message(41, ell, m, &x, &seed).expect("layout");
    let prepared =
        PreparedSource::<K>::hiding(41, ell, m, B, &message, &seed, &mut HashUsage::default())
            .expect("prepare");
    let source = *prepared.source();
    assert!(source.is_hiding());
    assert_eq!(
        Source::<K>::from_bytes(&source.bytes())
            .expect("bytes")
            .bytes(),
        source.bytes()
    );
    assert_eq!(source.bytes()[23], 3);
    let (certificate, _) = prepared.certificate().expect("certificate");
    assert_eq!(
        certificate.len(),
        source.proof_size(ProofKind::Certificate).expect("size")
    );
    let expected = Source::<K>::hiding(41, ell, m, B, source.root()).expect("expected");
    let (verified, _) = verify_certificate(expected, &certificate).expect("verified");
    // A2 point: W = κ (nonzero), data rows, Y = 0, data columns.
    let mut point = vec![element::<K>(1)];
    point.extend((0..ell).map(|i| element::<K>(10 + u64::from(i))));
    point.push(K::from_i64(0));
    point.extend((0..m).map(|i| element::<K>(40 + u64::from(i))));
    let value = evaluate(&message, &point);
    let mut prover = Transcript::<K>::new(b"hiding opening").expect("transcript");
    let (proof, _) = prepared
        .opening_point(&mut prover, &verified, 3, &point, value)
        .expect("opening");
    let mut verifier = Transcript::<K>::new(b"hiding opening").expect("transcript");
    verify_point(&mut verifier, &verified, 3, &point, value, &proof).expect("accepted");
    // The point's data part alone would reveal X; the rank check refuses W = 0.
    point[0] = K::from_i64(0);
    let value = evaluate(&message, &point);
    let mut prover = Transcript::<K>::new(b"hiding opening").expect("transcript");
    let refused = prepared.opening_point(&mut prover, &verified, 3, &point, value);
    assert_eq!(refused.err().map(|f| f.cause), Some(Error::MaskRank));
}

#[test]
fn accepts_hiding_certificate_and_opening() {
    round_trip::<QM31>();
    round_trip::<OM31>();
}

#[test]
fn rejects_hiding_context_outside_admission() {
    // R < 2D, and a budget q_c + q_o above C - 1 (Circle (9, 2): 444 > 255).
    assert_eq!(
        Source::<QM31>::hiding(1, 2, M, B, [0; 32]).err(),
        Some(Error::UnsupportedSource)
    );
    assert_eq!(
        Source::<OM31>::hiding(1, ELL, M, B, [0; 32]).err(),
        Some(Error::UnsupportedSource)
    );
    assert_eq!(
        Source::<QM31>::hiding(1, ELL, M - 1, B, [0; 32]).err(),
        Some(Error::UnsupportedSource)
    );
    let source = Source::<QM31>::hiding(1, ELL, M, B, [0; 32]).expect("admitted");
    let mut bytes = source.bytes().to_vec();
    bytes[33] = 3; // claims R = 4 data rows
    assert_eq!(
        Source::<QM31>::from_bytes(&bytes).err(),
        Some(Error::UnsupportedSource)
    );
}

/// First certificate response's data-row-0 symbol, and the certificate row's first
/// limb, for one secret and one seed.
fn observe(x: &[M31], seed: [u8; 32], masked: bool) -> (u32, u32) {
    let mut message = hiding_message(5, ELL, M, x, &seed).expect("layout");
    if !masked {
        // Negative control: the same layout with every mask set to zero.
        let c = 1usize << M;
        for (i, value) in message.iter_mut().enumerate() {
            let (row, column) = (i / (2 * c), i % (2 * c));
            if row >= 1 << ELL || column >= c {
                *value = M31::ZERO;
            }
        }
    }
    let prepared =
        PreparedSource::<QM31>::hiding(5, ELL, M, B, &message, &seed, &mut HashUsage::default())
            .expect("prepare");
    let (certificate, _) = prepared.certificate().expect("certificate");
    let row = 1 + 2 * (1usize << M) * 16;
    let symbol = u32::from_le_bytes(certificate[row + 32..row + 36].try_into().expect("limb"));
    let limb = u32::from_le_bytes(certificate[1..5].try_into().expect("limb"));
    (symbol, limb)
}

/// Pearson statistic of the top three bits against the uniform distribution.
fn chi_square(values: &[u32]) -> u64 {
    let mut counts = [0u64; 8];
    for value in values {
        counts[(*value >> 28) as usize] += 1;
    }
    let n = values.len() as u64;
    counts
        .iter()
        .map(|count| (8 * count).abs_diff(n).pow(2) / (8 * n))
        .sum()
}

/// RFC-0013 A2 Lemmas 1-2: an opened column symbol and a certificate row value are
/// uniform for the all-zero and the all-one secret. With the masks removed, the
/// zero secret's view is all zeros and the test detects it.
#[test]
fn accepts_masked_opened_values_and_rejects_unmasked() {
    let zeros = data(|_| 0);
    let ones = data(|_| 1);
    let seeds: Vec<[u8; 32]> = (0..96u8).map(|i| [i; 32]).collect();
    for x in [&zeros, &ones] {
        let (symbols, limbs): (Vec<u32>, Vec<u32>) =
            seeds.iter().map(|seed| observe(x, *seed, true)).unzip();
        // 7 degrees of freedom: 30 is beyond the 0.999 quantile (24.3).
        assert!(chi_square(&symbols) < 30, "{}", chi_square(&symbols));
        assert!(chi_square(&limbs) < 30, "{}", chi_square(&limbs));
    }
    // Unmasked, the zero secret shows only zeros while the one secret does not:
    // the same view separates the two secrets.
    let (symbols, limbs): (Vec<u32>, Vec<u32>) = seeds[..16]
        .iter()
        .map(|seed| observe(&zeros, *seed, false))
        .unzip();
    assert!(symbols.iter().chain(&limbs).all(|s| *s == 0));
    assert!(chi_square(&symbols) > 30);
    let (_, limbs): (Vec<u32>, Vec<u32>) = seeds[..16]
        .iter()
        .map(|seed| observe(&ones, *seed, false))
        .unzip();
    assert!(limbs.iter().any(|s| *s != 0));
}
