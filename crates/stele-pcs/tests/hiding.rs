//! RFC-0013 A2 item 1, RFC-0010 A15: hiding sources through the actual A9
//! certificate and opening verifiers, and evidence that opened values are masked.
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    hiding_message, verify_certificate, verify_point, Error, Functional, PreparedSource, ProofKind,
    RetainedRow, Source,
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
    // A second opening would reveal a third row combination: refused through
    // both the point path and the retained-row path.
    let mut prover = Transcript::<K>::new(b"second opening").expect("transcript");
    let again = prepared.opening_point(&mut prover, &verified, 4, &point, value);
    assert_eq!(again.err().map(|f| f.cause), Some(Error::MaskBudget));
    let a = stele_poly::eq_table(&point[..usize::from(ell) + 1]).expect("eq");
    let b = stele_poly::eq_table(&point[usize::from(ell) + 1..]).expect("eq");
    let row = RetainedRow::new(&prepared, &a).expect("row");
    let functional = Functional {
        id: 5,
        a: &a,
        b: &b,
        value,
    };
    let mut prover = Transcript::<K>::new(b"second opening").expect("transcript");
    let again = row.opening(&mut prover, &verified, functional);
    assert_eq!(again.err().map(|f| f.cause), Some(Error::MaskBudget));

    // On a fresh source, the point's data part alone would reveal X; the rank
    // check refuses W = 0.
    let fresh =
        PreparedSource::<K>::hiding(41, ell, m, B, &message, &seed, &mut HashUsage::default())
            .expect("prepare");
    point[0] = K::from_i64(0);
    let value = evaluate(&message, &point);
    let mut prover = Transcript::<K>::new(b"hiding opening").expect("transcript");
    let refused = fresh.opening_point(&mut prover, &verified, 3, &point, value);
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

fn unit<K: ChallengeField + CodeField>(d: usize) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut limbs = vec![0u8; 4 * usize::from(<K as CodeField>::DEGREE)];
    limbs[4 * d] = 1;
    K::from_le_bytes(K::Bytes::try_from(&limbs[..]).ok().expect("width")).expect("canonical")
}

/// RFC-0013 A4: a mask source admits exactly one opening of the two-block shape.
fn mask_source<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let degree = usize::from(<K as CodeField>::DEGREE);
    let ell = (2 * degree).trailing_zeros() as u8;
    let x: Vec<M31> = (0..(1usize << (usize::from(ell) + usize::from(M))))
        .map(|i| M31::from_i64(i as i64 % 97))
        .collect();
    let seed = [21; 32];
    let message = hiding_message(43, ell, M, &x, &seed).expect("layout");
    let prepare = || {
        PreparedSource::<K>::hiding_mask(43, ell, M, B, &message, &seed, &mut HashUsage::default())
            .expect("prepare")
    };
    let prepared = prepare();
    let (certificate, _) = prepared.certificate().expect("certificate");
    let (verified, _) = verify_certificate(*prepared.source(), &certificate).expect("verified");
    let rows = prepared.source().rows();
    let columns = prepared.source().columns();
    let shape = |w1: K| -> Vec<K> {
        let w0 = K::from_i64(1) - w1;
        let mut a: Vec<K> = (0..degree).map(|d| w0 * unit::<K>(d)).collect();
        a.extend((0..degree).map(|d| w1 * unit::<K>(d)));
        a.resize(rows, K::from_i64(0));
        a
    };
    let b: Vec<K> = (0..columns).map(|c| element::<K>(70 + c as u64)).collect();
    let value = |a: &[K]| {
        message
            .chunks_exact(columns)
            .zip(a)
            .fold(K::from_i64(0), |s, (row, w)| {
                s + *w
                    * row.iter().zip(&b).fold(K::from_i64(0), |t, (v, y)| {
                        t + *y * K::from_i64(i64::from(v.as_u32()))
                    })
            })
    };
    let open = |p: &PreparedSource<'_, K>, a: &[K]| {
        let mut t = Transcript::<K>::new(b"mask source").expect("transcript");
        let functional = Functional {
            id: 1,
            a,
            b: &b,
            value: value(a),
        };
        p.opening(&mut t, &verified, functional)
            .map(|(proof, _)| proof)
            .map_err(|f| f.cause)
    };
    // The two-block shape opens and verifies.
    let a = shape(element::<K>(5));
    let proof = open(&prepared, &a).expect("two-block opening");
    let mut t = Transcript::<K>::new(b"mask source").expect("transcript");
    let functional = Functional {
        id: 1,
        a: &a,
        b: &b,
        value: value(&a),
    };
    stele_pcs::verify_opening(&mut t, &verified, functional, &proof).expect("accepted");
    // A second opening is refused.
    assert_eq!(open(&prepared, &a).err(), Some(Error::MaskBudget));
    // Fresh sources: nonzero mask-row weight, a single block (a = e_0, which
    // would reveal g0), and w_1 = 1/2 are each refused.
    let mut masked = shape(element::<K>(5));
    masked[rows - 1] = K::from_i64(1);
    assert_eq!(open(&prepare(), &masked).err(), Some(Error::MaskRank));
    let mut single = vec![K::from_i64(0); rows];
    single[0] = K::from_i64(1);
    assert_eq!(open(&prepare(), &single).err(), Some(Error::MaskRank));
    let half = K::from_i64(2).inverse().expect("1/2");
    assert_eq!(open(&prepare(), &shape(half)).err(), Some(Error::MaskRank));
    // Any other data layout is not a mask source.
    let doubled = [x.clone(), x.clone()].concat();
    let wrong = hiding_message(43, ell + 1, M, &doubled, &seed).expect("layout");
    let other = PreparedSource::<K>::hiding_mask(
        43,
        ell + 1,
        M,
        B,
        &wrong,
        &seed,
        &mut HashUsage::default(),
    );
    assert!(other.is_err());
}

#[test]
fn rejects_mask_source_openings_outside_the_two_block_shape() {
    mask_source::<QM31>();
    mask_source::<OM31>();
}

/// The lifetime tests' data exponent: `q_c + 3·q_o = 704 ≤ C − 1 = 1023`.
const LM: u8 = 10;

/// One opening of a lifetime source (QM31, `ell = 4`: `R = 16 = (P + 1)·D` at
/// `P = 3`, `m = 10`) after `revealed`, at the point whose row part starts at `w`. Returns
/// the opening's result and its row vector.
fn lifetime_opening(revealed: Vec<Vec<QM31>>, w: u64) -> (Result<(), Error>, Vec<QM31>) {
    type K = QM31;
    let (ell, budget) = (ELL + 1, 3);
    let x: Vec<M31> = (0..(1usize << (ell + LM)))
        .map(|i| M31::from_i64(i as i64 % 89 - 44))
        .collect();
    let seed = [11; 32];
    let message = hiding_message(43, ell, LM, &x, &seed).expect("layout");
    let prepared = PreparedSource::<K>::hiding_lifetime(
        43,
        ell,
        LM,
        B,
        &message,
        &seed,
        &mut HashUsage::default(),
        budget,
        revealed,
    )
    .expect("prepare");
    let (certificate, _) = prepared.certificate().expect("certificate");
    let expected = Source::<K>::hiding(43, ell, LM, B, prepared.source().root()).expect("expected");
    let (verified, _) = verify_certificate(expected, &certificate).expect("verified");
    // Unstructured row coordinates (splitmix64 limbs), as Fiat–Shamir gives.
    let mut state = w.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut next = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((z ^ (z >> 31)) % 0x7fff_ffff) as u32
    };
    let mut random = || {
        let limbs: Vec<u8> = (0..4).flat_map(|_| next().to_le_bytes()).collect();
        <K as stele_field::Serialize>::from_le_bytes(limbs[..].try_into().expect("width"))
            .expect("canonical")
    };
    let mut point = vec![random()];
    point.extend((0..ell).map(|_| random()));
    point.push(K::from_i64(0));
    point.extend((0..LM).map(|i| element::<K>(40 + u64::from(i))));
    let value = evaluate(&message, &point);
    let a = stele_poly::eq_table(&point[..usize::from(ell) + 1]).expect("eq");
    let mut prover = Transcript::<K>::new(b"lifetime opening").expect("transcript");
    let result = prepared
        .opening_point(&mut prover, &verified, 3, &point, value)
        .map(|_| ())
        .map_err(|f| f.cause);
    (result, a)
}

/// RFC-0013 A6 (Proposed): a lifetime source at exactly `R = (P + 1)·D`.
/// - `admits_lifetime` holds for `P = 3` and fails for `P = 4` and `0`;
/// - `hiding_lifetime` refuses a spent budget (`MaskBudget`) and a budget past
///   the admission (`UnsupportedSource`);
/// - an opening whose row vector the earlier openings already revealed is
///   rank-deficient (`MaskRank`); after distinct earlier openings it verifies.
#[test]
fn rejects_rank_deficient_lifetime_openings() {
    type K = QM31;
    let ell = ELL + 1;
    let probe = Source::<K>::hiding(43, ell, LM, B, [0; 32]).expect("source");
    assert_eq!(probe.rows() / 2, (3 + 1) * 4);
    assert!(probe.admits_lifetime(3));
    assert!(!probe.admits_lifetime(4), "R < (P + 1)·D");
    assert!(!probe.admits_lifetime(0));
    let message = vec![M31::ZERO; probe.rows() * probe.columns()];
    let prepare = |budget, revealed: Vec<Vec<K>>| {
        PreparedSource::<K>::hiding_lifetime(
            43,
            ell,
            LM,
            B,
            &message,
            &[11; 32],
            &mut HashUsage::default(),
            budget,
            revealed,
        )
        .err()
    };
    assert_eq!(prepare(3, vec![vec![]; 3]), Some(Error::MaskBudget));
    assert_eq!(prepare(4, Vec::new()), Some(Error::UnsupportedSource));
    // Two earlier openings with distinct row vectors: the third verifies.
    let (first, a1) = lifetime_opening(Vec::new(), 1);
    assert_eq!(first, Ok(()));
    let (second, a2) = lifetime_opening(vec![a1.clone()], 2);
    assert_eq!(second, Ok(()));
    let (third, _) = lifetime_opening(vec![a1.clone(), a2], 3);
    assert_eq!(third, Ok(()));
    // Reopening at an already revealed row vector: rank-deficient.
    let (again, _) = lifetime_opening(vec![a1], 1);
    assert_eq!(again, Err(Error::MaskRank));
}
