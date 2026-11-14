//! E8-02e: the LogUp `(β, α)` round. The grinding bits match the 180 rows that
//! `research/fs-pcs/check_lu_grind.py` writes (`lu-grind-bits.txt`, also read by
//! `stele-reductions`). The nonce is absorbed into the state that `β` and `α` are
//! drawn from, and a failing, missing or extra nonce is refused.
use stele_field::QM31;
use stele_hash::{AbsorbLabel, Transcript};
use stele_verifier::logup::{bits, round, Error};

const BITS: &str = include_str!("../../stele-reductions/tests/fixtures/lu-grind-bits.txt");

#[test]
fn matches_reference_lu_grind_bits() {
    let mut count = 0;
    for line in BITS.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let n = |i: usize| f[i].parse::<u64>().expect("number");
        let expected = match f[4] {
            "none" => None,
            k => Some(k.parse::<u8>().expect("bits")),
        };
        assert_eq!(bits(n(0), n(1), n(2), n(3) as u8), expected, "{line}");
        count += 1;
    }
    assert_eq!(count, 180);
    // The text's spot check: range_8 over 2^27 positions grinds 12 bits.
    assert_eq!(bits(1, 1 << 27, 256, 4), Some(12));
}

/// No panic on an empty check or a huge count, and no answer for another field.
#[test]
fn rejects_empty_checks_and_other_degrees() {
    assert_eq!(bits(0, 4, 4, 4), None);
    assert_eq!(bits(1, 0, 0, 4), None);
    assert_eq!(bits(u64::MAX, u64::MAX, u64::MAX, 4), None);
    for degree in [0, 1, 2, 3, 5, 6, 7, 9, 255] {
        assert_eq!(bits(1, 1 << 20, 256, degree), None);
    }
    // c(N + t) = 1 grinds nothing; OM31 never grinds while c(N + t) fits in u128.
    assert_eq!(bits(1, 1, 0, 4), Some(0));
    assert_eq!(bits(u64::MAX, u64::MAX, 0, 8), Some(0));
    assert_eq!(bits(u64::MAX, u64::MAX, u64::MAX, 8), None);
}

fn fresh() -> Transcript<QM31> {
    let mut t = Transcript::new(b"stele/test/lu-round").expect("transcript");
    t.absorb(AbsorbLabel::LookupRepetition, &[0; 9])
        .expect("absorb");
    t
}

#[test]
fn draws_beta_and_alpha_after_the_nonce() {
    // Two valid 2-bit nonces must give different (β, α): the nonce is absorbed first.
    let valid: Vec<u64> = (0..64)
        .filter(|n| fresh().verify_grind(2, *n).is_ok())
        .take(2)
        .collect();
    assert_eq!(valid.len(), 2);
    let a = round(&mut fresh(), 2, Some(valid[0])).expect("round");
    let b = round(&mut fresh(), 2, Some(valid[1])).expect("round");
    assert!(a.0 != b.0 && a.1 != b.1);
    // Without grinding there is no nonce, and the pair is the transcript's next two draws.
    assert!(round(&mut fresh(), 0, None).is_ok());
}

#[test]
fn rejects_failing_missing_and_extra_nonces() {
    let failing = (0..64)
        .find(|n| fresh().verify_grind(4, *n).is_err())
        .expect("a failing nonce");
    assert_eq!(
        round(&mut fresh(), 4, Some(failing)),
        Err(Error::Transcript(stele_hash::Error::GrindMismatch))
    );
    assert_eq!(round(&mut fresh(), 4, None), Err(Error::ProofShape));
    assert_eq!(round(&mut fresh(), 0, Some(0)), Err(Error::ProofShape));
}
