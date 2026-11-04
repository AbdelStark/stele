//! RFC-0025 §2.4: native integer intervals against independent Arb reference bounds.
use super::{fixed::Signed, Generator};
use crate::{
    model::Rotation,
    tables::{natural::Natural, Error},
};
use alloc::vec::Vec;
use core::cmp::Ordering;

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take(2).try_into().expect("u16"))
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("u32"))
    }
    fn signed(&mut self) -> Signed {
        let mut raw: [u8; 17] = self.take(17).try_into().expect("Q128 signed endpoint");
        let negative = raw[16] & 128 != 0;
        if negative {
            let mut carry = true;
            for b in &mut raw {
                let (sum, overflow) = (!*b).overflowing_add(u8::from(carry));
                *b = sum;
                carry = overflow;
            }
        }
        let mut n = Natural::zero();
        for b in raw.iter().rev() {
            n = n
                .shl(8)
                .expect("shift")
                .add(&Natural::from_u64(u64::from(*b)).expect("byte"))
                .expect("sum");
        }
        Signed::new(negative, n)
    }
}

#[test]
fn matches_reference_ten_thousand_rotary_pairs_and_true_value_enclosures() {
    let mut r = Reader(include_bytes!(
        "../../../tests/fixtures/rotary-coefficients.bin"
    ));
    let count = r.u16();
    let mut generators: Vec<_> = (0..count)
        .map(|_| {
            let n = usize::from(r.u16());
            Generator::new(Rotation::decode(r.take(n)).expect("descriptor"))
        })
        .collect();
    assert_eq!(r.u32(), 10002);
    for case in 0..10002 {
        let index = usize::from(r.u16());
        let position = r.u32();
        let pair = r.u16();
        let expected = (r.u16() as i16, r.u16() as i16);
        let g = &mut generators[index];
        assert_eq!(g.coefficient(position, pair), Ok(expected), "case {case}");
        let (c, s) = g.enclosure(position, pair, 128).expect("Q128 enclosure");
        let reference = [(r.signed(), r.signed()), (r.signed(), r.signed())];
        for (bounds, (lo, hi)) in [&c, &s].into_iter().zip(&reference) {
            assert_ne!(bounds.lo.cmp(lo), Ordering::Greater, "lower case {case}");
            assert_ne!(bounds.hi.cmp(hi), Ordering::Less, "upper case {case}");
        }
        if case % 997 == 0 || case == 10000 {
            for bits in [256, 512] {
                let (c, s) = g
                    .enclosure(position, pair, bits)
                    .expect("refined enclosure");
                for (bounds, (lo, hi)) in [&c, &s].into_iter().zip(&reference) {
                    assert_ne!(
                        bounds
                            .lo
                            .down(bits - 128, false)
                            .expect("lower grid")
                            .cmp(lo),
                        Ordering::Greater
                    );
                    assert_ne!(
                        bounds
                            .hi
                            .down(bits - 128, true)
                            .expect("upper grid")
                            .cmp(hi),
                        Ordering::Less
                    );
                }
            }
        }
        if case == 10000 {
            assert!(
                c.lo.rounded(128).expect("low") != c.hi.rounded(128).expect("high")
                    || s.lo.rounded(128).expect("low") != s.hi.rounded(128).expect("high")
            );
        }
        if case == 10001 {
            assert_eq!(expected, (9214, 13548));
        }
    }
    assert!(r.0.is_empty());
    let g = &mut generators[0];
    assert_eq!(g.coefficient(1 << 20, 0), Err(Error::Parameters));
    assert_eq!(g.coefficient(0, 8192), Err(Error::Parameters));
    assert!(matches!(g.enclosure(0, 0, 1024), Err(Error::Precision)));
}

#[test]
fn matches_reference_complete_rotary_data_and_layout_identity() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/rotary-data.json"))
            .expect("fixture");
    let mut digests = Vec::new();
    for case in fixture["cases"].as_array().expect("cases") {
        let hex = case["descriptor"].as_str().expect("descriptor");
        let raw: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let p = Rotation::decode(&raw).expect("Rotation");
        assert_eq!(
            u64::from(p.width() / 2) * u64::from(p.length()),
            case["pairs"].as_u64().expect("pairs")
        );
        let digest = p.data_digest().expect("complete regenerated data");
        let expected = case["digest"].as_str().expect("digest");
        assert_eq!(blake3::Hash::from(digest).to_hex().as_str(), expected);
        assert_eq!(p.coefficient(0, p.width() / 2 - 1), Ok((16384, 0)));
        digests.push(digest);
    }
    for pair in digests[..6].chunks_exact(2) {
        assert_ne!(pair[0], pair[1]);
    }
}

#[test]
fn matches_reference_signed_q14_half_away_boundaries() {
    for bits in [128, 256, 512] {
        let one = Natural::from_u64(1).expect("one");
        let half = one.shl(bits - 15).expect("half");
        for (n, expected) in [
            (half.sub(&one).expect("below"), 0),
            (half.try_clone().expect("tie"), 1),
            (half.add(&one).expect("above"), 1),
        ] {
            assert_eq!(
                Signed::new(false, n.try_clone().expect("copy")).rounded(bits),
                Ok(expected)
            );
            assert_eq!(Signed::new(true, n).rounded(bits), Ok(-expected));
        }
    }
}
