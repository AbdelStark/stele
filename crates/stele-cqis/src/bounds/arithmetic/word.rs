//! RFC-0025 static appendix §§4–5: checked u2304 scratch, never a field value.
use super::Error;
use core::cmp::Ordering;

const LIMBS: usize = 36;
pub(super) const BYTES: usize = 288;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Word([u64; LIMBS]);

impl From<u64> for Word {
    fn from(value: u64) -> Self {
        let mut words = [0; LIMBS];
        words[0] = value;
        Self(words)
    }
}

impl Word {
    pub(super) fn to_u32(self) -> Result<u32, Error> {
        if self.0[1..].iter().any(|v| *v != 0) {
            return Err(Error::Arithmetic);
        }
        u32::try_from(self.0[0]).map_err(|_| Error::Arithmetic)
    }
    fn bits(self) -> usize {
        self.0
            .iter()
            .rposition(|v| *v != 0)
            .map_or(0, |i| 64 * i + 64 - self.0[i].leading_zeros() as usize)
    }
    fn cmp(self, rhs: Self) -> Ordering {
        self.0.iter().rev().cmp(rhs.0.iter().rev())
    }
    pub(super) fn add(self, rhs: Self) -> Result<Self, Error> {
        let mut out = [0; LIMBS];
        let mut carry = 0u128;
        for (i, word) in out.iter_mut().enumerate() {
            let sum = u128::from(self.0[i]) + u128::from(rhs.0[i]) + carry;
            *word = sum as u64;
            carry = sum >> 64;
        }
        if carry != 0 {
            return Err(Error::Arithmetic);
        }
        Ok(Self(out))
    }
    pub(super) fn sub(self, rhs: Self) -> Result<Self, Error> {
        let mut out = [0; LIMBS];
        let mut borrow = false;
        for (i, word) in out.iter_mut().enumerate() {
            let (difference, first) = self.0[i].overflowing_sub(rhs.0[i]);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            *word = difference;
            borrow = first || second;
        }
        if borrow {
            return Err(Error::Arithmetic);
        }
        Ok(Self(out))
    }
    pub(super) fn mul(self, rhs: Self) -> Result<Self, Error> {
        let mut out = [0u64; 2 * LIMBS];
        let (left, right) = (self.bits().div_ceil(64), rhs.bits().div_ceil(64));
        for i in 0..left {
            let mut carry = 0u128;
            for j in 0..right {
                // (2^64-1)^2 + stored limb + carry <= u128::MAX.
                let sum =
                    u128::from(self.0[i]) * u128::from(rhs.0[j]) + u128::from(out[i + j]) + carry;
                out[i + j] = sum as u64;
                carry = sum >> 64;
            }
            // Earlier rows stop before this fresh carry slot.
            out[i + right] = carry as u64;
        }
        if out[LIMBS..].iter().any(|v| *v != 0) {
            return Err(Error::Arithmetic);
        }
        let mut words = [0; LIMBS];
        words.copy_from_slice(&out[..LIMBS]);
        Ok(Self(words))
    }
    pub(super) fn shl(self, shift: usize) -> Result<Self, Error> {
        if self.bits() == 0 {
            return Ok(self);
        }
        if self
            .bits()
            .checked_add(shift)
            .filter(|b| *b <= 8 * BYTES)
            .is_none()
        {
            return Err(Error::Arithmetic);
        }
        let (whole, part) = (shift / 64, shift % 64);
        let mut out = [0; LIMBS];
        for (i, word) in out.iter_mut().enumerate().skip(whole) {
            *word = self.0[i - whole] << part;
            if part != 0 && i > whole {
                *word |= self.0[i - whole - 1] >> (64 - part);
            }
        }
        Ok(Self(out))
    }
    pub(super) fn power(shift: i16) -> Result<Self, Error> {
        Self::from(1).shl(usize::try_from(shift).map_err(|_| Error::Arithmetic)?)
    }
    /// Exact min(cap, floor(self/divisor)); no discarded high words.
    pub(super) fn quotient_cap(self, divisor: Self, cap: u32) -> Result<Self, Error> {
        if divisor == Self::from(0) {
            return Err(Error::Arithmetic);
        }
        let (mut low, mut high) = (0u64, u64::from(cap) + 1);
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            match divisor.mul(middle.into()) {
                Ok(product) if product.cmp(self) != Ordering::Greater => low = middle,
                // An overflowing positive product is strictly greater than self.
                Ok(_) | Err(Error::Arithmetic) => high = middle,
                Err(e) => return Err(e),
            }
        }
        Ok(low.into())
    }
    pub(super) fn width(self, radix_bits: u8) -> usize {
        self.bits().div_ceil(usize::from(radix_bits)).max(1)
    }
    pub(super) fn cap(self, index: usize, radix_bits: u8) -> u8 {
        let width = self.width(radix_bits);
        if index >= width {
            0
        } else if index + 1 < width {
            ((1u16 << radix_bits) - 1) as u8
        } else {
            let bit = index * usize::from(radix_bits);
            (self.0[bit / 64] >> (bit % 64)) as u8
        }
    }
    pub(super) fn bytes(self) -> [u8; BYTES] {
        let mut out = [0; BYTES];
        for (word, bytes) in self.0.iter().zip(out.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::natural::Natural;

    fn natural(w: Word) -> Natural {
        w.0.iter().rev().fold(Natural::zero(), |value, limb| {
            value
                .shl(64)
                .expect("shift")
                .add(&Natural::from_u64(*limb).expect("limb"))
                .expect("sum")
        })
    }
    fn bounded(n: Natural) -> Result<Word, Error> {
        if n.bits() > 8 * BYTES {
            return Err(Error::Arithmetic);
        }
        let mut words = [0u64; LIMBS];
        for (i, word) in words.iter_mut().enumerate() {
            let low = n.shr(64 * i).expect("low");
            let high = n.shr(64 * i + 32).expect("high");
            let low = low
                .sub(&low.shr(32).expect("upper").shl(32).expect("upper"))
                .expect("low");
            let high = high
                .sub(&high.shr(32).expect("upper").shl(32).expect("upper"))
                .expect("high");
            *word = u64::from(low.to_u32().expect("limb"))
                | (u64::from(high.to_u32().expect("limb")) << 32);
        }
        Ok(Word(words))
    }
    #[test]
    fn matches_reference_full_width_arithmetic_and_capped_division() {
        let mut state = 50338u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..256 {
            let mut words = || {
                let width = (next() as usize % LIMBS) + 1;
                let mut out = [0; LIMBS];
                for word in &mut out[..width] {
                    *word = next();
                }
                Word(out)
            };
            let (a, b) = (words(), words());
            let (x, y) = (natural(a), natural(b));
            assert_eq!(a.add(b), bounded(x.add(&y).expect("reference sum")));
            assert_eq!(a.mul(b), bounded(x.mul(&y).expect("reference product")));
            let difference = x.sub(&y).map_err(|_| Error::Arithmetic).and_then(bounded);
            assert_eq!(a.sub(b), difference);
            let shift = next() as usize % (8 * BYTES + 1);
            assert_eq!(
                a.shl(shift),
                bounded(x.shl(shift).expect("reference shift"))
            );
            let cap = next() as u32;
            let quotient = x.div_rem(&y).expect("reference division").0;
            let limit = Natural::from_u64(u64::from(cap)).expect("cap");
            let expected = if quotient.cmp(&limit) == Ordering::Greater {
                limit
            } else {
                quotient
            };
            assert_eq!(a.quotient_cap(b, cap), bounded(expected));
        }
    }
    #[test]
    fn accepts_every_bit_and_rejects_high_word_loss() {
        let one = Word::from(1);
        let maximum = Word([u64::MAX; LIMBS]);
        assert_eq!(maximum.add(one), Err(Error::Arithmetic));
        assert_eq!(maximum.mul(2.into()), Err(Error::Arithmetic));
        assert_eq!(one.sub(2.into()), Err(Error::Arithmetic));
        assert_eq!(one.shl(usize::MAX), Err(Error::Arithmetic));
        assert_eq!(Word::power(-1), Err(Error::Arithmetic));
        assert_eq!(one.quotient_cap(0.into(), 1), Err(Error::Arithmetic));
        assert_eq!(maximum.mul(0.into()), Ok(0.into()));
        assert_eq!(maximum.quotient_cap(maximum, u32::MAX), Ok(one));
        assert_eq!(Word::from(0).to_u32(), Ok(0));
        assert_eq!(Word::from(u64::from(u32::MAX)).to_u32(), Ok(u32::MAX));
        for bit in [32, 63, 64, 2303] {
            assert_eq!(
                Word::power(bit).expect("wide").to_u32(),
                Err(Error::Arithmetic)
            );
        }
        for bit in 0..8 * BYTES {
            let value = one.shl(bit).expect("bit");
            let mut bytes = [0; BYTES];
            bytes[bit / 8] = 1 << (bit % 8);
            assert_eq!(value.bytes(), bytes);
            assert_eq!(value.mul(one), Ok(value));
            assert_eq!(value.add(value), one.shl(bit + 1));
            for radix in [4, 8] {
                let width = bit / usize::from(radix) + 1;
                assert_eq!(value.width(radix), width);
                assert_eq!(value.cap(width - 1, radix), 1 << (bit % usize::from(radix)));
                assert_eq!(value.cap(width, radix), 0);
                if width > 1 {
                    assert_eq!(value.cap(width - 2, radix), ((1u16 << radix) - 1) as u8);
                }
            }
        }
    }
}
