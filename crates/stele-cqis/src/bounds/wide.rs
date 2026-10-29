//! RFC-0022 §3: checked exact u160 scratch, never field arithmetic.
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct U160([u64; 3]);

impl From<u64> for U160 {
    fn from(value: u64) -> Self {
        Self([value, 0, 0])
    }
}

impl U160 {
    fn finish(words: [u64; 3]) -> Result<Self, Error> {
        if words[2] >> 32 != 0 {
            return Err(Error::Arithmetic);
        }
        Ok(Self(words))
    }
    pub(super) fn add(self, rhs: Self) -> Result<Self, Error> {
        let mut out = [0; 3];
        let mut carry = 0u128;
        for (i, word) in out.iter_mut().enumerate() {
            let sum = u128::from(self.0[i]) + u128::from(rhs.0[i]) + carry;
            *word = sum as u64;
            carry = sum >> 64;
        }
        if carry != 0 {
            return Err(Error::Arithmetic);
        }
        Self::finish(out)
    }
    pub(super) fn mul(self, rhs: Self) -> Result<Self, Error> {
        let mut out = [0u64; 6];
        for i in 0..3 {
            let mut carry = 0u128;
            for j in 0..3 {
                // RFC-0022 §3: (2^64-1)^2 + two u64 values <= u128::MAX.
                let value =
                    u128::from(self.0[i]) * u128::from(rhs.0[j]) + u128::from(out[i + j]) + carry;
                out[i + j] = value as u64;
                carry = value >> 64;
            }
            // Earlier rows end at i+2; this next carry slot is still zero.
            out[i + 3] = carry as u64;
        }
        if out[3..].iter().any(|v| *v != 0) {
            return Err(Error::Arithmetic);
        }
        Self::finish([out[0], out[1], out[2]])
    }
    fn bits(self) -> u32 {
        (0..3)
            .rev()
            .find(|i| self.0[*i] != 0)
            .map_or(0, |i| 64 * i as u32 + 64 - self.0[i].leading_zeros())
    }
    pub(super) fn shl(self, bits: u32) -> Result<Self, Error> {
        if bits >= 160 || self.bits() + bits > 160 {
            return Err(Error::Arithmetic);
        }
        let whole = (bits / 64) as usize;
        let part = bits % 64;
        let mut out = [0; 3];
        for (i, word) in out.iter_mut().enumerate().skip(whole) {
            *word = self.0[i - whole] << part;
            if part != 0 && i > whole {
                *word |= self.0[i - whole - 1] >> (64 - part);
            }
        }
        Self::finish(out)
    }
    pub(super) fn max(self, rhs: Self) -> Self {
        for i in (0..3).rev() {
            if self.0[i] != rhs.0[i] {
                return if self.0[i] > rhs.0[i] { self } else { rhs };
            }
        }
        self
    }
    pub(super) fn width(self) -> usize {
        self.bits().div_ceil(8).max(1) as usize
    }
    pub(super) fn cap(self, index: usize) -> u8 {
        if index >= self.width() {
            0
        } else if index + 1 < self.width() {
            255
        } else {
            (self.0[index / 8] >> (8 * (index % 8))) as u8
        }
    }
    pub(super) fn bytes(self) -> [u8; 20] {
        let mut out = [0; 20];
        out[..8].copy_from_slice(&self.0[0].to_le_bytes());
        out[8..16].copy_from_slice(&self.0[1].to_le_bytes());
        out[16..].copy_from_slice(&(self.0[2] as u32).to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_reference_ten_thousand_full_width_products() {
        let mut seed = 2613u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..10000 {
            let (x, y, u, v) = (next(), next(), next() & 65535, next() & 65535);
            // Independent 80-bit factor expansion in u128, including middle carry.
            let low = u128::from(x) * u128::from(y);
            let cross = u128::from(x) * u128::from(v) + u128::from(y) * u128::from(u);
            let middle = (low >> 64) + u128::from(cross as u64);
            let high = (cross >> 64) + u128::from(u) * u128::from(v) + (middle >> 64);
            let expected = U160([low as u64, middle as u64, high as u64]);
            assert_eq!(U160([x, u, 0]).mul(U160([y, v, 0])), Ok(expected));
        }
    }
    #[test]
    fn accepts_every_bit_and_rejects_discarded_high_words() {
        let one = U160::from(1);
        let top = U160([u64::MAX, u64::MAX, u64::from(u32::MAX)]);
        assert_eq!(top.add(one), Err(Error::Arithmetic));
        assert_eq!(top.mul(2.into()), Err(Error::Arithmetic));
        assert_eq!(top.mul(0.into()), Ok(0.into()));
        assert_eq!(top.mul(one), Ok(top));
        assert_eq!(one.shl(160), Err(Error::Arithmetic));
        assert_eq!(one.shl(u32::MAX), Err(Error::Arithmetic));
        for a in 0..160 {
            let x = one.shl(a).expect("bit");
            let mut raw = [0u8; 20];
            raw[a as usize / 8] = 1 << (a % 8);
            assert_eq!(x.bytes(), raw);
            for b in 0..160 {
                let y = one.shl(b).expect("bit");
                let expected = if a + b < 160 {
                    one.shl(a + b)
                } else {
                    Err(Error::Arithmetic)
                };
                assert_eq!(x.mul(y), expected);
                assert_eq!(x.shl(b), expected);
            }
        }
        // Cross-word carry, full 128-bit product and all-word multiplication.
        let a = U160::from(u64::MAX);
        assert_eq!(a.add(one), Ok(U160([0, 1, 0])));
        assert_eq!(a.mul(a), Ok(U160([1, u64::MAX - 1, 0])));
        assert_eq!(
            U160([u64::MAX, u64::MAX, 0]).mul(2.into()),
            Ok(U160([u64::MAX - 1, u64::MAX, 1]))
        );
        assert_eq!(U160::from(257).cap(0), 255);
        assert_eq!(U160::from(257).cap(1), 1);
        assert_eq!(U160::from(257).cap(2), 0);
    }
}
