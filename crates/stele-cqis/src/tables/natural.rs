//! RFC-0021 §3: bounded exact generator arithmetic; no proof arithmetic.
use super::Error;
use alloc::vec::Vec;
use core::cmp::Ordering;

// The fixed schedule bounds scratch independently of any supplied byte length.
// Exp and sigmoid/SiLU/softcap arguments have <= 48-bit denominators after
// halving; Taylor denominators need <= 512*(48+9) bits plus <= 269 scaling
// bits. The cap is a resource limit, not a field bound. Further generators
// must establish their own scratch bounds.
// Tanh-GeLU's exponent denominators after halving are < 2^384, so its Taylor
// scratch uses <= 512*(384+9)+269 bits. Machin arctangent denominators use
// <= 8+512*(16+11) bits each; cross-products and root scaling stay below the cap.
// Exact GeLU integral denominators use <=31+512*(60+10+11) bits. For a<8,
// the sum of <=513 term magnitudes is <2^3086, bounding signed numerators.
// Width comparisons, normalizer products and scaling stay below 100,000 bits.
const MAX_BITS: usize = 1 << 18;
const MAX_WORDS: usize = MAX_BITS / 32;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Natural {
    words: Vec<u32>,
}

fn storage(length: usize) -> Result<Vec<u32>, Error> {
    if length > MAX_WORDS + 1 {
        return Err(Error::Capacity);
    }
    let mut words = Vec::new();
    words
        .try_reserve_exact(length)
        .map_err(|_| Error::Capacity)?;
    words.resize(length, 0);
    Ok(words)
}

impl Natural {
    fn finish(mut words: Vec<u32>) -> Result<Self, Error> {
        while words.last() == Some(&0) {
            words.pop();
        }
        if words.len() > MAX_WORDS {
            return Err(Error::Capacity);
        }
        Ok(Self { words })
    }
    pub(super) fn zero() -> Self {
        Self { words: Vec::new() }
    }
    pub(super) fn from_u64(value: u64) -> Result<Self, Error> {
        let mut words = storage(2)?;
        words[0] = value as u32;
        words[1] = (value >> 32) as u32;
        Self::finish(words)
    }
    pub(super) fn to_u32(&self) -> Result<u32, Error> {
        match self.words.as_slice() {
            [] => Ok(0),
            [value] => Ok(*value),
            _ => Err(Error::Interval),
        }
    }
    pub(super) fn try_clone(&self) -> Result<Self, Error> {
        let mut words = storage(self.words.len())?;
        words.copy_from_slice(&self.words);
        Ok(Self { words })
    }
    pub(super) fn bits(&self) -> usize {
        // finish bounds len <= 8192; every nonempty representation ends nonzero.
        self.words.last().map_or(0, |top| {
            32 * (self.words.len() - 1) + (32 - top.leading_zeros()) as usize
        })
    }
    pub(super) fn is_zero(&self) -> bool {
        self.words.is_empty()
    }
    pub(super) fn cmp(&self, other: &Self) -> Ordering {
        self.words
            .len()
            .cmp(&other.words.len())
            .then_with(|| self.words.iter().rev().cmp(other.words.iter().rev()))
    }
    pub(super) fn add(&self, other: &Self) -> Result<Self, Error> {
        let count = self.words.len().max(other.words.len());
        let mut words = storage(count.checked_add(1).ok_or(Error::Capacity)?)?;
        let mut carry = 0u64;
        for (i, word) in words.iter_mut().take(count).enumerate() {
            let sum = u64::from(*self.words.get(i).unwrap_or(&0))
                + u64::from(*other.words.get(i).unwrap_or(&0))
                + carry;
            *word = sum as u32;
            carry = sum >> 32;
        }
        words[count] = carry as u32;
        Self::finish(words)
    }
    fn subtract_assign(&mut self, other: &Self) -> Result<(), Error> {
        if self.cmp(other) == Ordering::Less {
            return Err(Error::Interval);
        }
        let mut borrow = 0u64;
        for (i, word) in self.words.iter_mut().enumerate() {
            let right = u64::from(*other.words.get(i).unwrap_or(&0)) + borrow;
            let left = u64::from(*word);
            borrow = u64::from(left < right);
            *word = ((borrow << 32) + left - right) as u32;
        }
        if borrow != 0 {
            return Err(Error::Interval);
        }
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
        Ok(())
    }
    pub(super) fn sub(&self, other: &Self) -> Result<Self, Error> {
        if self.cmp(other) == Ordering::Less {
            return Err(Error::Interval);
        }
        let mut result = self.try_clone()?;
        result.subtract_assign(other)?;
        Ok(result)
    }
    pub(super) fn mul_u64(&self, other: u64) -> Result<Self, Error> {
        self.mul(&Self::from_u64(other)?)
    }
    pub(super) fn mul(&self, other: &Self) -> Result<Self, Error> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }
        let minimum_bits = self
            .bits()
            .checked_add(other.bits())
            .and_then(|b| b.checked_sub(1))
            .ok_or(Error::Capacity)?;
        if minimum_bits > MAX_BITS {
            return Err(Error::Capacity);
        }
        let count = self
            .words
            .len()
            .checked_add(other.words.len())
            .ok_or(Error::Capacity)?;
        let mut words = storage(count)?;
        for (i, left) in self.words.iter().enumerate() {
            let mut carry = 0u64;
            for (j, right) in other.words.iter().enumerate() {
                // i+j < checked count. Product + stored limb + carry <= 2^64-1.
                let sum = u64::from(*left) * u64::from(*right) + u64::from(words[i + j]) + carry;
                words[i + j] = sum as u32;
                carry = sum >> 32;
            }
            // Earlier rows end before this fresh slot; assignment loses no carry.
            words[i + other.words.len()] = carry as u32;
        }
        Self::finish(words)
    }
    pub(super) fn shl(&self, shift: usize) -> Result<Self, Error> {
        if self.is_zero() {
            return Ok(Self::zero());
        }
        let bits = self
            .bits()
            .checked_add(shift)
            .filter(|b| *b <= MAX_BITS)
            .ok_or(Error::Capacity)?;
        let mut words = storage(bits.div_ceil(32))?;
        let (offset, remainder) = (shift / 32, shift % 32);
        let mut carry = 0u64;
        for (i, value) in self.words.iter().enumerate() {
            let shifted = (u64::from(*value) << remainder) | carry;
            // The checked bit count bounds offset+i and any nonzero final carry.
            words[offset + i] = shifted as u32;
            carry = shifted >> 32;
        }
        if carry != 0 {
            *words
                .get_mut(offset + self.words.len())
                .ok_or(Error::Capacity)? = carry as u32;
        }
        Self::finish(words)
    }
    pub(super) fn shr(&self, shift: usize) -> Result<Self, Error> {
        if shift >= self.bits() {
            return Ok(Self::zero());
        }
        let (offset, remainder) = (shift / 32, shift % 32);
        let count = self
            .words
            .len()
            .checked_sub(offset)
            .ok_or(Error::Interval)?;
        let mut words = storage(count)?;
        for (i, word) in words.iter_mut().enumerate() {
            let source = offset + i;
            *word = self.words[source] >> remainder;
            if remainder != 0 {
                *word |= self.words.get(source + 1).copied().unwrap_or(0) << (32 - remainder);
            }
        }
        Self::finish(words)
    }
    fn shift_right_one(&mut self) {
        let mut carry = 0;
        for word in self.words.iter_mut().rev() {
            let next = *word & 1;
            *word = (*word >> 1) | (carry << 31);
            carry = next;
        }
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
    }
    pub(super) fn div_rem(&self, other: &Self) -> Result<(Self, Self), Error> {
        if other.is_zero() {
            return Err(Error::Interval);
        }
        if self.cmp(other) == Ordering::Less {
            return Ok((Self::zero(), self.try_clone()?));
        }
        let shift = self
            .bits()
            .checked_sub(other.bits())
            .ok_or(Error::Interval)?;
        let mut divisor = other.shl(shift)?;
        let mut remainder = self.try_clone()?;
        let mut quotient = storage((shift / 32).checked_add(1).ok_or(Error::Capacity)?)?;
        // Binary division changes only owned scratch; every shift is <= MAX_BITS.
        for bit in (0..=shift).rev() {
            if remainder.cmp(&divisor) != Ordering::Less {
                remainder.subtract_assign(&divisor)?;
                quotient[bit / 32] |= 1u32 << (bit % 32);
            }
            divisor.shift_right_one();
        }
        Ok((Self::finish(quotient)?, remainder))
    }
}

#[cfg(test)]
#[path = "natural_tests.rs"]
mod tests;
