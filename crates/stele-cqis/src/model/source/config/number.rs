//! RFC-0025 source architecture §2: exact signed JSON numbers, never host floats.
use super::{Budget, Error};
use crate::tables::natural::Natural;
use core::cmp::Ordering;

/// Reduced magnitudes are inline, so the tree's vector budget includes them.
pub(super) struct Number {
    negative: bool,
    integer: bool,
    numerator: [u32; 8],
    denominator: [u32; 8],
}
impl Number {
    pub fn parse(raw: &[u8], budget: &mut Budget) -> Result<Self, Error> {
        let negative = raw.first() == Some(&b'-');
        let start = usize::from(negative);
        let mut at = start;
        while raw.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start || (at - start > 1 && raw[start] == b'0') {
            return Err(Error::SourceJson);
        }
        let end = at;
        let mut fractional = 0;
        let decimal = raw.get(at) == Some(&b'.');
        if decimal {
            at += 1;
            let first = at;
            while raw.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            fractional = at - first;
            if fractional == 0 {
                return Err(Error::SourceJson);
            }
        }
        let coefficient_end = at;
        let exponent = matches!(raw.get(at), Some(b'e' | b'E'));
        let mut power = 0i16;
        if exponent {
            at += 1;
            let minus = raw.get(at) == Some(&b'-');
            if matches!(raw.get(at), Some(b'+' | b'-')) {
                at += 1;
            }
            let first = at;
            while raw.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            if at == first {
                return Err(Error::SourceJson);
            }
            // Syntax is checked before numeric domains, including leading zeroes.
            if at != raw.len() {
                return Err(Error::SourceJson);
            }
            if raw.len() > 64 {
                return Err(Error::SourceNumber);
            }
            for d in &raw[first..at] {
                power = power
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(i16::from(d - b'0')))
                    .filter(|v| *v <= 64)
                    .ok_or(Error::SourceNumber)?;
            }
            if minus {
                power = -power;
            }
        }
        if at != raw.len() {
            return Err(Error::SourceJson);
        }
        let integer = !decimal && !exponent;
        let mut a = Arithmetic(budget);
        let (mut numerator, mut denominator) = if integer {
            let mut value = 0u64;
            for d in &raw[start..end] {
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(d - b'0')))
                    .ok_or(Error::SourceNumber)?;
            }
            (a.small(value)?, a.small(1)?)
        } else {
            if raw.len() > 64 {
                return Err(Error::SourceNumber);
            }
            let mut n = Natural::zero();
            for d in raw[start..coefficient_end].iter().filter(|d| **d != b'.') {
                n = a.times_ten(&n)?;
                let digit = a.small(u64::from(d - b'0'))?;
                a.0.spend(4 * (n.bits().div_ceil(32).max(digit.bits().div_ceil(32)) + 1))?;
                n = n.add(&digit).map_err(|_| Error::Capacity)?;
            }
            // <=64 token characters and |explicit exponent|<=64 give |scale|<=128.
            // Coefficients and powers, including unreduced values, fit <512 bits.
            let scale = power - i16::try_from(fractional).map_err(|_| Error::SourceNumber)?;
            let mut d = a.small(1)?;
            for _ in 0..scale.unsigned_abs() {
                if scale < 0 {
                    d = a.times_ten(&d)?;
                } else {
                    n = a.times_ten(&n)?;
                }
            }
            (n, d)
        };
        a.0.spend(4 * numerator.bits().div_ceil(32) + 4 * denominator.bits().div_ceil(32))?;
        let mut left = numerator.try_clone().map_err(|_| Error::Capacity)?;
        let mut right = denominator.try_clone().map_err(|_| Error::Capacity)?;
        while !right.is_zero() {
            let (_, remainder) = a.divide(&left, &right)?;
            left = right;
            right = remainder;
        }
        numerator = a.divide(&numerator, &left)?.0;
        denominator = a.divide(&denominator, &left)?.0;
        if numerator.bits() > 256 || denominator.bits() > 256 {
            return Err(Error::SourceNumber);
        }
        Ok(Self {
            negative: negative && !numerator.is_zero(),
            integer,
            numerator: a.words(numerator)?,
            denominator: a.words(denominator)?,
        })
    }
    pub fn unsigned(&self) -> Option<u64> {
        if !self.integer || self.negative {
            None
        } else {
            small(&self.numerator)
        }
    }
    pub fn ratio(&self, maximum: u64) -> Result<(u64, u64), Error> {
        let n = small(&self.numerator).filter(|n| !self.negative && *n > 0 && *n <= maximum);
        let d = small(&self.denominator).filter(|d| *d > 0 && *d <= maximum);
        Ok((
            n.ok_or(Error::SourceRational)?,
            d.ok_or(Error::SourceRational)?,
        ))
    }
    pub fn nonnegative(&self) -> bool {
        !self.negative
    }
    pub fn unit_interval(&self) -> bool {
        !self.negative
            && self
                .numerator
                .iter()
                .rev()
                .cmp(self.denominator.iter().rev())
                != Ordering::Greater
    }
}
fn small(words: &[u32; 8]) -> Option<u64> {
    words[2..]
        .iter()
        .all(|w| *w == 0)
        .then(|| u64::from(words[0]) | (u64::from(words[1]) << 32))
}

/// Charge conservative requested Natural limb storage before each operation,
/// including discarded results and temporaries; no refunds or unbudgeted limbs.
/// Natural's global generator cap is unchanged. All local operands fit <512 bits.
struct Arithmetic<'a>(&'a mut Budget);
impl Arithmetic<'_> {
    fn small(&mut self, value: u64) -> Result<Natural, Error> {
        self.0.spend(8)?;
        Natural::from_u64(value).map_err(|_| Error::Capacity)
    }
    fn times_ten(&mut self, value: &Natural) -> Result<Natural, Error> {
        self.0.spend(8 + 4 * (value.bits().div_ceil(32) + 1))?;
        value.mul_u64(10).map_err(|_| Error::Capacity)
    }
    fn divide(&mut self, left: &Natural, right: &Natural) -> Result<(Natural, Natural), Error> {
        // div_rem allocates at most a shifted divisor, remainder and quotient,
        // each with <=ceil(left.bits/32) limbs (or only a remainder when left<right).
        self.0.spend(12 * left.bits().div_ceil(32))?;
        left.div_rem(right).map_err(|_| Error::Capacity)
    }
    fn words(&mut self, mut value: Natural) -> Result<[u32; 8], Error> {
        let base = self.small(1 << 32)?;
        let mut words = [0; 8];
        for word in &mut words {
            if value.is_zero() {
                break;
            }
            let (next, digit) = self.divide(&value, &base)?;
            *word = digit.to_u32().map_err(|_| Error::SourceNumber)?;
            value = next;
        }
        if !value.is_zero() {
            return Err(Error::SourceNumber);
        }
        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_reference_exact_config_numbers() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/source-architecture.json"
        ))
        .expect("fixtures");
        for case in fixture["numbers"].as_array().expect("numbers") {
            let raw = case["raw"].as_str().expect("raw");
            let result = Number::parse(raw.as_bytes(), &mut Budget::new(1 << 20));
            if case["error"].is_string() {
                assert_eq!(result.err(), Some(Error::SourceNumber), "{raw}");
                continue;
            }
            let number = result.expect(raw);
            assert_eq!(number.integer, case["integer"].as_bool().expect("integer"));
            assert_eq!(
                number.negative,
                case["negative"].as_bool().expect("negative")
            );
            for (name, words) in [
                ("numerator", number.numerator),
                ("denominator", number.denominator),
            ] {
                for (word, expected) in words.iter().zip(case[name].as_array().expect("words")) {
                    assert_eq!(
                        u64::from(*word),
                        expected.as_u64().expect("limb"),
                        "{raw} {name}"
                    );
                }
            }
            assert_eq!(
                Number::parse(raw.as_bytes(), &mut Budget::new(0)).err(),
                Some(Error::Capacity)
            );
        }
    }
}
