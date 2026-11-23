//! RFC-0025 §2.2/2.5 and flow §1: complete-row quantisation, without proof admission.
//! A grouped row (RFC-0004 A15, policy 2) converts each group of g values on its own.
//! A power-of-two row (RFC-0004 A16, policy 3) has b-bit codes and the scale `2^a`.
use crate::bounds::arithmetic::{self, Power, Record, Row};
use alloc::vec::Vec;

/// A rejected configuration or complete row; no partial output is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The complete static certificate could not be derived from these parameters.
    Bounds(arithmetic::Error),
    /// The int16/gated entry point differs from the configured source kind.
    Kind,
    /// Input length differs from the original configured complete row width.
    Shape,
    /// A gated input is outside [-2^30,2^30]; this is not a general int32 converter.
    Input,
    /// Exact rounding exceeds [-127,127]; a static policy never changes its scale.
    /// For a power-of-two row: no exponent up to the largest holds every code.
    Range,
    /// The complete owned output row could not be allocated.
    Capacity,
}

/// Checked numerical row parameters with their complete static schema-4 record.
/// The record uses declared ranges only; runtime extrema cannot change it.
/// Original Model/operation/source and consuming-reduction checks remain separate.
#[derive(Debug)]
pub struct Quantiser {
    parameters: Row,
    certificate: Record,
}
impl Quantiser {
    /// Validate all parameters and derive the complete static certificate once.
    /// Reuse this immutable quantiser only for rows of the same configured scope.
    pub fn new(parameters: Row) -> Result<Self, Error> {
        let certificate = Record::row(parameters).map_err(Error::Bounds)?;
        Ok(Self {
            parameters,
            certificate,
        })
    }
    /// Original dimension, kind, fraction, policy and full u32 configured scale.
    pub fn parameters(&self) -> Row {
        self.parameters
    }
    /// Complete canonical static record; this alone enforces no proof relation.
    pub fn certificate(&self) -> &Record {
        &self.certificate
    }
    /// Convert one complete original int16 row, retaining its configured fraction.
    pub fn convert_wide(&self, input: &[i16]) -> Result<QuantisedRow, Error> {
        if self.parameters.kind != 0 {
            return Err(Error::Kind);
        }
        self.convert(input.len(), input.iter().copied().map(i32::from))
    }
    /// Convert a complete gated-product row with no int16 or u16 narrowing.
    /// Values must satisfy the declared gated envelope. Their original product
    /// provenance is a separate operation/source obligation, not implied here.
    pub fn convert_gated(&self, input: &[i32]) -> Result<QuantisedRow, Error> {
        if self.parameters.kind != 1 {
            return Err(Error::Kind);
        }
        self.convert(input.len(), input.iter().copied())
    }
    fn convert(
        &self,
        length: usize,
        input: impl Iterator<Item = i32> + Clone,
    ) -> Result<QuantisedRow, Error> {
        if length != usize::from(self.parameters.dimension) {
            return Err(Error::Shape);
        }
        let h = if self.parameters.kind == 0 {
            32768
        } else {
            1 << 30
        };
        let high = if self.parameters.kind == 0 { h - 1 } else { h };
        let p = self.parameters;
        if let Some(limits) = p.power() {
            return self.convert_power(length, input, limits, (-h, high));
        }
        let g = usize::from(p.dimension);
        let g = if p.policy == 2 { p.scale as usize } else { g };
        let mut maximum = (p.policy == 0).then_some((0u16, 0u32));
        // One magnitude per group: the whole row for policies 0/1.
        let mut magnitudes = Vec::new();
        magnitudes
            .try_reserve_exact(length / g)
            .map_err(|_| Error::Capacity)?;
        for (index, value) in input.clone().enumerate() {
            if !(-h..=high).contains(&value) {
                return Err(Error::Input);
            }
            if index % g == 0 {
                magnitudes.push(0u32);
            }
            if let Some(m) = magnitudes.last_mut() {
                *m = (*m).max(value.unsigned_abs());
            }
            if let Some((first, magnitude)) = maximum.as_mut() {
                // Flow §1: strict improvement preserves the first attained index;
                // an all-zero complete row keeps the canonical pair (0,0).
                if value.unsigned_abs() > *magnitude {
                    *first = index as u16; // Checked complete width <=16384.
                    *magnitude = value.unsigned_abs();
                }
            }
        }
        let mut scales = Vec::new();
        scales
            .try_reserve_exact(magnitudes.len())
            .map_err(|_| Error::Capacity)?;
        if p.policy == 1 {
            scales.push(p.scale);
        } else {
            scales.extend(magnitudes.iter().map(|m| m.div_ceil(127)));
        }
        let mut codes = Vec::new();
        codes
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        for (index, value) in input.enumerate() {
            let scale = scales[index / g];
            // Flow §1: floor((2*abs(x)+s)/(2*s)), with canonical zero-row branch.
            // The validated envelope and full u32 scale keep both sides below 2^33.
            let q = if scale == 0 {
                0
            } else {
                (2 * u64::from(value.unsigned_abs()) + u64::from(scale)) / (2 * u64::from(scale))
            };
            if q > 127 {
                return Err(Error::Range);
            }
            codes.push(if value < 0 { -(q as i8) } else { q as i8 });
        }
        Ok(QuantisedRow {
            parameters: self.parameters,
            codes,
            wide: Vec::new(),
            scales,
            maximum,
        })
    }
    /// RFC-0004 A16: codes `R+(x/2^a) = floor((x + floor(2^a/2)) / 2^a)` at the least
    /// exponent `a` in `amin..=amax` that keeps every code within `[-c, c]`.
    fn convert_power(
        &self,
        length: usize,
        input: impl Iterator<Item = i32> + Clone,
        limits: Power,
        envelope: (i32, i32),
    ) -> Result<QuantisedRow, Error> {
        let code = |x: i32, a: u8| (i64::from(x) + ((1i64 << a) >> 1)) >> a;
        // R+ is monotone, so the row's extremes decide the exponent.
        let (mut low, mut high) = (0, 0);
        for value in input.clone() {
            if !(envelope.0..=envelope.1).contains(&value) {
                return Err(Error::Input);
            }
            low = low.min(value);
            high = high.max(value);
        }
        let c = i64::from(limits.code);
        let a = (limits.least..=limits.most)
            .find(|&a| code(high, a) <= c && code(low, a) >= -c)
            .ok_or(Error::Range)?;
        let mut wide = Vec::new();
        wide.try_reserve_exact(length).map_err(|_| Error::Capacity)?;
        wide.extend(input.map(|x| code(x, a) as i16));
        let mut scales = Vec::new();
        scales.try_reserve_exact(1).map_err(|_| Error::Capacity)?;
        scales.push(1 << a);
        Ok(QuantisedRow {
            parameters: self.parameters,
            codes: Vec::new(),
            wide,
            scales,
            maximum: None,
        })
    }
}

/// Immutable complete numerical result, not an authenticated source or proof claim.
/// Codes, runtime scale and original fraction must remain one semantic bundle.
/// ```compile_fail
/// fn change(row: &mut stele_cqis::row::QuantisedRow) { row.codes[0] = 1; }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct QuantisedRow {
    parameters: Row,
    codes: Vec<i8>,
    /// The codes of a power-of-two row (RFC-0004 A16); `codes` is then empty.
    wide: Vec<i16>,
    scales: Vec<u32>,
    maximum: Option<(u16, u32)>,
}
impl QuantisedRow {
    pub(crate) fn try_clone(&self) -> Result<Self, Error> {
        let mut codes = Vec::new();
        codes
            .try_reserve_exact(self.codes.len())
            .map_err(|_| Error::Capacity)?;
        codes.extend_from_slice(&self.codes);
        let mut scales = Vec::new();
        scales
            .try_reserve_exact(self.scales.len())
            .map_err(|_| Error::Capacity)?;
        scales.extend_from_slice(&self.scales);
        let mut wide = Vec::new();
        wide.try_reserve_exact(self.wide.len())
            .map_err(|_| Error::Capacity)?;
        wide.extend_from_slice(&self.wide);
        Ok(Self {
            parameters: self.parameters,
            codes,
            wide,
            scales,
            maximum: self.maximum,
        })
    }
    /// Original configured scope, including the unchanged policy and full scale.
    pub fn parameters(&self) -> Row {
        self.parameters
    }
    /// Complete row-order signed codes in [-127,127], without padding. Empty for a
    /// power-of-two row, whose codes are [`Self::wide_codes`].
    pub fn codes(&self) -> &[i8] {
        &self.codes
    }
    /// RFC-0004 A16: the codes of a power-of-two row, in `[-(2^(b-1) - 1), 2^(b-1) - 1]`.
    /// Empty for every other policy.
    pub fn wide_codes(&self) -> &[i16] {
        &self.wide
    }
    /// RFC-0004 A16: the exponent `a` of a power-of-two row, whose scale is `2^a`.
    pub fn exponent(&self) -> Option<u8> {
        self.parameters
            .power()
            .map(|_| self.scales[0].trailing_zeros() as u8)
    }
    /// Runtime row scale, up to 8454661 for gated inputs; zero only in dynamic mode.
    /// A grouped row (policy 2) has no single scale: this is its first group's.
    pub fn scale(&self) -> u32 {
        self.scales[0]
    }
    /// Runtime scales, one per group of g codes (RFC-0004 A15); a single scale for
    /// policies 0/1.
    pub fn scales(&self) -> &[u32] {
        &self.scales
    }
    /// Original source fraction; conversion changes no implicit units.
    pub fn fraction(&self) -> u8 {
        self.parameters.fraction
    }
    /// Dynamic mode's (first original index, attained magnitude), including (0,0)
    /// for an all-zero row. Static mode has no maximum/index witness and returns None.
    /// shortcut: a grouped row also returns None (its per-group local witnesses j_k of
    /// RFC-0004 A15 are not exposed); add them with the schema-23 prover consumer.
    pub fn maximum(&self) -> Option<(u16, u32)> {
        self.maximum
    }
}
