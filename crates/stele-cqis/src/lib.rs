//! Scalar CQIS arithmetic, RFC-0004 §2, §5.2 and A1.
//! Canonical functions, representations, manifests and tables follow RFC-0021 §§2,4.
//! These integer operations do not enforce a field proof or a bound certificate.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Threads for block-parallel generation (rotation rows, table rows): the machine's
/// parallelism, capped by `RAYON_NUM_THREADS` when it is set, so a run pinned to a thread
/// count stays within it. Only the schedule depends on it, never a value.
#[cfg(feature = "std")]
pub(crate) fn workers() -> usize {
    let available = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .map_or(available, |n| n.min(available))
}

/// Join scoped workers in order. A worker's panic is re-raised after every worker has
/// been joined; otherwise the first error in worker order is returned.
#[cfg(feature = "std")]
pub(crate) fn join_all<'scope, E>(
    handles: impl IntoIterator<Item = std::thread::ScopedJoinHandle<'scope, Result<(), E>>>,
) -> Result<(), E> {
    let (mut first, mut panic) = (Ok(()), None);
    for handle in handles {
        match handle.join() {
            Ok(result) if first.is_ok() => first = result,
            Ok(_) => {}
            Err(payload) => panic = panic.or(Some(payload)),
        }
    }
    if let Some(payload) = panic {
        std::panic::resume_unwind(payload);
    }
    first
}

mod numerics;

/// Complete Artifact-backed integer model evaluation (RFC-0025 §2).
pub mod execution;

/// Closed static arithmetic records from separate checked parameters (RFC-0022).
pub mod bounds;

/// Complete dynamic/static row conversion and static certificates (RFC-0025 §2.2/2.5).
pub mod row;

/// Canonical full-model configuration, Scales and Registry (RFC-0025 encoding §§1,4-6).
pub mod model;

/// Checked function definitions and selected component schemas (RFC-0021 §4).
pub mod functions;

/// Checked component-table metadata and canonical encodings (RFC-0021 §4).
pub mod tables;

/// A rejected arithmetic configuration or value; no saturation or wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Mantissa is outside 1..65536.
    Scale,
    /// Right shift is outside the supported exact i64 range 0..=62.
    Shift,
    /// The output does not fit its target signed format.
    Range,
    /// An exact intermediate cannot be represented.
    Overflow,
}

/// Requantisation output formats; accumulator inputs use the native i32 type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Signed integer in -128..=127.
    Int8,
    /// Signed integer in -32768..=32767.
    Int16,
}

/// Checked public mantissa/right-shift pair for RFC-0004 A1.
///
/// The supported shift range is 0..=62 so D and the biased magnitude fit i64.
/// Weight exponents, tensor scales and static bound certificates are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requant {
    mantissa: i64,
    shift: u32,
}

impl Requant {
    /// Validate a positive 16-bit mantissa and supported nonnegative shift.
    pub fn new(mantissa: u32, shift: u32) -> Result<Self, Error> {
        if !(1..65536).contains(&mantissa) {
            return Err(Error::Scale);
        }
        if shift > 62 {
            return Err(Error::Shift);
        }
        Ok(Self {
            mantissa: i64::from(mantissa),
            shift,
        })
    }

    /// Round the exact scaled accumulator half away from zero, then check range.
    /// A successful result fits `format`, even though both formats return i16.
    pub fn apply(self, accumulator: i32, format: Format) -> Result<i16, Error> {
        let product = i64::from(accumulator)
            .checked_mul(self.mantissa)
            .ok_or(Error::Overflow)?;
        let divisor = 1i64.checked_shl(self.shift).ok_or(Error::Overflow)?;
        let bias = if self.shift == 0 { 0 } else { divisor / 2 };
        let magnitude = product.checked_abs().ok_or(Error::Overflow)?;
        let quotient = magnitude.checked_add(bias).ok_or(Error::Overflow)? / divisor;
        let rounded = if product < 0 { -quotient } else { quotient };
        match format {
            Format::Int8 => i8::try_from(rounded)
                .map(i16::from)
                .map_err(|_| Error::Range),
            Format::Int16 => i16::try_from(rounded).map_err(|_| Error::Range),
        }
    }
}

/// Exact residual addition with saturation disabled (RFC-0004 §5.2).
/// Runtime rejection does not replace a reduction's static bound certificate.
pub fn residual_add(left: i16, right: i16) -> Result<i16, Error> {
    left.checked_add(right).ok_or(Error::Range)
}
