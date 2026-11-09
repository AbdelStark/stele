//! RFC-0025 §2 and execution appendix: complete numerical forward/cache execution.
//! Original-byte/configuration joins are checked; no numerical result admits a proof.
use crate::{bounds::arithmetic, functions, model, numerics, row, tables};
use alloc::vec::Vec;
mod attention;
pub mod capture;
#[cfg(test)]
mod capture_tests;
mod data;
mod decoding;
mod forward;
mod request;
#[cfg(test)]
mod tests;
pub use capture::Capture;
use data::Data;
pub use decoding::{Decision, Generation};
pub use forward::{Cache, Full, Step};
pub use request::Request;

type RotationPoint = (model::Rotation, u32, u16, (i16, i16));

/// Rejection is atomic: no partial output or updated K/V cache is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Complete Model/Preparation/Scales/Artifact validation failed.
    Model(model::Error),
    /// A configured static arithmetic record failed admission.
    Bounds(arithmetic::Error),
    /// Complete-row conversion failed.
    Row(row::Error),
    /// An internal exact numerical or shape invariant failed.
    Arithmetic,
    /// A required output is outside its signed range.
    Range,
    /// A selected exponential input lies outside its inclusive domain.
    ExpDomain,
    /// The definition could not certify a nonlinear point.
    Generation(tables::Error),
    /// Actual prefix length is empty or exceeds the configured context.
    Length,
    /// An original token is outside the configured vocabulary.
    Token,
    /// Cache Model, Scales or Artifact identity differs.
    CacheScope,
    /// Cache geometry, fractions, policy, scale or codes are invalid.
    Cache,
    /// Request framing, Model identity, lengths, EOS set or mode is invalid.
    Request,
    /// The original prompt differs or the complete prefix cannot make another step.
    Prefix,
    /// Sampled seed length/commitment differs, or greedy supplied seed bytes.
    Seed,
    /// The generated prefix already stopped or the completed stop cause differs.
    Stop,
    /// The decoding input is not the complete vocabulary row.
    Logits,
    /// The explicit working-storage budget or a fallible allocation failed.
    Capacity,
}
impl From<model::Error> for Error {
    fn from(e: model::Error) -> Self {
        Self::Model(e)
    }
}
impl From<row::Error> for Error {
    fn from(e: row::Error) -> Self {
        Self::Row(e)
    }
}
impl From<arithmetic::Error> for Error {
    fn from(e: arithmetic::Error) -> Self {
        Self::Bounds(e)
    }
}
impl From<tables::Error> for Error {
    fn from(e: tables::Error) -> Self {
        Self::Generation(e)
    }
}
impl From<numerics::Error> for Error {
    fn from(e: numerics::Error) -> Self {
        match e {
            numerics::Error::Range => Self::Range,
            numerics::Error::Capacity => Self::Capacity,
            numerics::Error::Arithmetic => Self::Arithmetic,
        }
    }
}
impl From<functions::NormError> for Error {
    fn from(e: functions::NormError) -> Self {
        match e {
            functions::NormError::Overflow => Self::Range,
            functions::NormError::Capacity => Self::Capacity,
            _ => Self::Arithmetic,
        }
    }
}
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    n.checked_mul(core::mem::size_of::<T>())
        .filter(|v| *v <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(out)
}
fn copy<T: Copy>(raw: &[T]) -> Result<Vec<T>, Error> {
    let mut out = reserved(raw.len())?;
    out.extend_from_slice(raw);
    Ok(out)
}
fn wide(value: i64) -> Result<i16, Error> {
    i16::try_from(value).map_err(|_| Error::Range)
}
/// Signed `bits`-bit target: 16, or 24 for RFC-0004 A14's wide residual stream.
fn signed(value: i64, bits: u32) -> Result<i32, Error> {
    let bound = 1i64 << (bits - 1);
    if !(-bound..bound).contains(&value) {
        return Err(Error::Range);
    }
    i32::try_from(value).map_err(|_| Error::Range)
}

/// Checked immutable source data plus bounded, locally derived point caches.
/// The borrowed Artifact remains immutable for the entire executor lifetime.
/// Output/cache memory is admitted per request under an explicit host budget;
/// this budget is not a change to Model's shape domains.
pub struct Executor<'a> {
    data: Data<'a>,
    quantisers: Vec<Vec<row::Quantiser>>,
    final_quantiser: row::Quantiser,
    points: tables::points::Points,
    rotations: Vec<Option<RotationPoint>>,
    memory_limit: u64,
}
impl<'a> Executor<'a> {
    /// Validate every Artifact byte under an independently expected digest and
    /// admit the full configured score/block bounds before numerical use.
    /// `memory_limit` bounds conservative working arrays, certificates and point
    /// caches, excluding the caller-owned Artifact/metadata and the generators'
    /// separately bounded exact scratch. It never replaces fallible allocation.
    pub fn new(
        model: &'a model::Model,
        preparation: &model::Preparation<'_>,
        scales: &'a model::Scales,
        raw: &'a [u8],
        expected: &[u8; 32],
        memory_limit: u64,
    ) -> Result<Self, Error> {
        Self::admit(model, 1, memory_limit)?;
        let data = Data::new(model, preparation, scales, raw, expected)?;
        let s = model.shape();
        let mut quantisers = reserved(model.blocks().len())?;
        for b in model.blocks() {
            let p = b.policies();
            let f = b.projection_fractions();
            let shape = arithmetic::AttentionShape {
                heads: s.heads(),
                groups: s.groups(),
                width: s.head_width(),
                context: s.context(),
            };
            let policy = |i: usize| (p[i].mode(), p[i].scale() as u16);
            arithmetic::Record::score(arithmetic::Score {
                shape,
                query_fraction: f[0],
                key_fraction: f[1],
                exp_fraction: b.exponential().function().parameters()[1],
                query_policy: policy(1),
                key_policy: policy(2),
                multiplier: b.score_multiplier().0,
                exponent: b.score_multiplier().1,
            })?;
            arithmetic::Record::weighted(arithmetic::Weighted {
                shape,
                value_fraction: f[2],
                exp_fraction: b.exponential().function().parameters()[2],
                policy: policy(3),
                mode: b.accumulation(),
                drop: b.drop(),
            })?;
            let ap = b.activation().function().parameters();
            if ap[1] > ap[0] {
                return Err(Error::Model(model::Error::Activation));
            }
            let units = [
                b.first_norm().function().parameters()[4],
                f[0],
                f[1],
                f[2],
                b.attention_fraction(),
                b.second_norm().function().parameters()[4],
                ap[1] + if s.family() == 1 { f[4] } else { 0 },
            ];
            let kv = s.groups() * s.head_width();
            let widths = [
                s.width(),
                s.width(),
                kv,
                kv,
                s.width(),
                s.width(),
                s.hidden(),
            ];
            let mut qs = reserved(7)?;
            for i in 0..7 {
                qs.push(row::Quantiser::new(arithmetic::Row {
                    dimension: widths[i],
                    kind: u8::from(i == 6 && s.family() == 1),
                    fraction: units[i],
                    policy: p[i].mode(),
                    scale: p[i].scale(),
                })?);
            }
            quantisers.push(qs);
        }
        let p = model.final_policy();
        let final_quantiser = row::Quantiser::new(arithmetic::Row {
            dimension: s.width(),
            kind: 0,
            fraction: model.final_norm().function().parameters()[4],
            policy: p.mode(),
            scale: p.scale(),
        })?;
        let mut rotations = reserved(65536)?;
        rotations.resize(65536, None);
        Ok(Self {
            data,
            quantisers,
            final_quantiser,
            points: tables::points::Points::new()?,
            rotations,
            memory_limit,
        })
    }
    fn admit(model: &model::Model, n: usize, limit: u64) -> Result<(), Error> {
        let s = model.shape();
        let l = u64::from(s.layers());
        // Includes full output cuts/logits, old and new K/V caches, Q/K/V and
        // FFN temporaries, row headers, and sorting/attention scratch. Eight
        // 128-KiB certificates per block bound the retained Quantiser records.
        let columns = u64::from(s.vocabulary())
            + (l + 1) * u64::from(s.width())
            + l * u64::from(s.groups()) * u64::from(s.head_width())
            + u64::from(s.hidden())
            + 256;
        let bytes = (n as u64)
            .checked_mul(columns)
            .and_then(|v| v.checked_mul(64))
            .and_then(|v| v.checked_add((l + 1) * 8 * 131072 + (1 << 26)))
            .ok_or(Error::Capacity)?;
        if bytes > limit {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn tokens(&self, tokens: &[u32]) -> Result<(), Error> {
        if tokens.is_empty() || tokens.len() as u64 > u64::from(self.data.model.shape().context()) {
            return Err(Error::Length);
        }
        if tokens
            .iter()
            .any(|v| *v >= self.data.model.shape().vocabulary())
        {
            return Err(Error::Token);
        }
        Self::admit(self.data.model, tokens.len(), self.memory_limit)
    }
    fn exponential(
        &mut self,
        r: &functions::Representation,
        input: i64,
        mut record: Option<&mut capture::Exponential>,
    ) -> Result<i32, Error> {
        let p = r.function().parameters();
        if input > 0 || input < -(1i64 << p[0]) {
            return Err(Error::ExpDomain);
        }
        let c = r.components();
        let mut lookups = [(0, 0); 3];
        let value = if r.mode() == 0 {
            let value = self.points.value(c[0], input as i32)?;
            lookups[0] = (input as i32, value);
            value
        } else {
            let k = c[0].parameters()[3];
            let n = (-input) as u32;
            lookups[0].0 = (n >> k) as i32;
            lookups[1].0 = (n % (1u32 << k)) as i32;
            let high = self.points.value(c[0], lookups[0].0)?;
            let low = self.points.value(c[1], lookups[1].0)?;
            (lookups[0].1, lookups[1].1) = (high, low);
            let product = high * low / (1i32 << p[2]);
            if let Some(w) = record.as_deref_mut() {
                w.product
                    .push(i128::from(high * low), 1u128 << p[2], i64::from(product))?;
            }
            if r.mode() == 2 {
                lookups[2] = (input as i32, self.points.value(c[2], input as i32)?);
                product + lookups[2].1
            } else {
                product
            }
        };
        if let Some(w) = record {
            w.product.rounding = capture::Rounding::Floor;
            capture::put(&mut w.input, input)?;
            capture::put(&mut w.output, i64::from(value))?;
            if w.components.is_empty() {
                for _ in c {
                    capture::put(&mut w.components, capture::Lookup::default())?;
                }
            }
            for (lookup, (t, v)) in w.components.iter_mut().zip(lookups) {
                lookup.push(i64::from(t), i64::from(v))?;
            }
        }
        Ok(value)
    }
}
