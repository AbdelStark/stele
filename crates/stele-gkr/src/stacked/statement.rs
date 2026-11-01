//! RFC-0006 A4 §§1–4: checked expected statement and exact source/Stack bytes.
use super::{add, mul, reserve, Error};
use crate::public_mle::{self, Axis, Coefficient, Kind};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_sumcheck::{Instance, Term};

/// The two accepted canonical coordinate-group orders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Order {
    /// Layer coordinates first.
    LayerFirst,
    /// Layer coordinates last.
    LayerLast,
}
/// Expected consumed output claim; the runtime does not prove its op derivation.
pub struct Claim<'a, K> {
    /// Tensor identity.
    pub id: u64,
    /// Original layout; empty for a scalar.
    pub axes: &'a [Axis],
    /// Canonical original coordinates.
    pub point: &'a [K],
    /// Claimed output value, also the complete A1 sum.
    pub value: K,
}
/// Expected public-coefficient relation, fixed independently of the proof.
pub struct Statement<'a, K> {
    /// Stage identity.
    pub id: u64,
    /// Common original layout, with a leading layer axis.
    pub axes: &'a [Axis],
    /// Expected elimination order.
    pub order: Order,
    /// Complete consumed claim.
    pub output: Claim<'a, K>,
    /// Uncommitted public coefficient identity.
    pub coefficient_id: u64,
    /// Distinct original tensor identities in plan order.
    pub inputs: &'a [u64],
    /// P's ordered terms, with at most three original factors each.
    pub terms: &'a [Term<K>],
    /// A7 selected-axis points, multiplied on the Boolean table before extension.
    pub selectors: &'a [Option<&'a [K]>],
    /// Exact public Boolean primitive and immutable source values.
    pub kind: Kind<'a>,
    /// Required only for onehot/exact-table sources; disjoint from all tensor IDs.
    pub source_id: Option<u64>,
}
/// Caller policy, never proof metadata. Counts are checked before any absorb.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Combined StackSources, Stack and A1 descriptor bytes.
    pub descriptor_bytes: usize,
    /// All A1 round/final payload bytes, including their id/index prefixes.
    pub proof_bytes: usize,
    /// Conservative total prepared field entries, excluding borrowed inputs/proof/partials.
    pub prepared_entries: usize,
    /// Dense padded-block partial entries, including zero slots.
    pub partial_entries: usize,
    /// A7's simultaneous axis-vector entries.
    pub axis_entries: usize,
}
/// Preparation only, not a proof record. Construction does not touch a transcript.
pub struct Prepared<'a, K> {
    pub(super) statement: &'a Statement<'a, K>,
    pub(super) coefficient: Coefficient<'a, K>,
    pub(super) instance: Instance<K>,
    pub(super) n: usize,
    pub(super) degree: usize,
    pub(super) partial_count: usize,
    bytes: Vec<u8>,
    source_len: usize,
}
fn layout(axes: &[Axis], required: bool) -> Result<usize, Error> {
    if axes.len() > 64
        || (required && axes.is_empty())
        || axes
            .iter()
            .any(|a| a.bits > 63 || a.real == 0 || a.real > 1u64 << a.bits)
    {
        return Err(Error::InvalidStacked);
    }
    let m: usize = axes.iter().map(|a| usize::from(a.bits)).sum();
    if m > 63 {
        return Err(Error::InvalidStacked);
    }
    Ok(m)
}
fn same_layout(a: &[Axis], b: &[Axis]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| a.bits == b.bits && a.real == b.real)
}
fn put_layout(out: &mut Vec<u8>, axes: &[Axis]) {
    out.push(axes.len() as u8);
    for a in axes {
        out.push(a.bits);
        out.extend_from_slice(&a.real.to_le_bytes());
    }
}
impl<'a, K: ChallengeField + Eq> Prepared<'a, K> {
    /// Validate all identities, A7 parameters, A1 shapes and simultaneous capacities.
    pub fn new(s: &'a Statement<'a, K>, limits: Limits) -> Result<Self, Error> {
        let m = layout(s.axes, true)?;
        if layout(s.output.axes, false)? != s.output.point.len()
            || s.coefficient_id == s.output.id
            || s.inputs.contains(&s.coefficient_id)
            || s.inputs
                .iter()
                .enumerate()
                .any(|(i, id)| s.inputs[..i].contains(id))
            || (s.inputs.contains(&s.output.id) && !same_layout(s.axes, s.output.axes))
            || s.terms.iter().any(|t| {
                t.factors.len() > 3 || t.factors.iter().any(|i| *i as usize >= s.inputs.len())
            })
        {
            return Err(Error::InvalidStacked);
        }
        let has_source = matches!(s.kind, Kind::OnehotSparse { .. } | Kind::RopeTables { .. });
        if has_source != s.source_id.is_some()
            || s.source_id.is_some_and(|id| {
                id == s.output.id || id == s.coefficient_id || s.inputs.contains(&id)
            })
        {
            return Err(Error::InvalidStacked);
        }
        let coefficient = Coefficient::new(s.axes, s.selectors, s.kind, limits.axis_entries)
            .map_err(|e| {
                if e == public_mle::Error::Capacity {
                    Error::Capacity
                } else {
                    Error::InvalidStacked
                }
            })?;
        let a = s.inputs.len();
        let count = add(a, 1)?;
        u32::try_from(count).map_err(|_| Error::Capacity)?;
        u32::try_from(s.terms.len()).map_err(|_| Error::Capacity)?;
        let degree = s
            .terms
            .iter()
            .map(|t| t.factors.len() + 1)
            .max()
            .unwrap_or(0);
        let n = 1usize.checked_shl(m as u32).ok_or(Error::Capacity)?;
        let blocks = 1usize
            .checked_shl(u32::from(s.axes[0].bits))
            .ok_or(Error::Capacity)?;
        let partial_count = mul(blocks, degree + 1)?;
        // Covers dense copies, public evaluation weights, point/claims and A1 term coefficients.
        let prepared = add(add(mul(count, n)?, n)?, add(add(m, count)?, s.terms.len())?)?;
        // Even an unlimited caller policy cannot admit unaddressable Vec storage.
        if mul(prepared, core::mem::size_of::<K>())? > isize::MAX as usize
            || mul(partial_count, core::mem::size_of::<K>())? > isize::MAX as usize
        {
            return Err(Error::Capacity);
        }
        let k = 4 * K::DEGREE;
        let proof_len = add(
            mul(m, add(12, mul(degree + 1, k)?)?)?,
            add(12, mul(count, k)?)?,
        )?;
        let source_len = add(14, mul(a, add(8, mul(n, k)?)?)?)?;
        let mut len = add(
            10 + 1
                + 9 * s.axes.len()
                + 1
                + 8
                + 1
                + 9 * s.output.axes.len()
                + 8
                + 4
                + 4
                + 1
                + s.axes.len(),
            mul(add(s.output.point.len(), 1)?, k)?,
        )?;
        len = add(len, mul(a, 8)?)?;
        let mut instance_len = add(23 + k, mul(count, 8)?)?;
        for term in s.terms {
            len = add(len, k + 1 + 4 * term.factors.len())?;
            instance_len = add(instance_len, k + 1 + 4 * (term.factors.len() + 1))?;
        }
        for z in s.selectors.iter().flatten() {
            len = add(len, mul(z.len(), k)?)?;
        }
        let payload = match s.kind {
            Kind::Eq => 0,
            Kind::CausalMask { .. } | Kind::GqaBroadcast { .. } => 2,
            Kind::WindowMask { .. } => 10,
            Kind::OnehotSparse { indices, .. } => add(18, mul(indices.len(), 8)?)?,
            Kind::RopeTables { axes, values } => add(17 + axes.len(), mul(values.len(), 4)?)?,
        };
        len = add(len, payload)?;
        if add(add(len, source_len)?, instance_len)? > limits.descriptor_bytes
            || proof_len > limits.proof_bytes
            || prepared > limits.prepared_entries
            || partial_count > limits.partial_entries
        {
            return Err(Error::Capacity);
        }
        let mut inputs = Vec::new();
        reserve(&mut inputs, count)?;
        inputs.extend_from_slice(s.inputs);
        inputs.push(s.coefficient_id);
        let mut terms = Vec::new();
        reserve(&mut terms, s.terms.len())?;
        for term in s.terms {
            let mut factors = Vec::new();
            reserve(&mut factors, term.factors.len() + 1)?;
            factors.extend_from_slice(&term.factors);
            factors.push(a as u32);
            terms.push(Term {
                coefficient: term.coefficient,
                factors,
            });
        }
        let instance = Instance {
            id: s.id,
            num_vars: m as u32,
            inputs,
            terms,
            claimed_sum: s.output.value,
        };
        if instance.encoded_len().map_err(Error::Sumcheck)? != instance_len {
            return Err(Error::Capacity);
        }
        let mut bytes = Vec::new();
        reserve(&mut bytes, len)?;
        bytes.extend_from_slice(&[1, K::DEGREE as u8]);
        bytes.extend_from_slice(&s.id.to_le_bytes());
        put_layout(&mut bytes, s.axes);
        bytes.push(u8::from(s.order == Order::LayerLast));
        bytes.extend_from_slice(&s.output.id.to_le_bytes());
        put_layout(&mut bytes, s.output.axes);
        for value in s.output.point {
            bytes.extend_from_slice(value.to_le_bytes().as_ref());
        }
        bytes.extend_from_slice(s.output.value.to_le_bytes().as_ref());
        bytes.extend_from_slice(&s.coefficient_id.to_le_bytes());
        bytes.extend_from_slice(&(a as u32).to_le_bytes());
        for id in s.inputs {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes.extend_from_slice(&(s.terms.len() as u32).to_le_bytes());
        for term in s.terms {
            bytes.extend_from_slice(term.coefficient.to_le_bytes().as_ref());
            bytes.push(term.factors.len() as u8);
            for factor in &term.factors {
                bytes.extend_from_slice(&factor.to_le_bytes());
            }
        }
        bytes.push(match s.kind {
            Kind::Eq => 0,
            Kind::CausalMask { .. } => 1,
            Kind::WindowMask { .. } => 2,
            Kind::OnehotSparse { .. } => 3,
            Kind::GqaBroadcast { .. } => 4,
            Kind::RopeTables { .. } => 5,
        });
        for z in s.selectors {
            bytes.push(u8::from(z.is_some()));
            if let Some(z) = z {
                for value in *z {
                    bytes.extend_from_slice(value.to_le_bytes().as_ref());
                }
            }
        }
        match s.kind {
            Kind::Eq => (),
            Kind::CausalMask { row, column }
            | Kind::WindowMask { row, column, .. }
            | Kind::OnehotSparse { row, column, .. } => {
                bytes.extend_from_slice(&[row as u8, column as u8])
            }
            Kind::GqaBroadcast { head, group } => {
                bytes.extend_from_slice(&[head as u8, group as u8])
            }
            Kind::RopeTables { axes, .. } => {
                bytes.push(axes.len() as u8);
                for a in axes {
                    bytes.push(*a as u8);
                }
            }
        }
        if let Kind::WindowMask { width, .. } = s.kind {
            bytes.extend_from_slice(&width.to_le_bytes());
        }
        if let Some(id) = s.source_id {
            bytes.extend_from_slice(&id.to_le_bytes());
            match s.kind {
                Kind::OnehotSparse { indices, .. } => {
                    bytes.extend_from_slice(&(indices.len() as u64).to_le_bytes());
                    for i in indices {
                        bytes.extend_from_slice(&i.to_le_bytes());
                    }
                }
                Kind::RopeTables { values, .. } => {
                    bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
                    for v in values {
                        bytes.extend_from_slice(&v.as_u32().to_le_bytes());
                    }
                }
                _ => return Err(Error::InvalidStacked),
            }
        }
        if bytes.len() != len {
            return Err(Error::Capacity);
        }
        Ok(Self {
            statement: s,
            coefficient,
            instance,
            n,
            degree,
            partial_count,
            bytes,
            source_len,
        })
    }
    /// Canonical Stack payload, derived from the immutable expected statement.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Nested A1 descriptor; its raw point is not an original-tensor claim.
    pub fn instance(&self) -> &Instance<K> {
        &self.instance
    }
    pub(super) fn coordinates(&self, index: usize) -> [u64; 64] {
        let mut coordinates = [0; 64];
        let mut shift = self.instance.num_vars as usize;
        for (out, axis) in coordinates.iter_mut().zip(self.statement.axes) {
            shift -= usize::from(axis.bits);
            *out = (index >> shift) as u64 & ((1u64 << axis.bits) - 1);
        }
        coordinates
    }
    pub(super) fn valid(&self, coordinates: &[u64; 64]) -> bool {
        self.statement
            .axes
            .iter()
            .zip(coordinates)
            .all(|(a, i)| *i < a.real)
    }
    pub(super) fn check_tables(&self, tables: &[&[K]]) -> Result<(), Error> {
        if tables.len() != self.statement.inputs.len() || tables.iter().any(|t| t.len() != self.n) {
            return Err(Error::PublicShape);
        }
        for i in 0..self.n {
            if !self.valid(&self.coordinates(i)) && tables.iter().any(|t| t[i] != K::from_i64(0)) {
                return Err(Error::PublicShape);
            }
        }
        Ok(())
    }
    /// Exact public StackSources payload, including the empty source roster.
    pub fn source_bytes(&self, tables: &[&[K]]) -> Result<Vec<u8>, Error> {
        self.check_tables(tables)?;
        let mut bytes = Vec::new();
        reserve(&mut bytes, self.source_len)?;
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&self.statement.id.to_le_bytes());
        bytes.extend_from_slice(&(tables.len() as u32).to_le_bytes());
        for (id, table) in self.statement.inputs.iter().zip(tables) {
            bytes.extend_from_slice(&id.to_le_bytes());
            for value in *table {
                bytes.extend_from_slice(value.to_le_bytes().as_ref());
            }
        }
        Ok(bytes)
    }
}
