//! RFC-0024 §1.1: whole-original range_8 authority from a complete fixed A5 attempt.
use crate::lookup::{self, Error, Layout, Limits, Table, TableField};
use alloc::vec::Vec;
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::{CodeField, PreparedSource, Usage, VerifiedCertificate};

const PREFIX: &[u8] = b"stele/v0.1/integer-linear/byte-range/v1";

/// Derived immutable expected data; construction alone establishes no membership.
/// Limits::public_bytes includes the fixed constructor payload for this wrapper.
pub struct Descriptor<'cert, K: ChallengeField> {
    id: u64,
    m: u8,
    originals: [&'cert VerifiedCertificate<K>; 1],
    table: Table,
    selector: Vec<u8>,
    layouts: [Layout; 2],
    r: usize,
    limits: Limits,
    public_bytes: usize,
    proof_bytes: usize,
}

/// One completed range event; retain every conditional A5/A9 obligation.
/// An arbitrary conditional lookup cannot be promoted:
/// ```compile_fail
/// use stele_field::QM31;
/// use stele_reductions::{byte_range::ByteRange, lookup::LookupRecord};
/// fn promote(r: LookupRecord<'_, QM31>) -> ByteRange<'_, QM31> { r.into() }
/// ```
/// The original certificate owns the result's lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::{byte_range::{ByteRange, Descriptor}, lookup::Limits};
/// fn escape(c: VerifiedCertificate<QM31>, mu: &[&'static VerifiedCertificate<QM31>],
///     proof: &[u8], limits: Limits) -> ByteRange<'static, QM31> {
///     Descriptor::new(&c, 7, &[20], limits).unwrap().verify(mu, proof).unwrap()
/// }
/// ```
/// Every ordered multiplicity owner also bounds that lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::byte_range::{ByteRange, Descriptor};
/// fn escape(d: &Descriptor<'static, QM31>, mu: VerifiedCertificate<QM31>,
///     proof: &[u8]) -> ByteRange<'static, QM31> {
///     d.verify(&[&mu], proof).unwrap()
/// }
/// ```
#[must_use = "retain this event and every original/multiplicity certificate obligation"]
pub struct ByteRange<'cert, K: ChallengeField> {
    lookup: lookup::LookupRecord<'cert, K>,
    original: &'cert VerifiedCertificate<K>,
    multiplicities: Vec<&'cert VerifiedCertificate<K>>,
    limits: Limits,
    usage: Usage,
}
impl<'cert, K: ChallengeField> ByteRange<'cert, K> {
    /// Actual complete conditional A5 record, including its fixed range parameters.
    pub fn lookup(&self) -> &lookup::LookupRecord<'cert, K> {
        &self.lookup
    }
    /// Genuine immutable original context and exact certificate identity.
    pub fn original(&self) -> &'cert VerifiedCertificate<K> {
        self.original
    }
    /// Caller-owned genuine multiplicity registrations, in repetition order.
    pub fn multiplicities(&self) -> &[&'cert VerifiedCertificate<K>] {
        &self.multiplicities
    }
    /// Local admission policy; no adversarial/global profile budget is certified.
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// This verification's constructor plus A5 work; independent imports are separate.
    pub fn usage(&self) -> &Usage {
        &self.usage
    }
}
impl<'original, K: ChallengeField> Descriptor<'original, K> {
    /// Derive only the canonical whole-source predicate and ordered fixed mu layouts.
    /// Exact A5 admission completes before any transcript or proof execution.
    pub fn new(
        original: &'original VerifiedCertificate<K>,
        id: u64,
        multiplicity_ids: &[u64],
        limits: Limits,
    ) -> Result<Self, Error> {
        let r = multiplicity_ids.len();
        if !(1..=2).contains(&r) || id >= 1 << 60 {
            return Err(Error::Statement);
        }
        let source = original.record().source();
        let n = source
            .rows()
            .checked_mul(source.columns())
            .ok_or(Error::Capacity)?;
        let child_public = limits
            .public_bytes
            .checked_sub(PREFIX.len())
            .ok_or(Error::ResourceLimit)?;
        // Bound expected selector storage before allocation; A5 checks exact costs below.
        if n as u64 > limits.positions || n > child_public || limits.proof_bytes < 2 {
            return Err(Error::ResourceLimit);
        }
        if n.checked_mul(core::mem::size_of::<K>())
            .ok_or(Error::Capacity)?
            > isize::MAX as usize
        {
            return Err(Error::Capacity);
        }
        let mut selector = Vec::new();
        selector.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        selector.resize(n, 1);
        let mut layouts = [Layout {
            id: 0,
            ell: 0,
            blowup: 1,
        }; 2];
        for (layout, id) in layouts.iter_mut().zip(multiplicity_ids) {
            layout.id = *id;
        }
        let mut d = Self {
            id,
            m: n.trailing_zeros() as u8,
            originals: [original],
            table: Table::range(8).map_err(Error::Table)?,
            selector,
            layouts,
            r,
            limits,
            public_bytes: 0,
            proof_bytes: 0,
        };
        let a5 = d.descriptor()?;
        let (public, proof) = (a5.public_bytes(), a5.proof_size());
        d.public_bytes = public.checked_add(PREFIX.len()).ok_or(Error::Capacity)?;
        d.proof_bytes = proof;
        Ok(d)
    }
    fn statement(&self) -> lookup::Statement<'_, 'original, K> {
        lookup::Statement {
            id: self.id,
            m: self.m,
            b: self.m.min(30),
            table: &self.table,
            selector: &self.selector,
            originals: &self.originals,
            multiplicities: &self.layouts[..self.r],
        }
    }
    /// RFC-0008 A2 item 2: plan admission over every physical message entry
    /// (RFC-0024 §1.1); r and d come from the profile only.
    pub fn admit(&self, profile: lookup::Profile) -> Result<(), Error> {
        lookup::admit(&self.statement(), self.selector.len() as u64, profile)
    }
    fn descriptor(&self) -> Result<lookup::Descriptor<'_, 'original, K>, Error> {
        lookup::Descriptor::new(
            self.statement(),
            Limits {
                public_bytes: self.limits.public_bytes - PREFIX.len(),
                ..self.limits
            },
        )
    }
    /// Exact constructor plus complete A5 absorb payload bound, excluding imports.
    pub fn public_bytes(&self) -> usize {
        self.public_bytes
    }
    /// Exact unchanged A5 proof length, including multiplicity packets.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes
    }
}
impl<'original, K: ChallengeField + CodeField + TableField + Eq> Descriptor<'original, K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    /// Complete producer payload bound, including both real mu registration calls.
    pub fn producer_public_bytes(&self) -> Result<usize, Error> {
        self.descriptor()?
            .producer_public_bytes()?
            .checked_add(PREFIX.len())
            .ok_or(Error::Capacity)
    }
    /// Existing A5 conservative dense-slot admission; not observed capacity or RSS.
    pub fn producer_dense_elements(&self) -> Result<usize, Error> {
        self.descriptor()?.producer_dense_elements()
    }
    /// Actual A5 production under the fixed prefix; producing bytes grants no authority.
    #[allow(clippy::result_large_err)]
    pub fn prove(
        &self,
        original: &PreparedSource<'_, K>,
        limits: lookup::ProducerLimits,
    ) -> Result<(Vec<u8>, lookup::ProverUsage), lookup::ProverFailure> {
        let before = |cause| lookup::ProverFailure {
            cause,
            usage: lookup::ProverUsage::default(),
        };
        let a5 = self.descriptor().map_err(before)?;
        let public = a5
            .producer_public_bytes()
            .map_err(before)?
            .checked_add(PREFIX.len())
            .ok_or_else(|| before(Error::Capacity))?;
        if public > limits.public_bytes
            || a5.producer_dense_elements().map_err(before)? > limits.dense_elements
        {
            return Err(before(Error::ResourceLimit));
        }
        let mut t = Transcript::new(PREFIX).map_err(|e| before(Error::Transcript(e)))?;
        a5.prove(
            &mut t,
            &[original],
            lookup::ProducerLimits {
                public_bytes: limits.public_bytes - PREFIX.len(),
                ..limits
            },
        )
    }
    /// Separate actual A9 imports, retaining the ordered failed prefix without owners.
    #[allow(clippy::result_large_err)]
    pub fn register_multiplicities(
        &self,
        proof: &[u8],
        max_public_bytes: usize,
    ) -> Result<lookup::RegisteredMultiplicities<K>, lookup::RegistrationFailure> {
        self.descriptor()
            .map_err(|cause| lookup::RegistrationFailure {
                cause,
                registrations: [None; 2],
            })?
            .register_multiplicities(proof, max_public_bytes)
    }
    /// Only the complete fixed A5 verifier constructs a range event; no transcript is supplied.
    pub fn verify<'cert>(
        &self,
        multiplicities: &[&'cert VerifiedCertificate<K>],
        proof: &[u8],
    ) -> Result<ByteRange<'cert, K>, lookup::Failure>
    where
        'original: 'cert,
    {
        let before = |cause| lookup::Failure {
            cause,
            usage: Usage::default(),
        };
        let a5 = self.descriptor().map_err(before)?;
        // Reserve bounded owner-reference storage before any charged work.
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(self.r)
            .map_err(|_| before(Error::Capacity))?;
        let mut t = Transcript::new(PREFIX).map_err(|e| before(Error::Transcript(e)))?;
        let (lookup, usage) = a5.verify(&mut t, multiplicities, proof)?;
        owners.extend_from_slice(multiplicities);
        Ok(ByteRange {
            lookup,
            original: self.originals[0],
            multiplicities: owners,
            limits: self.limits,
            usage,
        })
    }
}
