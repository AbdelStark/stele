//! RFC-0008 A5 / native-lookup §§1,3,5,6: checked expected data and untrusted wire.
//! Validation scans selectors/proof bytes; encoding copies public bytes and charges
//! Table's ordinary hash to T_misc. Production executes actual registrations and
//! emits untrusted lookup bytes; no lookup acceptance record or profile is granted.
use alloc::vec::Vec;
use core::mem::size_of;
use stele_cqis::tables::EncodedDescriptor;
pub use stele_cqis::tables::{Descriptor as TableDescriptor, Table, TableField};
use stele_field::{Serialize, M31};
use stele_hash::{ChallengeField, HashUsage};
use stele_lookup::fraction;
use stele_pcs::{ProofKind, Source, VerifiedCertificate};

/// Rejected expected data, untrusted encoding or admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported expected dimensions, lookup identity or multiplicity layout.
    Statement,
    /// The group exponent exceeds min(m,30).
    GroupBound,
    /// The literal selector has the wrong length or a non-Boolean byte.
    Selector,
    /// Original count/dimensions or distinct original/multiplicity ids disagree.
    SourceRoster,
    /// Outer length/version/degree or an outer piece scalar is not canonical.
    ProofShape,
    /// A caller's positions, cumulative public payload or proof cap is exceeded.
    ResourceLimit,
    /// Checked arithmetic, addressability, hash counting or allocation failed.
    Capacity,
    /// Preserve the existing A3 codec's canonical-field error.
    Fraction(fraction::Error),
    /// Preserve the actual A9 source/parser cause.
    Pcs(stele_pcs::Error),
    /// Preserve the actual immutable Table encoding cause.
    Table(stele_cqis::tables::Error),
    /// Actual public Table denominator disagrees with the table-tree claim.
    TableDenominatorMismatch,
    /// All structural piece values do not sum to the actual table numerator.
    PieceSumMismatch,
    /// The production transcript aborted; discard the entire attempt.
    Transcript(stele_hash::Error),
}
/// Expected physical multiplicity layout; its root remains a proof choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    /// Source identity, distinct from every original and other multiplicity.
    pub id: u64,
    /// Physical row exponent; the canonical limb axis stays in columns.
    pub ell: u8,
    /// Circle blowup exponent, one or two.
    pub blowup: u8,
}
/// Codec/closed-verifier admission; producer dense admission belongs to its producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum number of original positions.
    pub positions: u64,
    /// Sum of all outer and nested absorb payload lengths, including proof payloads.
    /// Excludes hash framing, challenges, prior caller work and standalone registration.
    /// This cumulative work cap is distinct from any single allocation or peak memory.
    pub public_bytes: usize,
    /// Complete serialized lookup proof, including registration packets.
    pub proof_bytes: usize,
}
/// Borrowed caller-owned inputs; short-lived tables/selectors do not own certificates.
/// Construction of this input alone validates nothing.
/// Certificate references cannot gain a longer lifetime through the statement:
/// ```compile_fail
/// use stele_field::QM31;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::lookup::{Layout, Statement, Table};
/// fn escape<'a>(table: &'a Table, selector: &'a [u8], layouts: &'a [Layout],
///     originals: &'a [&'a VerifiedCertificate<QM31>]) -> Statement<'a, 'static, QM31> {
///     Statement { id: 7, m: 0, b: 0, table, selector, originals, multiplicities: layouts }
/// }
/// ```
#[derive(Clone, Copy)]
pub struct Statement<'input, 'cert, K: ChallengeField> {
    /// Lookup identity below 2^60.
    pub id: u64,
    /// Original hypercube depth, at most 59.
    pub m: u8,
    /// Characteristic-safe ordinary group exponent.
    pub b: u8,
    /// Actual definition-generated Table, including its signed integer rows.
    pub table: &'input Table,
    /// Exactly 2^m literal Boolean bytes.
    pub selector: &'input [u8],
    /// Ordered genuine original registration handles, one per Table column.
    pub originals: &'input [&'cert VerifiedCertificate<K>],
    /// One or two expected multiplicity layouts, in repetition order.
    pub multiplicities: &'input [Layout],
}
/// Checked immutable shape and resource policy, never a lookup acceptance record.
/// Base-field challenges are unavailable:
/// ```compile_fail
/// use stele_field::M31;
/// use stele_reductions::lookup::Descriptor;
/// fn invalid(_: Descriptor<'_, '_, M31>) {}
/// ```
pub struct Descriptor<'input, 'cert, K: ChallengeField> {
    statement: Statement<'input, 'cert, K>,
    metadata: EncodedDescriptor,
    mu: [Source<K>; 2],
    pieces: [usize; 2],
    tree_bytes: [usize; 2],
    leaf_bytes: usize,
    statement_bytes: usize,
    proof_bytes: usize,
    public_bytes: usize,
    local_hashes: u64,
    k: u8,
}
fn sum(values: &[usize]) -> Result<usize, Error> {
    values
        .iter()
        .try_fold(0usize, |s, v| s.checked_add(*v).ok_or(Error::Capacity))
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn addressable<T>(count: usize) -> Result<(), Error> {
    if mul(count, size_of::<T>())? > isize::MAX as usize {
        return Err(Error::Capacity);
    }
    Ok(())
}
fn tree_size(v: usize, w: usize) -> Result<usize, Error> {
    mul(w, sum(&[2, mul(2, mul(v, v)?)?, mul(3, v)?])?)
}
// Actual A3 bind/layer and A1 instance/round/final payloads (tree.rs, instance.rs).
fn tree_payload(v: usize, units: usize, w: usize) -> Result<usize, Error> {
    let rounds = mul(v, v.saturating_sub(1))? / 2;
    sum(&[
        34,
        mul(w, sum(&[units, 2])?)?,
        mul(v, sum(&[126, mul(11, w)?])?)?,
        mul(rounds, sum(&[12, mul(5, w)?])?)?,
    ])
}
// Actual SelectedProduct frame and A1 instance/round/final payloads (selected.rs).
fn leaf_payload(m: usize, h: usize, c: usize, w: usize) -> Result<usize, Error> {
    sum(&[
        89,
        mul(29, c)?,
        mul(12, m)?,
        mul(w, sum(&[h, mul(5, m)?, mul(2, c)?, 7])?)?,
    ])
}
fn mu_source<K: ChallengeField>(layout: Layout, k: u8, root: [u8; 32]) -> Result<Source<K>, Error> {
    if layout.ell > k || !matches!(layout.blowup, 1 | 2) {
        return Err(Error::Statement);
    }
    let columns = k
        .checked_sub(layout.ell)
        .and_then(|v| v.checked_add(K::DEGREE.trailing_zeros() as u8))
        .ok_or(Error::Capacity)?;
    Source::new(layout.id, layout.ell, columns, layout.blowup, root).map_err(Error::Pcs)
}
fn opening_cost<K: ChallengeField>(source: &Source<K>) -> Result<(usize, u64), Error> {
    // Actual verifier coefficient/row/encoder allocations; no message matrix is built.
    for count in [
        source.rows(),
        source.columns(),
        source.code().codeword_len(),
    ] {
        addressable::<K>(count)?;
    }
    let frame = source.opening_frame_size().map_err(Error::Pcs)?;
    let proof = source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
    addressable::<u8>(frame)?;
    addressable::<u8>(proof)?;
    let hashes = u64::from(source.queries(ProofKind::Opening))
        .checked_mul(1 + source.path_height() as u64)
        .ok_or(Error::Capacity)?;
    Ok((
        sum(&[frame, proof.checked_sub(1).ok_or(Error::Capacity)?])?,
        hashes,
    ))
}
impl<'input, 'cert, K: ChallengeField> Descriptor<'input, 'cert, K> {
    /// Validate immutable expected data and all known verifier sizes without hashing.
    /// Dense producer storage is not allocated or admitted by this constructor.
    pub fn new(s: Statement<'input, 'cert, K>, limits: Limits) -> Result<Self, Error> {
        let r = s.multiplicities.len();
        if s.id >= 1 << 60 || s.m > 59 || !(1..=2).contains(&r) {
            return Err(Error::Statement);
        }
        if s.b > s.m.min(30) {
            return Err(Error::GroupBound);
        }
        let positions = 1u64.checked_shl(u32::from(s.m)).ok_or(Error::Capacity)?;
        if positions > limits.positions {
            return Err(Error::ResourceLimit);
        }
        let n_positions = usize::try_from(positions).map_err(|_| Error::Capacity)?;
        // SelectedProduct converts sigma and builds full equality scratch even in verify.
        addressable::<K>(n_positions)?;
        if s.selector.len() != n_positions {
            return Err(Error::Selector);
        }
        let shape = s.table.descriptor().shape();
        let (t, n, c) = (
            shape.rows() as usize,
            shape.padded() as usize,
            usize::from(shape.columns()),
        );
        if !(1..=65536).contains(&t)
            || t.checked_next_power_of_two() != Some(n)
            || !(1..=2).contains(&c)
        {
            return Err(Error::Statement);
        }
        if s.originals.len() != c {
            return Err(Error::SourceRoster);
        }
        let k = n.trailing_zeros() as u8;
        let first = mu_source::<K>(s.multiplicities[0], k, [0; 32])?;
        let mut mu = [first; 2]; // Unused second slot is never exposed as a repetition.
        let mut ids = [0; 4];
        for (i, certificate) in s.originals.iter().enumerate() {
            let source = certificate.record().source();
            if mul(source.rows(), source.columns())? != n_positions {
                return Err(Error::SourceRoster);
            }
            ids[i] = source.descriptor().id;
        }
        for (j, layout) in s.multiplicities.iter().enumerate() {
            mu[j] = mu_source::<K>(*layout, k, [0; 32])?;
            ids[c + j] = layout.id;
        }
        if ids[..c + r]
            .iter()
            .enumerate()
            .any(|(i, id)| *id < 2 || ids[..i].contains(id))
        {
            return Err(Error::SourceRoster);
        }
        let metadata = s.table.descriptor().encode().map_err(Error::Table)?;
        let cells = mul(n, c)?;
        if s.table.entries().len() != cells {
            return Err(Error::Statement);
        }
        // RFC-0021 §4 canonical Table data: prefix, identity, rows/padded/width, i32 cells.
        let data_bytes = sum(&[b"stele/v0.1/table/data".len(), 32, 9, mul(4, cells)?])?;
        u32::try_from(metadata.as_bytes().len()).map_err(|_| Error::Capacity)?;
        u32::try_from(data_bytes).map_err(|_| Error::Capacity)?;
        let statement_bytes = sum(&[
            35,
            metadata.as_bytes().len(),
            data_bytes,
            n_positions,
            mul(137, c)?,
            mul(10, r)?,
        ])?;
        let (m, h, w) = (usize::from(s.m), usize::from(s.m - s.b), 4 * K::DEGREE);
        let tree_bytes = [tree_size(m, w)?, tree_size(usize::from(k), w)?];
        let leaf_bytes = mul(w, sum(&[mul(4, m)?, c, 2])?)?;
        let mut repetition_bytes = sum(&[tree_bytes[0], tree_bytes[1], leaf_bytes])?;
        let mut repetition_payload = sum(&[
            tree_payload(m, h, w)?,
            tree_payload(usize::from(k), 0, w)?,
            leaf_payload(m, h, c, w)?,
        ])?;
        let mut original_hashes = 0u64;
        for certificate in s.originals {
            let source = certificate.record().source();
            let (payload, hashes) = opening_cost(source)?;
            repetition_bytes = sum(&[
                repetition_bytes,
                source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?,
            ])?;
            repetition_payload = sum(&[repetition_payload, payload])?;
            original_hashes = original_hashes.checked_add(hashes).ok_or(Error::Capacity)?;
        }
        let mut proof_bytes = sum(&[2, mul(r, repetition_bytes)?])?;
        // Units, Multiplicities and both Repetition phases, native-lookup §4.
        let mut public_bytes = sum(&[
            statement_bytes,
            9,
            mul(167, r)?,
            mul(r, repetition_payload)?,
        ])?;
        let mut local_hashes = original_hashes
            .checked_mul(r as u64)
            .and_then(|v| v.checked_add(1 + r as u64))
            .ok_or(Error::Capacity)?;
        let mut pieces = [0; 2];
        for j in 0..r {
            let columns = mu[j].columns() / K::DEGREE;
            pieces[j] = usize::from(t / columns > 0) + usize::from(t % columns > 0);
            let p = pieces[j];
            let (payload, hashes) = opening_cost(&mu[j])?;
            let certificate = mu[j]
                .proof_size(ProofKind::Certificate)
                .map_err(Error::Pcs)?;
            let opening = mu[j].proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
            proof_bytes = sum(&[proof_bytes, 32, certificate, mul(p, sum(&[w, opening])?)?])?;
            let claims = sum(&[10, mul(w, usize::from(k) + 1)?, mul(p, 1 + w)?])?;
            public_bytes = sum(&[public_bytes, claims, mul(p, payload)?])?;
            local_hashes = hashes
                .checked_mul(p as u64)
                .and_then(|v| v.checked_add(local_hashes))
                .ok_or(Error::Capacity)?;
        }
        addressable::<u8>(statement_bytes)?;
        addressable::<u8>(proof_bytes)?;
        if public_bytes > limits.public_bytes || proof_bytes > limits.proof_bytes {
            return Err(Error::ResourceLimit);
        }
        if s.selector.iter().any(|v| *v > 1) {
            return Err(Error::Selector);
        }
        Ok(Self {
            statement: s,
            metadata,
            mu,
            pieces,
            tree_bytes,
            leaf_bytes,
            statement_bytes,
            proof_bytes,
            public_bytes,
            local_hashes,
            k,
        })
    }
    /// Exact expected statement bytes, including canonical signed Table encodings.
    pub fn statement_size(&self) -> usize {
        self.statement_bytes
    }
    /// Exact complete untrusted proof length, including every structural piece.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes
    }
    /// Inclusive cumulative absorb-payload bound defined by Limits::public_bytes.
    pub fn public_bytes(&self) -> usize {
        self.public_bytes
    }
    /// Checked §5 local-H execution bound, never a receipt of work already performed.
    pub fn max_local_hashes(&self) -> u64 {
        self.local_hashes
    }
    /// Derive an unauthenticated expected mu context with the supplied packet root.
    pub fn multiplicity_source(&self, j: usize, root: [u8; 32]) -> Result<Source<K>, Error> {
        let layout = self
            .statement
            .multiplicities
            .get(j)
            .ok_or(Error::Statement)?;
        mu_source(*layout, self.k, root)
    }
    /// Serialize the complete statement and retain the actual ordinary-hash prefix.
    /// The same immutable Table's size/descriptor checks were established by new().
    pub fn encode(&self, hashes: &mut HashUsage) -> Result<Vec<u8>, Error> {
        let s = &self.statement;
        let mut out = Vec::new();
        out.try_reserve_exact(self.statement_bytes)
            .map_err(|_| Error::Capacity)?;
        hashes.hash_evaluations = hashes
            .hash_evaluations
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let data = s.table.encode().map_err(Error::Table)?;
        out.extend_from_slice(&[1, K::DEGREE as u8]);
        out.extend_from_slice(&s.id.to_le_bytes());
        out.extend_from_slice(&[
            s.m,
            s.b,
            s.multiplicities.len() as u8,
            s.originals.len() as u8,
        ]);
        out.extend_from_slice(&s.table.descriptor().shape().rows().to_le_bytes());
        out.push(self.k);
        for bytes in [self.metadata.as_bytes(), &data] {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&(s.selector.len() as u64).to_le_bytes());
        out.extend_from_slice(s.selector);
        for certificate in s.originals {
            out.extend_from_slice(&certificate.record().source().bytes());
            out.extend_from_slice(&certificate.record().id());
        }
        for layout in s.multiplicities {
            out.extend_from_slice(&layout.id.to_le_bytes());
            out.extend_from_slice(&[layout.ell, layout.blowup]);
        }
        Ok(out)
    }
    /// Check untrusted wire shape and canonical scalar regions without allocation/hash.
    /// Does not authenticate responses, compare packet identities to mu handles, verify
    /// equations or accept lookup membership. Actual A9 consumers decode columns later.
    pub fn preflight(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != self.proof_bytes || bytes.get(..2) != Some(&[1, K::DEGREE as u8]) {
            return Err(Error::ProofShape);
        }
        let mut rest = &bytes[2..];
        let r = self.statement.multiplicities.len();
        for source in &self.mu[..r] {
            take(&mut rest, 32)?; // Root bytes have no canonical-field restriction.
            source
                .parse(
                    ProofKind::Certificate,
                    take(
                        &mut rest,
                        source
                            .proof_size(ProofKind::Certificate)
                            .map_err(Error::Pcs)?,
                    )?,
                )
                .map_err(Error::Pcs)?;
        }
        for j in 0..r {
            for size in [self.tree_bytes[0], self.tree_bytes[1], self.leaf_bytes] {
                canonical(
                    take(&mut rest, size)?,
                    Error::Fraction(fraction::Error::NoncanonicalField),
                )?;
            }
            for certificate in self.statement.originals {
                let source = certificate.record().source();
                source
                    .parse(
                        ProofKind::Opening,
                        take(
                            &mut rest,
                            source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?,
                        )?,
                    )
                    .map_err(Error::Pcs)?;
            }
            canonical(
                take(&mut rest, mul(self.pieces[j], 4 * K::DEGREE)?)?,
                Error::ProofShape,
            )?;
            for _ in 0..self.pieces[j] {
                self.mu[j]
                    .parse(
                        ProofKind::Opening,
                        take(
                            &mut rest,
                            self.mu[j]
                                .proof_size(ProofKind::Opening)
                                .map_err(Error::Pcs)?,
                        )?,
                    )
                    .map_err(Error::Pcs)?;
            }
        }
        if !rest.is_empty() {
            return Err(Error::ProofShape);
        }
        Ok(())
    }
}
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    let out = bytes.get(..count).ok_or(Error::ProofShape)?;
    *bytes = &bytes[count..];
    Ok(out)
}
fn canonical(bytes: &[u8], error: Error) -> Result<(), Error> {
    for limb in bytes.chunks_exact(4) {
        if M31::from_le_bytes(limb.try_into().map_err(|_| error)?).is_none() {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "lookup_sizes_tests.rs"]
mod sizes_tests;

#[path = "lookup_producer.rs"]
mod producer;
pub use producer::{ProducerLimits, ProverFailure, ProverUsage, RegistrationUsage};
