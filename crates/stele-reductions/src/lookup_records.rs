//! RFC-0008 A5 §§3,5: private conditional results retaining every actual obligation.
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_lookup::fraction::{LeafReduction, Reduction};
use stele_pcs::OpeningRecord;

/// Descriptive fixed parameters; constructing this metadata certifies nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupParameters {
    /// Expected lookup identity.
    pub id: u64,
    /// Canonical extension degree d.
    pub degree: u8,
    /// Original position count N.
    pub positions: u64,
    /// Real Table row count t.
    pub table_rows: u32,
    /// Original/Table tuple width c.
    pub columns: u8,
    /// Static characteristic-safe group exponent b.
    pub group_bits: u8,
    /// Unit-vector length h=m-b.
    pub unit_bits: u8,
    /// Independent identity exponent r; no profile admission follows.
    pub repetitions: u8,
    /// Joint identity numerator h+N+c*t-1 over |K|, before clipping and exponent r.
    pub identity_numerator: u64,
}
/// Actual tree, selected-product and ordered opening records for one repetition.
pub struct RepetitionRecord<'cert, K: ChallengeField> {
    pub(super) lookup: Reduction<K>,
    pub(super) table: Reduction<K>,
    pub(super) selected: LeafReduction<K>,
    pub(super) originals: Vec<OpeningRecord<'cert, K>>,
    pub(super) multiplicities: Vec<OpeningRecord<'cert, K>>,
}
impl<K: ChallengeField> RepetitionRecord<'_, K> {
    /// Actual grouped A3 point, claims, scoped SC records and Gamma/Fold counts.
    pub fn lookup_tree(&self) -> &Reduction<K> {
        &self.lookup
    }
    /// Actual ordinary Table A3 result, including all its separate loss terms.
    pub fn table_tree(&self) -> &Reduction<K> {
        &self.table
    }
    /// Actual A3 selected-product result; every original has been consumed.
    pub fn selected_product(&self) -> &LeafReduction<K> {
        &self.selected
    }
    /// Ordered actual original openings, including unused/zero-factor columns.
    pub fn originals(&self) -> &[OpeningRecord<'_, K>] {
        &self.originals
    }
    /// Ordered structural piece openings, retaining their genuine certificate losses.
    pub fn multiplicities(&self) -> &[OpeningRecord<'_, K>] {
        &self.multiplicities
    }
}
/// Complete conditional lookup result; parsing or registration cannot construct it.
/// No integer/source/plan ownership, Q12, ZK or profile follows. Fields are private:
/// ```compile_fail
/// use stele_field::QM31;
/// let fake = stele_reductions::lookup::LookupRecord::<QM31>::from_digest([0;32]);
/// ```
/// An original certificate cannot be local to the call returning the record:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::lookup::{Descriptor, Layout, Limits, LookupRecord, Statement, Table};
/// fn escape(c: VerifiedCertificate<QM31>, mu: &[&'static VerifiedCertificate<QM31>],
///     table: &Table, t: &mut Transcript<QM31>, proof: &[u8]) -> LookupRecord<'static, QM31> {
///     let originals = [&c];
///     let layouts = [Layout { id:20, ell:0, blowup:1 }];
///     let d = Descriptor::new(Statement {id:7,m:0,b:0,table,selector:&[1],
///         originals:&originals,multiplicities:&layouts}, Limits {
///         positions:1,public_bytes:usize::MAX,proof_bytes:usize::MAX}).unwrap();
///     d.verify(t, mu, proof).unwrap().0
/// }
/// ```
/// Every multiplicity certificate also owns the record's lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::lookup::{Descriptor, LookupRecord};
/// fn escape(d: &Descriptor<'_, 'static, QM31>, mu: VerifiedCertificate<QM31>,
///     t: &mut Transcript<QM31>, proof: &[u8]) -> LookupRecord<'static, QM31> {
///     d.verify(t, &[&mu], proof).unwrap().0
/// }
/// ```
#[must_use = "retain joint identity, actual A3 losses and every certificate/opening obligation"]
pub struct LookupRecord<'cert, K: ChallengeField> {
    pub(super) parameters: LookupParameters,
    pub(super) repetitions: Vec<RepetitionRecord<'cert, K>>,
}
impl<K: ChallengeField> LookupRecord<'_, K> {
    /// Immutable statement and identity parameters; no probability float or profile sum.
    pub fn parameters(&self) -> &LookupParameters {
        &self.parameters
    }
    /// Actual obligations in the complete prescribed repetition order.
    pub fn repetitions(&self) -> &[RepetitionRecord<'_, K>] {
        &self.repetitions
    }
}
