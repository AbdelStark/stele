//! RFC-0008 A7 / RFC-0014 §6: genuine CPU GKR references, behind `bench`.
//! No new advice or virtual columns; output uniqueness is the unchanged A7
//! reduction and authenticated claim batches. Observations carry private witness
//! material, never public inventory. They cannot supply values to the proof.
use super::{
    bench::Masked, lookup, Claim, Error, Instance, Lifetime, ModelSecret, Occurrences, Proof, Seed,
    Statement,
};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::CodeField;

pub use lookup::construction::{GkrConstruction, GkrFactor, GkrMask, GkrMember, GkrSelector};

pub(super) type Observer<'a, K> = dyn FnMut(&GkrCase<'_, K>) -> Result<(), Error> + 'a;

/// A genuine CPU step after its rounds and public aborts, before its claims leave.
/// All references are read-only and expire before the next step. The observer
/// chooses whether to rebuild factors; that extra work is benchmark overhead.
pub struct GkrCase<'a, K> {
    /// Step index in the complete proof, across lookups.
    pub step: usize,
    /// Lookup index in the statement.
    pub lookup: usize,
    /// Whether this step consumes the committed top.
    pub first: bool,
    /// Whether this step consumes member columns and the public table.
    pub leaf: bool,
    /// The genuine expanded instance, not the compact producer's term list.
    pub instance: &'a Instance<K>,
    /// Actual sumcheck challenges, in MSB-first binding order.
    pub point: &'a [K],
    /// Actual expanded final values sent by the ordinary CPU prover.
    pub finals: &'a [K],
    /// Actual production claim routing; cloning this receipt is observation work.
    pub routed: GkrClaims<K>,
    pub(super) build: &'a dyn Fn() -> Result<Occurrences<K>, Error>,
    pub(super) construct: &'a dyn Fn() -> Result<GkrConstruction<'a, K>, Error>,
    #[allow(clippy::type_complexity)]
    pub(super) route: &'a dyn Fn(&[K]) -> Result<GkrClaims<K>, Error>,
}

/// A7's source claims, shared mask-block claims and next-layer child values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GkrClaims<K> {
    /// Source index and the linear claim in the source's data-message coordinates.
    pub sources: Vec<(usize, Claim<K>)>,
    /// Linear claims on the shared mask source.
    pub blocks: Vec<Claim<K>>,
    /// `[[p(0), p(1)], [q(0), q(1)]]` for the next line fold.
    pub children: [[K; 2]; 2],
}

impl<K> From<lookup::Finals<K>> for GkrClaims<K> {
    fn from(value: lookup::Finals<K>) -> Self {
        Self {
            sources: value.claims,
            blocks: value.blocks,
            children: value.layers,
        }
    }
}

impl<'a, K: ChallengeField> GkrCase<'a, K> {
    /// Borrow original inputs without materializing full factor tables. Descriptor
    /// and small mask-block copies are host preparation, not device construction.
    /// Returned references expire with this observed step and cannot alter it.
    pub fn construction(&self) -> Result<GkrConstruction<'a, K>, Error> {
        (self.construct)()
    }

    /// Rebuild actual production factors and compact expansion state. No synthetic
    /// shape substitutes for the plan, columns, layer values or claim-mask blocks.
    pub fn reference(&self) -> Result<Masked<K>, Error> {
        (self.build)().map(Masked)
    }

    /// Re-run production public-final checks and claim routing at the actual point.
    /// Non-public claims remain untrusted until their ordinary source openings;
    /// successful routing alone does not authenticate an arbitrary claimed value.
    pub fn route(&self, finals: &[K]) -> Result<GkrClaims<K>, Error> {
        (self.route)(finals)
    }
}

/// Prove with ordinary CPU values while observing each genuine GKR step. This is
/// an explicit research entry point, not a backend: the callback can only return
/// success or an error, which stops the operation. It cannot change the transcript.
/// The optional lifetime and returned disclosure have `prove_lifetime` semantics.
/// Seeds have the same one-proof lifecycle as `claims::prove`; use synthetic data.
#[allow(clippy::type_complexity)]
pub fn observe_gkr<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    transcript: &mut Transcript<K>,
    lifetime: Option<(&Lifetime, ModelSecret<'_, K>)>,
    observer: &mut Observer<'_, K>,
) -> Result<(Proof<K>, Option<Vec<K>>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let requires_disclosure = lifetime.is_some();
    let result = super::prove_observed(
        statement,
        columns,
        &seed.0,
        transcript,
        true,
        None,
        lifetime,
        Some(observer),
    )?;
    // RFC-0013 A6: preserve prove_lifetime's required opening disclosure.
    if requires_disclosure && result.1.is_none() {
        return Err(Error::Statement);
    }
    Ok(result)
}
