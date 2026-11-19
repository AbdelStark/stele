//! RFC-0014 A2 and RFC-0013 A5 item 5. The backend supplies field operations to the checked masked prover.
use super::{Claim, Error};
use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData};
use stele_hash::{ChallengeField, Transcript};
use stele_kernels::{Backend, SourceGeometry, WeightedClaim};
use stele_pcs::{CodeField, PreparedSource};
use stele_sumcheck::{
    masked::{self, Mask},
    Instance, Summand,
};

/// The ordinary batch execution selected for one proof attempt (RFC-0014 A2).
/// The caller creates a fresh backend session, even on a reused device context.
#[derive(Clone, Copy)]
pub struct BatchExecution<'a, K> {
    batches: &'a dyn Arithmetic<K>,
    sources: Option<&'a dyn super::source_backend::Factory<K>>,
    trees: Option<&'a dyn super::source_backend::TreeFactory<K>>,
    gkr: Option<&'a dyn super::gkr_backend::Arithmetic<K>>,
    relations: Option<&'a dyn super::gkr_backend::Relations<K>>,
}

impl<'a, K: ChallengeField + CodeField + Eq> BatchExecution<'a, K> {
    /// Wrap the field session used for this proof attempt.
    pub fn new<B: Backend<K>>(session: &'a B) -> Self {
        Self {
            batches: session,
            sources: None,
            trees: None,
            gkr: None,
            relations: None,
        }
    }

    /// Select both live GKR and ordinary batches for this proof attempt (RFC-0014 A3).
    pub fn with_gkr<B: stele_kernels::gkr::GkrBackend<K>>(session: &'a B) -> Self {
        Self {
            batches: session,
            sources: None,
            trees: None,
            gkr: Some(session),
            relations: None,
        }
    }

    /// Select live relation, GKR and ordinary batch operations together (RFC-0014 A4).
    pub fn with_relations<B: stele_kernels::gkr::RelationBackend<K>>(session: &'a B) -> Self {
        Self {
            batches: session,
            sources: None,
            trees: None,
            gkr: Some(session),
            relations: Some(session),
        }
    }

    pub(super) fn begin_sources(self) -> Option<super::source_backend::Session<'a, K>> {
        self.trees
            .map(|session| session.begin_trees())
            .or_else(|| self.sources.map(|session| session.begin()))
    }

    pub(super) fn relations(self) -> Option<&'a dyn super::gkr_backend::Relations<K>> {
        self.relations
    }

    pub(super) fn gkr(self) -> Option<&'a dyn super::gkr_backend::Arithmetic<K>> {
        self.gkr
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prove(
        self,
        i: &Instance<K>,
        source: &PreparedSource<'_, K>,
        claims: &[Claim<K>],
        gammas: &[K],
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
    ) -> Result<(masked::Proof<K>, Vec<K>), Error> {
        self.batches
            .prove(i, source, claims, gammas, mask, binding, t)
    }
}

impl<'a> BatchExecution<'a, stele_kernels::QM31> {
    /// Select lookup trees and all earlier field and source operations on one proof session (A6).
    pub fn with_lookup<B: stele_kernels::lookup::LookupBackend + stele_kernels::HidingBackend>(
        session: &'a B,
    ) -> Self {
        let mut execution = Self::with_relations(session);
        execution.trees = Some(session);
        execution
    }

    /// Use the same proof-local originals for hiding-source visits and ordinary batches (A5).
    pub fn with_sources<B>(session: &'a B) -> Self
    where
        B: stele_kernels::HidingBackend + stele_kernels::gkr::RelationBackend<stele_kernels::QM31>,
    {
        let mut execution = Self::with_relations(session);
        execution.sources = Some(session);
        execution
    }
}

// Private type erasure keeps the full reduction/proof engine independent of a concrete backend.
// Only the field-only Backend trait is implemented by an external caller.
trait Arithmetic<K: ChallengeField + CodeField> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        i: &Instance<K>,
        source: &PreparedSource<'_, K>,
        claims: &[Claim<K>],
        gammas: &[K],
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
    ) -> Result<(masked::Proof<K>, Vec<K>), Error>;
}
impl<K: ChallengeField + CodeField + Eq, B: Backend<K>> Arithmetic<K> for B {
    fn prove(
        &self,
        i: &Instance<K>,
        source: &PreparedSource<'_, K>,
        claims: &[Claim<K>],
        gammas: &[K],
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
    ) -> Result<(masked::Proof<K>, Vec<K>), Error> {
        if !source.source().is_hiding() || claims.len() != gammas.len() {
            return Err(Error::Statement);
        }
        let s = source.source();
        let geometry = SourceGeometry {
            id: s.descriptor().id,
            rows: s.rows(),
            columns: s.columns(),
        };
        let original = self
            .original(geometry, source.message())
            .map_err(|_| Error::Backend)?;
        prove_original(
            self, geometry, &original, i, claims, gammas, mask, binding, t,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prove_original<K: ChallengeField + CodeField + Eq, B: Backend<K>>(
    backend: &B,
    geometry: SourceGeometry,
    original: &B::Original<'_>,
    i: &Instance<K>,
    claims: &[Claim<K>],
    gammas: &[K],
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>), Error> {
    let count = geometry.word_count().map_err(|_| Error::Statement)? / 2;
    if count.ilog2() != i.num_vars || claims.len() != gammas.len() {
        return Err(Error::Statement);
    }
    let claims: Vec<_> = claims
        .iter()
        .zip(gammas)
        .map(|(c, &gamma)| WeightedClaim {
            weights: &c.weights,
            value: c.value,
            gamma,
        })
        .collect();
    let (state, value) = backend
        .dense_batch(geometry, original, &claims)
        .map_err(|_| Error::Backend)?;
    if value != i.claimed_sum {
        return Err(Error::Backend);
    }
    let dense = FieldSummand::<K, B> {
        state: RefCell::new(state),
        remaining: i.num_vars,
        field: PhantomData,
    };
    masked::prove(i, dense, mask, binding, t).map_err(|error| match error {
        stele_sumcheck::Error::Source => Error::Backend,
        other => Error::Sumcheck(other),
    })
}
struct FieldSummand<'s, K: ChallengeField, B: Backend<K> + 's> {
    state: RefCell<B::Dense<'s>>,
    remaining: u32,
    field: PhantomData<K>,
}
impl<K: ChallengeField, B: Backend<K>> Summand<K> for FieldSummand<'_, K, B> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining, 2)
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        B::dense_round(&mut self.state.borrow_mut())
            .map(Vec::from)
            .map_err(|_| stele_sumcheck::Error::Source)
    }
    fn fold(&mut self, point: K) -> Result<(), stele_sumcheck::Error> {
        let remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(stele_sumcheck::Error::InvalidInstance)?;
        B::dense_fold(self.state.get_mut(), point).map_err(|_| stele_sumcheck::Error::Source)?;
        self.remaining = remaining;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        B::dense_finals(&self.state.borrow())
            .map(Vec::from)
            .map_err(|_| stele_sumcheck::Error::Source)
    }
}
