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
pub struct BatchExecution<'a, K>(&'a dyn Arithmetic<K>);

impl<'a, K: ChallengeField + CodeField + Eq> BatchExecution<'a, K> {
    /// Wrap the field session used for this proof attempt.
    pub fn new<B: Backend<K>>(session: &'a B) -> Self {
        Self(session)
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
        self.0.prove(i, source, claims, gammas, mask, binding, t)
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
        let count = geometry.word_count().map_err(|_| Error::Statement)? / 2;
        if count.ilog2() != i.num_vars {
            return Err(Error::Statement);
        }
        let original = self
            .original(geometry, source.message())
            .map_err(|_| Error::Backend)?;
        let claims: Vec<_> = claims
            .iter()
            .zip(gammas)
            .map(|(c, &gamma)| WeightedClaim {
                weights: &c.weights,
                value: c.value,
                gamma,
            })
            .collect();
        let (state, value) = self
            .dense_batch(geometry, &original, &claims)
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
