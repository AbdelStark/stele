//! RFC-0014 A3. The ordinary checked masked prover consumes the backend's live field state.
use super::Error;
use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData};
use stele_hash::{ChallengeField, Transcript};
use stele_kernels::gkr::{GkrBackend, GkrConstruction};
use stele_sumcheck::{
    masked::{self, Mask},
    Instance, Summand,
};

type Expand<'a, K> = dyn Fn(&[K], &[K]) -> Result<Vec<K>, Error> + 'a;

pub(super) trait Arithmetic<K: ChallengeField> {
    fn prove(
        &self,
        i: &Instance<K>,
        input: &GkrConstruction<'_, K>,
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
        expand: &Expand<'_, K>,
    ) -> Result<(masked::Proof<K>, Vec<K>), Error>;
}

impl<K: ChallengeField + Eq, B: GkrBackend<K>> Arithmetic<K> for B {
    fn prove(
        &self,
        i: &Instance<K>,
        construction: &GkrConstruction<'_, K>,
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
        expand: &Expand<'_, K>,
    ) -> Result<(masked::Proof<K>, Vec<K>), Error> {
        if construction.num_vars != i.num_vars || construction.degree != mask.degree() {
            return Err(Error::Statement);
        }
        let state = self
            .gkr_start(construction)
            .map_err(|_| Error::Sumcheck(stele_sumcheck::Error::Source))?;
        let summand = FieldGkr::<K, B> {
            state: RefCell::new(state),
            remaining: i.num_vars,
            original: i.inputs.len(),
            compact: construction.factors.len(),
            degree: construction.degree,
            point: Vec::new(),
            expand,
            field: PhantomData,
        };
        masked::prove(i, summand, mask, binding, t).map_err(Error::Sumcheck)
    }
}

struct FieldGkr<'a, K: ChallengeField, B: GkrBackend<K> + 'a> {
    state: RefCell<B::Gkr<'a>>,
    remaining: u32,
    original: usize,
    compact: usize,
    degree: usize,
    point: Vec<K>,
    expand: &'a Expand<'a, K>,
    field: PhantomData<B>,
}

impl<K: ChallengeField, B: GkrBackend<K>> Summand<K> for FieldGkr<'_, K, B> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining, self.original)
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        let values = B::gkr_round(&mut self.state.borrow_mut())
            .map_err(|_| stele_sumcheck::Error::Source)?;
        if values.len() != self.degree + 1 {
            return Err(stele_sumcheck::Error::ProofShape);
        }
        Ok(values)
    }
    fn fold(&mut self, point: K) -> Result<(), stele_sumcheck::Error> {
        let next = self
            .remaining
            .checked_sub(1)
            .ok_or(stele_sumcheck::Error::PublicShape)?;
        B::gkr_fold(self.state.get_mut(), point).map_err(|_| stele_sumcheck::Error::Source)?;
        self.point.push(point);
        self.remaining = next;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if self.remaining != 0 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let compact =
            B::gkr_finals(&self.state.borrow()).map_err(|_| stele_sumcheck::Error::Source)?;
        if compact.len() != self.compact {
            return Err(stele_sumcheck::Error::ProofShape);
        }
        let values =
            (self.expand)(&self.point, &compact).map_err(|_| stele_sumcheck::Error::Source)?;
        if values.len() != self.original {
            return Err(stele_sumcheck::Error::ProofShape);
        }
        Ok(values)
    }
}
