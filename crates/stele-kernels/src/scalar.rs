//! RFC-0014 A2 scalar reference for the two original batch factors.
use crate::{Backend, Error, SourceGeometry, WeightedClaim};
use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData};
use stele_field::{Field, M31};

/// A single proof attempt. The session address and its imported ids bind each owner.
#[derive(Default)]
pub struct Scalar<K> {
    ids: RefCell<Vec<u64>>,
    field: PhantomData<K>,
}

impl<K> Scalar<K> {
    pub fn new() -> Self {
        Self {
            ids: RefCell::new(Vec::new()),
            field: PhantomData,
        }
    }
}

pub struct Original<'s, K> {
    session: &'s Scalar<K>,
    geometry: SourceGeometry,
    words: &'s [M31],
}

pub struct Dense<K> {
    weights: Vec<K>,
    face: Vec<K>,
    needs_fold: bool,
}

impl<K: Field> Backend<K> for Scalar<K> {
    type Error = Error;
    type Original<'s>
        = Original<'s, K>
    where
        K: 's;
    type Dense<'s>
        = Dense<K>
    where
        K: 's;

    fn original<'s>(
        &'s self,
        geometry: SourceGeometry,
        words: &'s [M31],
    ) -> Result<Original<'s, K>, Error> {
        if words.len() != geometry.word_count()? {
            return Err(Error::Shape);
        }
        let mut ids = self.ids.borrow_mut();
        if ids.contains(&geometry.id) {
            return Err(Error::DuplicateSource);
        }
        ids.try_reserve(1).map_err(|_| Error::Capacity)?;
        ids.push(geometry.id);
        Ok(Original {
            session: self,
            geometry,
            words,
        })
    }

    fn dense_batch<'s>(
        &'s self,
        geometry: SourceGeometry,
        original: &'s Original<'_, K>,
        claims: &[WeightedClaim<'_, K>],
    ) -> Result<(Dense<K>, K), Error> {
        if !core::ptr::eq(self, original.session) || original.geometry != geometry {
            return Err(Error::Source);
        }
        let half = geometry.word_count()? / 4;
        let len = 2 * half;
        let zero = K::from_i64(0);
        let mut weights = Vec::new();
        weights
            .try_reserve_exact(len)
            .map_err(|_| Error::Capacity)?;
        weights.resize(len, zero);
        let mut value = zero;
        for claim in claims {
            value = value + claim.gamma * claim.value;
            for &(position, coefficient) in claim.weights {
                let w = weights[..half].get_mut(position).ok_or(Error::Shape)?;
                *w = *w + claim.gamma * coefficient;
            }
        }
        let mut face = Vec::new();
        face.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        for row in original.words.chunks_exact(geometry.columns) {
            face.extend(
                row[..geometry.columns / 2]
                    .iter()
                    .map(|x| K::from_i64(i64::from(x.as_u32()))),
            );
        }
        Ok((
            Dense {
                weights,
                face,
                needs_fold: false,
            },
            value,
        ))
    }

    fn dense_round<'s>(state: &mut Self::Dense<'s>) -> Result<[K; 3], Error>
    where
        Self: 's,
    {
        if state.weights.len() < 2 || state.needs_fold {
            return Err(Error::Phase);
        }
        let half = state.weights.len() / 2;
        let mut out = [K::from_i64(0); 3];
        for j in 0..half {
            let (w0, w1) = (state.weights[j], state.weights[half + j]);
            let (v0, v1) = (state.face[j], state.face[half + j]);
            out[0] = out[0] + w0 * v0;
            out[1] = out[1] + w1 * v1;
            out[2] = out[2] + (w1 + (w1 - w0)) * (v1 + (v1 - v0));
        }
        state.needs_fold = true;
        Ok(out)
    }

    fn dense_fold<'s>(state: &mut Self::Dense<'s>, point: K) -> Result<(), Error>
    where
        Self: 's,
    {
        if !state.needs_fold {
            return Err(Error::Phase);
        }
        let half = state.weights.len() / 2;
        for factor in [&mut state.weights, &mut state.face] {
            let (lo, hi) = factor.split_at_mut(half);
            for (a, b) in lo.iter_mut().zip(hi) {
                *a = *a + point * (*b - *a);
            }
            factor.truncate(half);
        }
        state.needs_fold = false;
        Ok(())
    }

    fn dense_finals<'s>(state: &Self::Dense<'s>) -> Result<[K; 2], Error>
    where
        Self: 's,
    {
        if state.weights.len() != 1 {
            return Err(Error::Phase);
        }
        Ok([state.weights[0], state.face[0]])
    }
}
