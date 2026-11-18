//! RFC-0014 A6. Pair lookup visits by their original draws and retain one tree until its last use.
use super::{Original, Registry, Sources};
use crate::zk::claims::{
    gkr_backend::{prove_fields, Expand},
    Error,
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
use stele_field::QM31;
use stele_hash::{ChallengeField, Transcript};
use stele_kernels::{
    gkr::GkrConstruction,
    lookup::{Input, Key, LookupBackend, Visit},
    HidingBackend,
};
use stele_sumcheck::{
    masked::{Mask, Proof},
    Instance,
};

pub(in crate::zk::claims) trait TreeFactory<K> {
    fn begin_trees(&self) -> Rc<dyn Sources<'_, K> + '_>;
}

pub(in crate::zk::claims) trait Trees<K> {
    fn top(&self, input: &Input<'_, K>) -> Result<Vec<[K; 2]>, Error>;
    fn rebuild(&self, input: &Input<'_, K>) -> Result<(), Error>;
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        key: Key<K>,
        last: bool,
        i: &Instance<K>,
        input: &GkrConstruction<'_, K>,
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
        expand: &Expand<'_, K>,
    ) -> Result<(Proof<K>, Vec<K>), Error>
    where
        K: ChallengeField;
}

struct Live<'s, B: HidingBackend + LookupBackend + 's> {
    backend: &'s B,
    originals: Rc<RefCell<Vec<Original<'s, B>>>>,
    // A top can authorize at most one rebuild in this proof attempt.
    tops: RefCell<Vec<Option<Key>>>,
    tree: RefCell<Option<B::Tree<'s>>>,
}

impl<B: HidingBackend + LookupBackend> TreeFactory<QM31> for B {
    fn begin_trees(&self) -> Rc<dyn Sources<'_, QM31> + '_> {
        let originals = Rc::default();
        Rc::new(Registry {
            backend: self,
            originals: Rc::clone(&originals),
            active: RefCell::default(),
            trees: Some(Box::new(Live {
                backend: self,
                originals,
                tops: RefCell::default(),
                tree: RefCell::default(),
            })),
        })
    }
}

impl<B: HidingBackend + LookupBackend> Trees<QM31> for Live<'_, B> {
    fn top(&self, input: &Input<'_>) -> Result<Vec<[QM31; 2]>, Error> {
        let mut tops = self.tops.borrow_mut();
        if input.key.id != tops.len() as u64 || self.tree.borrow().is_some() {
            return Err(Error::Backend);
        }
        let owners = self.originals.borrow();
        let originals = owners.iter().map(|o| &o.original).collect::<Vec<_>>();
        let pairs = self
            .backend
            .lookup_top(input, &originals)
            .map_err(|_| Error::Backend)?;
        if pairs.len()
            != 1usize
                .checked_shl(input.key.top_variables as u32)
                .ok_or(Error::Backend)?
        {
            return Err(Error::Backend);
        }
        tops.push(Some(input.key));
        Ok(pairs)
    }
    fn rebuild(&self, input: &Input<'_>) -> Result<(), Error> {
        let mut tops = self.tops.borrow_mut();
        let top = tops
            .get_mut(usize::try_from(input.key.id).map_err(|_| Error::Backend)?)
            .ok_or(Error::Backend)?;
        let mut tree = self.tree.borrow_mut();
        if *top != Some(input.key) || tree.is_some() {
            return Err(Error::Backend);
        }
        let owners = self.originals.borrow();
        let originals = owners.iter().map(|o| &o.original).collect::<Vec<_>>();
        *tree = Some(
            self.backend
                .lookup_tree(input, &originals)
                .map_err(|_| Error::Backend)?,
        );
        *top = None;
        Ok(())
    }
    fn prove(
        &self,
        key: Key,
        last: bool,
        i: &Instance<QM31>,
        input: &GkrConstruction<'_, QM31>,
        mask: &Mask<QM31>,
        binding: &[u8],
        t: &mut Transcript<QM31>,
        expand: &Expand<'_, QM31>,
    ) -> Result<(Proof<QM31>, Vec<QM31>), Error> {
        if i.num_vars != input.num_vars || mask.degree() != input.degree {
            return Err(Error::Statement);
        }
        let mut tree = self.tree.borrow_mut();
        let visit = if last {
            Visit::Last(tree.take().ok_or(Error::Backend)?)
        } else {
            Visit::Borrow(tree.as_ref().ok_or(Error::Backend)?)
        };
        let state = self
            .backend
            .lookup_gkr(key, visit, input)
            .map_err(|_| Error::Backend)?;
        drop(tree);
        prove_fields::<_, B>(
            i,
            state,
            input.factors.len(),
            mask,
            binding,
            t,
            Some(expand),
        )
    }
}
