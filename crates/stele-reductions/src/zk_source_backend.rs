//! RFC-0014 A5. One immutable original per hiding source, with one live tree at a time.
use super::{backend::prove_original, certify, face, finish_batch, Batch, Claim, Error};
use alloc::{borrow::Cow, rc::Rc, vec::Vec};
use core::cell::RefCell;
use stele_field::{Serialize, M31, QM31};
use stele_hash::{
    mask::{MaskStream, SOURCE_SALT},
    merkle, ChallengeField, HashUsage, Transcript,
};
use stele_kernels::{HidingBackend, SourceGeometry};
use stele_pcs::{
    CodeField, ColumnMaterial, ColumnResponse, Error as PcsError, HidingUse, PreparedSource,
    Source, VerifiedCertificate,
};
use stele_sumcheck::{
    masked::{Mask, Proof},
    Instance,
};

#[path = "zk_lookup_backend.rs"]
mod lookup;
pub(super) use lookup::TreeFactory;

pub(super) trait Factory<K> {
    fn begin(&self) -> Rc<dyn Sources<'_, K> + '_>;
}

pub(super) trait Sources<'s, K> {
    fn trees(&self) -> Option<&dyn lookup::Trees<K>>;
    fn import(
        &self,
        source: &Source<K>,
        message: &'s [M31],
        seed: &[u8; 32],
        hashes: &mut u64,
    ) -> Result<merkle::Digest, PcsError>
    where
        K: ChallengeField;
    fn reopen(&self, id: u64) -> Result<(), PcsError>;
    fn release(&self);
    fn selected(&self, id: u64, index: u64) -> Result<ColumnResponse<'static>, PcsError>;
    #[allow(clippy::too_many_arguments)]
    fn batch(
        &self,
        source: u64,
        i: &Instance<K>,
        claims: &[Claim<K>],
        gammas: &[K],
        mask: &Mask<K>,
        binding: &[u8],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Vec<K>), Error>
    where
        K: ChallengeField;
}

struct Original<'s, B: HidingBackend + 's> {
    geometry: SourceGeometry,
    descriptor: merkle::Descriptor,
    original: B::Original<'s>,
    seed: [u8; 32],
    root: merkle::Digest,
    reopened: bool,
}

struct Registry<'s, B: HidingBackend + 's> {
    backend: &'s B,
    originals: Rc<RefCell<Vec<Original<'s, B>>>>,
    trees: Option<alloc::boxed::Box<dyn lookup::Trees<QM31> + 's>>,
    active: RefCell<Option<(u64, B::Columns<'s>)>>,
}

impl<B: HidingBackend> Factory<QM31> for B {
    fn begin(&self) -> Rc<dyn Sources<'_, QM31> + '_> {
        Rc::new(Registry {
            backend: self,
            originals: Rc::default(),
            trees: None,
            active: RefCell::default(),
        })
    }
}

impl<'s, B: HidingBackend> Sources<'s, QM31> for Registry<'s, B> {
    fn trees(&self) -> Option<&dyn lookup::Trees<QM31>> {
        self.trees.as_deref()
    }
    fn import(
        &self,
        source: &Source<QM31>,
        message: &'s [M31],
        seed: &[u8; 32],
        hashes: &mut u64,
    ) -> Result<merkle::Digest, PcsError> {
        let descriptor = source.descriptor();
        let geometry = SourceGeometry {
            id: descriptor.id,
            rows: source.rows(),
            columns: source.columns(),
        };
        let mut originals = self.originals.borrow_mut();
        if self.active.borrow().is_some() || originals.iter().any(|o| o.geometry.id == geometry.id)
        {
            return Err(PcsError::CertificateContext);
        }
        let original = self
            .backend
            .original(geometry, message)
            .map_err(|_| PcsError::MessageShape)?;
        let (tree, root) = self
            .backend
            .prepare_columns(geometry, &original, seed, hashes)
            .map_err(|_| PcsError::MessageShape)?;
        originals.push(Original {
            geometry,
            descriptor,
            original,
            seed: *seed,
            root,
            reopened: false,
        });
        *self.active.borrow_mut() = Some((geometry.id, tree));
        Ok(root)
    }
    fn reopen(&self, id: u64) -> Result<(), PcsError> {
        let mut originals = self.originals.borrow_mut();
        let entry = originals
            .iter_mut()
            .find(|o| o.geometry.id == id)
            .ok_or(PcsError::CertificateContext)?;
        if self.active.borrow().is_some() || entry.reopened {
            return Err(PcsError::CertificateContext);
        }
        entry.reopened = true;
        let mut hashes = 0;
        let (tree, root) = self
            .backend
            .prepare_columns(entry.geometry, &entry.original, &entry.seed, &mut hashes)
            .map_err(|_| PcsError::MessageShape)?;
        let expected = entry
            .descriptor
            .count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(PcsError::Capacity)?;
        if hashes != expected {
            return Err(PcsError::Merkle(merkle::Error::InvalidTree));
        }
        if root != entry.root {
            return Err(PcsError::Merkle(merkle::Error::RootMismatch));
        }
        *self.active.borrow_mut() = Some((id, tree));
        Ok(())
    }
    fn release(&self) {
        self.active.borrow_mut().take();
    }

    fn selected(&self, id: u64, index: u64) -> Result<ColumnResponse<'static>, PcsError> {
        let originals = self.originals.borrow();
        let entry = originals
            .iter()
            .find(|o| o.geometry.id == id)
            .ok_or(PcsError::CertificateContext)?;
        let active = self.active.borrow();
        let (owner, tree) = active.as_ref().ok_or(PcsError::CertificateContext)?;
        if *owner != id || index >= entry.descriptor.count {
            return Err(PcsError::CertificateContext);
        }
        let col = self
            .backend
            .selected_column(
                entry.geometry,
                tree,
                usize::try_from(index).map_err(|_| PcsError::Capacity)?,
            )
            .map_err(|_| PcsError::MessageShape)?;
        if col.symbols.len() != entry.geometry.rows
            || col.siblings.len() != entry.descriptor.count.ilog2() as usize
        {
            return Err(PcsError::ProofShape);
        }
        let mut salt = [0; 32];
        MaskStream::new(&entry.seed, SOURCE_SALT, id)
            .fill_at(index.checked_mul(32).ok_or(PcsError::Capacity)?, &mut salt);
        let mut payload = Vec::with_capacity(
            usize::try_from(entry.descriptor.width).map_err(|_| PcsError::Capacity)?,
        );
        payload.extend_from_slice(&salt);
        for symbol in col.symbols {
            payload.extend_from_slice(&symbol.to_le_bytes());
        }
        Ok((Cow::Owned(payload), col.siblings))
    }

    fn batch(
        &self,
        id: u64,
        i: &Instance<QM31>,
        claims: &[Claim<QM31>],
        gammas: &[QM31],
        mask: &Mask<QM31>,
        binding: &[u8],
        t: &mut Transcript<QM31>,
    ) -> Result<(Proof<QM31>, Vec<QM31>), Error> {
        let originals = self.originals.borrow();
        let entry = originals
            .iter()
            .find(|o| o.geometry.id == id)
            .ok_or(Error::Backend)?;
        prove_original(
            self.backend,
            entry.geometry,
            &entry.original,
            i,
            claims,
            gammas,
            mask,
            binding,
            t,
        )
    }
}

pub(super) struct Selected<'s, K> {
    registry: Rc<dyn Sources<'s, K> + 's>,
    descriptor: merkle::Descriptor,
    root: merkle::Digest,
}
impl<K> ColumnMaterial for Selected<'_, K> {
    fn descriptor(&self) -> merkle::Descriptor {
        self.descriptor
    }
    fn root(&self) -> merkle::Digest {
        self.root
    }
    fn selected(&self, index: u64) -> Result<ColumnResponse<'_>, PcsError> {
        self.registry.selected(self.descriptor.id, index)
    }
}

pub(super) type Session<'s, K> = Rc<dyn Sources<'s, K> + 's>;
pub(super) enum Ready<'s, K: ChallengeField> {
    Host(PreparedSource<'s, K>),
    Device(PreparedSource<'s, K, Selected<'s, K>>, Session<'s, K>),
}
pub(super) type Certified<'s, K> = (Ready<'s, K>, (Vec<u8>, VerifiedCertificate<K>));

pub(super) fn prepare<'s, K: ChallengeField + CodeField>(
    registry: &Session<'s, K>,
    id: u64,
    (ell, m): (u8, u8),
    message: &'s [M31],
    seed: &[u8; 32],
    purpose: HidingUse<K>,
    expected: Option<merkle::Digest>,
) -> Result<Certified<'s, K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let p = PreparedSource::hiding_material(
        id,
        ell,
        m,
        message,
        seed,
        purpose,
        &mut HashUsage::default(),
        |source, message, seed, usage| {
            let root = registry.import(source, message, seed, &mut usage.hash_evaluations)?;
            Ok(Selected {
                registry: registry.clone(),
                descriptor: source.descriptor(),
                root,
            })
        },
    )
    .map_err(Error::Pcs)?;
    if expected.is_some_and(|pin| pin != p.source().root()) {
        return Err(Error::Pcs(PcsError::Merkle(merkle::Error::RootMismatch)));
    }
    // A16 verifies every selected response before the certificate enters the proof.
    let certificate = certify(&p);
    registry.release();
    Ok((Ready::Device(p, registry.clone()), certificate?))
}

impl<K: ChallengeField + CodeField + Eq> Ready<'_, K> {
    pub(super) fn source(&self) -> &Source<K> {
        match self {
            Self::Host(p) => p.source(),
            Self::Device(p, _) => p.source(),
        }
    }
    pub(super) fn face(&self) -> Vec<K> {
        match self {
            Self::Host(p) => face(p),
            Self::Device(p, _) => face(p),
        }
    }
    fn opening_visit<T>(&self, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if let Self::Device(p, registry) = self {
            registry
                .reopen(p.source().descriptor().id)
                .map_err(Error::Pcs)?;
            let result = f();
            registry.release();
            result
        } else {
            f()
        }
    }
    pub(super) fn finish(
        &self,
        id: u64,
        verified: &VerifiedCertificate<K>,
        result: (Proof<K>, Vec<K>),
        t: &mut Transcript<K>,
    ) -> Result<(Batch<K>, Vec<K>), Error> {
        self.opening_visit(|| match self {
            Self::Host(p) => finish_batch(id, p, verified, result, t),
            Self::Device(p, _) => finish_batch(id, p, verified, result, t),
        })
    }
    pub(super) fn open(
        &self,
        t: &mut Transcript<K>,
        verified: &VerifiedCertificate<K>,
        id: u64,
        point: &[K],
        value: K,
    ) -> Result<Vec<u8>, Error> {
        self.opening_visit(|| {
            match self {
                Self::Host(p) => p.opening_point(t, verified, id, point, value),
                Self::Device(p, _) => p.opening_point(t, verified, id, point, value),
            }
            .map(|(opening, _)| opening)
            .map_err(|f| Error::Pcs(f.cause))
        })
    }
}

pub(super) fn host_certificates<'s, K: ChallengeField + CodeField>(
    sources: Vec<PreparedSource<'s, K>>,
) -> Result<Vec<Certified<'s, K>>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let certificates = stele_sumcheck::parallel::map(sources.len(), |i| certify(&sources[i]));
    sources
        .into_iter()
        .zip(certificates)
        .map(|(p, c)| Ok((Ready::Host(p), c?)))
        .collect()
}
