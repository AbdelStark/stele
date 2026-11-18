//! RFC-0014 A2. Dense RFC-0013 A5 batch state, scoped to one proof's original messages.
use crate::packing::{canonical, words, Packed, TILE};
use crate::runtime::{Cuda, Error};
use cudarc::driver::{CudaSlice, LaunchConfig, PushKernelArg};
use std::cell::{Cell, RefCell};
use stele_kernels::{Backend, SourceGeometry, WeightedClaim, M31, QM31};

/// Actual completed device calls in this proof session.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    pub lookup_tops: usize,
    pub lookup_rebuilds: usize,
    pub lookup_child_views: usize,
    pub lookup_child_released: usize,
    pub lookup_uploaded_bytes: u64,
    pub lookup_downloaded_bytes: u64,
    pub lookup_planned_peak_bytes: usize,
    pub lookup_observed_peak_bytes: usize,
    pub originals: usize,
    pub source_visits: usize,
    pub source_responses: usize,
    pub source_hashes: u64,
    pub source_uploaded_bytes: u64,
    pub source_downloaded_bytes: u64,
    pub source_observed_peak_bytes: usize,
    pub batches: usize,
    pub observed_peak_bytes: usize,
    pub expected_rounds: usize,
    pub rounds: usize,
    pub folds: usize,
    pub finals: usize,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub gkr_steps: usize,
    pub gkr_expected_rounds: usize,
    pub gkr_rounds: usize,
    pub gkr_folds: usize,
    pub gkr_finals: usize,
    pub gkr_uploaded_bytes: u64,
    pub gkr_downloaded_bytes: u64,
    pub gkr_layer_source_bytes: u64,
    pub gkr_planned_peak_bytes: usize,
    pub gkr_observed_peak_bytes: usize,
    pub relation_steps: usize,
    pub relation_expected_rounds: usize,
    pub relation_rounds: usize,
    pub relation_folds: usize,
    pub relation_finals: usize,
    pub relation_uploaded_bytes: u64,
    pub relation_downloaded_bytes: u64,
    pub relation_value_bytes: u64,
    pub relation_mask_bytes: u64,
    pub relation_planned_peak_bytes: usize,
    pub relation_observed_peak_bytes: usize,
}

/// The source registry lasts for exactly one proof attempt.
pub struct Session<'d> {
    pub(crate) device: &'d Cuda,
    ids: RefCell<Vec<u64>>,
    counts: Cell<Counts>,
}
impl Cuda {
    /// Begin a fresh session for a single proof, sharing only the compiled device context.
    pub fn session(&self) -> Session<'_> {
        Session {
            device: self,
            ids: RefCell::new(Vec::new()),
            counts: Cell::new(Counts::default()),
        }
    }
}
impl Session<'_> {
    pub fn counts(&self) -> Counts {
        self.counts.get()
    }
    pub(crate) fn record(&self, update: impl FnOnce(&mut Counts)) {
        let mut counts = self.counts.get();
        update(&mut counts);
        self.counts.set(counts);
    }
}
pub struct Original<'s, 'd> {
    session: &'s Session<'d>,
    geometry: SourceGeometry,
    words: CudaSlice<u32>,
}
impl Original<'_, '_> {
    pub(crate) fn checked_words(
        &self,
        session: &Session<'_>,
        geometry: SourceGeometry,
    ) -> Result<&CudaSlice<u32>, Error> {
        if !std::ptr::eq(session, self.session) || geometry != self.geometry {
            return Err(Error::Source);
        }
        Ok(&self.words)
    }
}

enum Face {
    Base(CudaSlice<u32>),
    Ext(CudaSlice<[u32; 4]>),
}
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Round,
    Fold,
    Poisoned,
}
pub struct Dense<'s, 'd> {
    session: &'s Session<'d>,
    weights: CudaSlice<[u32; 4]>,
    face: Face,
    partials: CudaSlice<[u32; 4]>,
    polynomial: CudaSlice<[u32; 4]>,
    len: usize,
    phase: Phase,
}

impl<'d> Backend<QM31> for Session<'d> {
    type Error = Error;
    type Original<'s>
        = Original<'s, 'd>
    where
        Self: 's;
    type Dense<'s>
        = Dense<'s, 'd>
    where
        Self: 's;

    fn original<'s>(
        &'s self,
        geometry: SourceGeometry,
        words: &'s [M31],
    ) -> Result<Original<'s, 'd>, Error> {
        if geometry.word_count().map_err(|_| Error::Geometry)? != words.len() {
            return Err(Error::Geometry);
        }
        let mut ids = self.ids.borrow_mut();
        if ids.contains(&geometry.id) {
            return Err(Error::Source);
        }
        ids.try_reserve(1).map_err(|_| Error::Budget)?;
        let bytes = words.len().checked_mul(4).ok_or(Error::Budget)?;
        let _guard = self.device.allocation(bytes)?;
        let stream = &self.device.stream;
        let mut device_words = stream.alloc_zeros(words.len())?;
        let mut staging = Vec::with_capacity(words.len().min(1 << 20));
        for (i, chunk) in words.chunks(1 << 20).enumerate() {
            staging.clear();
            staging.extend(chunk.iter().map(|w| w.as_u32()));
            let start = i * (1 << 20);
            self.device.complete_transfer(stream.memcpy_htod(
                &staging,
                &mut device_words.slice_mut(start..start + chunk.len()),
            ))?;
        }
        let peak = self.device.check_peak()?;
        ids.push(geometry.id);
        self.record(|c| {
            c.observed_peak_bytes = c.observed_peak_bytes.max(peak);
            c.originals += 1;
            c.uploaded_bytes += bytes as u64
        });
        Ok(Original {
            session: self,
            geometry,
            words: device_words,
        })
    }

    fn dense_batch<'s>(
        &'s self,
        geometry: SourceGeometry,
        original: &'s Self::Original<'_>,
        claims: &[WeightedClaim<'_, QM31>],
    ) -> Result<(Dense<'s, 'd>, QM31), Error> {
        if !std::ptr::eq(self, original.session) || geometry != original.geometry {
            return Err(Error::Source);
        }
        let len = original.words.len() / 2;
        let packed = Packed::new(claims, len / 2)?;
        self.build_dense(original, packed)
    }

    fn dense_round<'s>(state: &mut Self::Dense<'s>) -> Result<[QM31; 3], Error>
    where
        Self: 's,
    {
        if state.len < 2 || state.phase != Phase::Round {
            return Err(Error::Phase);
        }
        state.phase = Phase::Poisoned;
        let device = state.session.device;
        let stream = &device.stream;
        let half = (state.len / 2) as u64;
        let grid = device.grid(state.len / 2);
        let base = u32::from(matches!(state.face, Face::Base(_)));
        let kernel = device.kernel("dense_round")?;
        let mut launch = stream.launch_builder(&kernel);
        launch.arg(&state.weights);
        match &state.face {
            Face::Base(data) => launch.arg(data),
            Face::Ext(data) => launch.arg(data),
        };
        launch.arg(&base).arg(&half).arg(&mut state.partials);
        // SAFETY: each live factor covers 2*half values; 3 partials per original block are allocated.
        unsafe { launch.launch(grid) }?;
        let kernel = device.kernel("reduce_kernel")?;
        let mut launch = stream.launch_builder(&kernel);
        let blocks = grid.grid_dim.0 as i32;
        let nodes = 3i32;
        launch
            .arg(&state.partials)
            .arg(&blocks)
            .arg(&nodes)
            .arg(&mut state.polynomial);
        // SAFETY: the three threads read initialized partials and each writes a distinct output.
        unsafe {
            launch.launch(LaunchConfig {
                grid_dim: (1, 1, 1),
                block_dim: (3, 1, 1),
                shared_mem_bytes: 0,
            })
        }?;
        let mut result = [[0u32; 4]; 3];
        device.complete_transfer(stream.memcpy_dtoh(&state.polynomial, &mut result[..]))?;
        let [a, b, c] = result;
        let result = [canonical(a)?, canonical(b)?, canonical(c)?];
        state.phase = Phase::Fold;
        state.session.record(|c| {
            c.rounds += 1;
            c.downloaded_bytes += 48
        });
        Ok(result)
    }

    fn dense_fold<'s>(state: &mut Self::Dense<'s>, point: QM31) -> Result<(), Error>
    where
        Self: 's,
    {
        if state.phase != Phase::Fold || state.len < 2 {
            return Err(Error::Phase);
        }
        state.phase = Phase::Poisoned;
        let device = state.session.device;
        let stream = &device.stream;
        let half = state.len / 2;
        let count = half as u64;
        let [a, b, c, d] = words(point);
        let grid = device.grid(half);
        let fold = device.kernel("fold_ext")?;
        let mut launch = stream.launch_builder(&fold);
        launch
            .arg(&mut state.weights)
            .arg(&count)
            .arg(&a)
            .arg(&b)
            .arg(&c)
            .arg(&d);
        // SAFETY: 2*half initialized values; each pair folds into its unique lower element.
        unsafe { launch.launch(grid) }?;
        match &mut state.face {
            Face::Ext(face) => {
                let mut launch = stream.launch_builder(&fold);
                launch.arg(face).arg(&count).arg(&a).arg(&b).arg(&c).arg(&d);
                // SAFETY: the extension face has the same live length and pairing as weights.
                unsafe { launch.launch(grid) }?;
            }
            Face::Base(face) => {
                let _guard = device.allocation(half.checked_mul(16).ok_or(Error::Budget)?)?;
                let mut promoted = stream.alloc_zeros::<[u32; 4]>(half)?;
                let kernel = device.kernel("fold_base")?;
                let mut launch = stream.launch_builder(&kernel);
                launch
                    .arg(&*face)
                    .arg(&mut promoted)
                    .arg(&count)
                    .arg(&a)
                    .arg(&b)
                    .arg(&c)
                    .arg(&d);
                // SAFETY: the base face has 2*half limbs and promoted has half extension elements.
                unsafe { launch.launch(grid) }?;
                let peak = device.check_peak()?;
                state
                    .session
                    .record(|c| c.observed_peak_bytes = c.observed_peak_bytes.max(peak));
                state.face = Face::Ext(promoted);
            }
        }
        stream.synchronize()?;
        state.len = half;
        state.phase = Phase::Round;
        state.session.record(|c| c.folds += 1);
        Ok(())
    }

    fn dense_finals<'s>(state: &Self::Dense<'s>) -> Result<[QM31; 2], Error>
    where
        Self: 's,
    {
        if state.len != 1 || state.phase != Phase::Round {
            return Err(Error::Phase);
        }
        let Face::Ext(face) = &state.face else {
            return Err(Error::Phase);
        };
        let device = state.session.device;
        let stream = &device.stream;
        let mut w = [[0u32; 4]; 1];
        let mut f = [[0u32; 4]; 1];
        device.complete_transfer(stream.memcpy_dtoh(&state.weights.slice(..1), &mut w[..]))?;
        device.complete_transfer(stream.memcpy_dtoh(&face.slice(..1), &mut f[..]))?;
        let pair = [canonical(w[0])?, canonical(f[0])?];
        state.session.record(|c| {
            c.finals += 1;
            c.downloaded_bytes += 32
        });
        Ok(pair)
    }
}

impl<'d> Session<'d> {
    fn build_dense<'s>(
        &'s self,
        original: &'s Original<'_, 'd>,
        packed: Packed,
    ) -> Result<(Dense<'s, 'd>, QM31), Error> {
        let geometry = original.geometry;
        let len = original.words.len() / 2;
        let uploaded = packed.upload_bytes()?;
        let device = self.device;
        let grid = device.grid(len / 2);
        let partial_count = grid.grid_dim.0 as usize * 3;
        let allocation = len
            .checked_mul(20)
            .and_then(|v| v.checked_add(16 * (partial_count + 3)))
            .and_then(|v| v.checked_add(uploaded))
            .ok_or(Error::Budget)?;
        let _guard = device.allocation(allocation)?;
        let stream = &device.stream;
        let mut weights = stream.alloc_zeros::<[u32; 4]>(len)?;
        let mut face = stream.alloc_zeros::<u32>(len)?;
        let partials = stream.alloc_zeros::<[u32; 4]>(partial_count)?;
        let polynomial = stream.alloc_zeros::<[u32; 4]>(3)?;
        let contributions = device.complete_transfer(stream.clone_htod(&packed.weights))?;
        let gammas = device.complete_transfer(stream.clone_htod(&packed.gammas))?;
        let runs = device.complete_transfer(stream.clone_htod(&packed.runs))?;
        let offsets = device.complete_transfer(stream.clone_htod(&packed.offsets))?;
        let tile = TILE as u64;
        let half = (len / 2) as u64;
        let kernel = device.kernel("batch_weights")?;
        let mut launch = stream.launch_builder(&kernel);
        launch
            .arg(&contributions)
            .arg(&gammas)
            .arg(&runs)
            .arg(&offsets)
            .arg(&mut weights)
            .arg(&tile)
            .arg(&half);
        // SAFETY: packing bounds every tile interval, claim and weight span; half <= weights.len().
        unsafe { launch.launch(grid) }?;
        let columns = (geometry.columns / 2) as u64;
        let count = len as u64;
        let kernel = device.kernel("batch_face")?;
        let mut launch = stream.launch_builder(&kernel);
        launch
            .arg(&original.words)
            .arg(&mut face)
            .arg(&columns)
            .arg(&count);
        // SAFETY: original contains exactly 2*len limbs in physical rows of 2*columns.
        unsafe { launch.launch(device.grid(len)) }?;
        let peak = device.check_peak()?;
        self.record(|c| {
            c.observed_peak_bytes = c.observed_peak_bytes.max(peak);
            c.batches += 1;
            c.expected_rounds += len.ilog2() as usize;
            c.uploaded_bytes += uploaded as u64
        });
        Ok((
            Dense {
                session: self,
                weights,
                face: Face::Base(face),
                partials,
                polynomial,
                len,
                phase: Phase::Round,
            },
            packed.sum,
        ))
    }
}

#[cfg(test)]
#[path = "dense_tests.rs"]
mod tests;
