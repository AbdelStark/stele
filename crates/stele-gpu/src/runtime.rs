//! RFC-0014 §§4–5 and A2. One stream, integer-only kernels and measured device capacity.
use cudarc::driver::{
    result, sys, CudaContext, CudaFunction, CudaModule, CudaStream, DriverError, LaunchConfig,
};
use cudarc::nvrtc::{compile_ptx_with_opts, CompileOptions};
use std::sync::{Arc, Mutex, MutexGuard};

/// A requested CUDA operation failed before producing admissible fields.
#[derive(Debug)]
pub enum Error {
    Unavailable,
    Compile(String),
    Driver(DriverError),
    Geometry,
    Source,
    Phase,
    Budget,
    Noncanonical,
}

impl From<DriverError> for Error {
    fn from(error: DriverError) -> Self {
        Self::Driver(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CUDA proving failed: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A reusable compiled CUDA program. Each proof creates its own source session.
pub struct Cuda {
    ctx: Arc<CudaContext>,
    pub(crate) stream: Arc<CudaStream>,
    module: Arc<CudaModule>,
    blocks: u32,
}

/// Physical memory outside the pool, its live allocations and retained capacity.
#[derive(Clone, Copy, Debug)]
pub struct Memory {
    pub total: usize,
    pub outside_pool: usize,
    pub pool_used: usize,
    pub pool_reserved: usize,
    pub pool_high: usize,
}

// The default device pool is shared by all proof sessions and Cuda instances.
static ALLOCATION: Mutex<()> = Mutex::new(());

impl Cuda {
    /// Open the visible device and compile the integer program. CUDA is required here.
    pub fn new() -> Result<Self, Error> {
        // SAFETY: these are library presence queries and never dereference caller data.
        if !unsafe { sys::is_culib_present() && cudarc::nvrtc::sys::is_culib_present() } {
            return Err(Error::Unavailable);
        }
        let ctx = CudaContext::new(0)?;
        if !ctx.has_async_alloc() {
            return Err(Error::Unavailable);
        }
        let blocks = u32::try_from(
            ctx.attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)?,
        )
        .map_err(|_| Error::Unavailable)?
        .checked_mul(8)
        .ok_or(Error::Unavailable)?;
        if blocks == 0 {
            return Err(Error::Unavailable);
        }
        let options = CompileOptions {
            arch: match ctx.compute_capability()? {
                (9, 0) => Some("compute_90"),
                (8, 0) => Some("compute_80"),
                (8, 6) => Some("compute_86"),
                (8, 9) => Some("compute_89"),
                _ => None,
            },
            ..Default::default()
        };
        let ptx = compile_ptx_with_opts(
            concat!(
                include_str!("dense.cu"),
                "\n",
                include_str!("gkr.cu"),
                "\n",
                include_str!("hiding.cu"),
                "\n",
                include_str!("lookup.cu")
            ),
            options,
        )
        .map_err(|error| Error::Compile(error.to_string()))?;
        let module = ctx.load_module(ptx)?;
        let stream = ctx.default_stream();
        Ok(Self {
            ctx,
            stream,
            module,
            blocks,
        })
    }

    pub(crate) fn grid(&self, n: usize) -> LaunchConfig {
        LaunchConfig {
            grid_dim: (n.div_ceil(256).clamp(1, self.blocks as usize) as u32, 1, 1),
            block_dim: (256, 1, 1),
            shared_mem_bytes: 0,
        }
    }
    pub(crate) fn kernel(&self, name: &str) -> Result<CudaFunction, Error> {
        Ok(self.module.load_function(name)?)
    }

    /// Sample A1 capacity, including memory retained by CUDA after an allocation is freed.
    pub fn memory(&self) -> Result<Memory, Error> {
        self.ctx.bind_to_thread()?;
        let (free, total) = self.ctx.mem_get_info()?;
        // SAFETY: the current live context owns the default allocation pool.
        let pool = unsafe { result::device::get_mem_pool(self.ctx.cu_device()) }?;
        let counter = |attr| -> Result<usize, Error> {
            let mut value = 0u64;
            // SAFETY: all three requested CUDA pool counters return a cuuint64_t.
            unsafe {
                result::mem_pool::get_attribute(pool, attr, core::ptr::from_mut(&mut value).cast())
            }?;
            usize::try_from(value).map_err(|_| Error::Budget)
        };
        use sys::CUmemPool_attribute as A;
        let pool_reserved = counter(A::CU_MEMPOOL_ATTR_RESERVED_MEM_CURRENT)?;
        Ok(Memory {
            total,
            outside_pool: (total - free).saturating_sub(pool_reserved),
            pool_reserved,
            pool_used: counter(A::CU_MEMPOOL_ATTR_USED_MEM_CURRENT)?,
            pool_high: counter(A::CU_MEMPOOL_ATTR_RESERVED_MEM_HIGH)?,
        })
    }

    pub(crate) fn allocation(&self, extra: usize) -> Result<MutexGuard<'static, ()>, Error> {
        let lock = ALLOCATION.lock().map_err(|_| Error::Budget)?;
        self.stream.synchronize()?;
        let m = self.memory()?;
        let required = m
            .pool_used
            .checked_add(extra)
            .ok_or(Error::Budget)?
            .max(m.pool_reserved);
        if required.saturating_add(m.outside_pool) > m.total / 5 * 2 {
            return Err(Error::Budget);
        }
        Ok(lock)
    }
    /// Pageable HostSlice transfers use the asynchronous driver entry points. Wait even
    /// on a submission error before the caller reuses or releases its host storage.
    pub(crate) fn complete_transfer<T>(
        &self,
        submission: Result<T, DriverError>,
    ) -> Result<T, Error> {
        let completion = self.stream.synchronize();
        let value = submission?;
        completion?;
        Ok(value)
    }
    pub(crate) fn check_peak(&self) -> Result<usize, Error> {
        self.stream.synchronize()?;
        let m = self.memory()?;
        let peak = m.outside_pool.saturating_add(m.pool_high);
        if peak > m.total / 5 * 2 {
            return Err(Error::Budget);
        }
        Ok(peak)
    }
}
