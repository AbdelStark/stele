//! RFC-0014 §§4–5 and A2. One stream, integer-only kernels and measured device capacity.
use cudarc::driver::{
    result, sys, CudaContext, CudaFunction, CudaModule, CudaStream, DriverError, LaunchConfig,
    PushKernelArg,
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

impl Memory {
    // Driver thread backing cannot reuse unused bytes in the asynchronous allocation pool.
    #[track_caller]
    fn admit(&self, pool: usize, driver: usize) -> Result<(), Error> {
        let projected = self
            .pool_used
            .checked_add(pool)
            .map(|n| n.max(self.pool_reserved))
            .and_then(|n| n.checked_add(self.outside_pool))
            .and_then(|n| n.checked_add(driver));
        self.limit("admission", projected, pool, driver).map(|_| ())
    }
    #[track_caller]
    pub(crate) fn checked_peak(&self) -> Result<usize, Error> {
        self.limit(
            "observation",
            self.outside_pool.checked_add(self.pool_high),
            0,
            0,
        )
    }

    #[track_caller]
    fn limit(
        &self,
        operation: &str,
        bytes: Option<usize>,
        pool: usize,
        driver: usize,
    ) -> Result<usize, Error> {
        let limit = self.total / 5 * 2;
        if let Some(n) = bytes.filter(|n| *n <= limit) {
            return Ok(n);
        }
        if std::env::var_os("STELE_STAGE_TIMES").is_some() {
            let site = std::panic::Location::caller();
            let file = site.file().rsplit('/').next().unwrap_or(site.file());
            eprintln!("cuda_budget_rejected operation={operation} site={file}:{} requested_pool_bytes={pool} requested_driver_bytes={driver} projected_bytes={bytes:?} used_bytes={} reserved_bytes={} reserved_high_bytes={} outside_pool_bytes={} limit_bytes={limit} total_bytes={}",
                site.line(),self.pool_used,self.pool_reserved,self.pool_high,self.outside_pool,self.total);
        }
        Err(Error::Budget)
    }
}

// The default device pool is shared by all proof sessions and Cuda instances.
static ALLOCATION: Mutex<()> = Mutex::new(());

impl Cuda {
    /// Open the visible device and compile the integer program. CUDA is required here.
    pub fn new() -> Result<Self, Error> {
        let _guard = ALLOCATION.lock().map_err(|_| Error::Budget)?;
        let device = Self::open()?;
        device.prime_source_kernels()?;
        Ok(device)
    }
    fn open() -> Result<Self, Error> {
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

    // RFC-0014 A1/A5. CUDA may grow per-thread backing on a function's first
    // launch. Make every source kernel resident and launch the largest resident
    // grid before admitting any private source. Every kernel has zero items.
    fn prime_source_kernels(&self) -> Result<(), Error> {
        let functions = [
            self.kernel("transpose_kernel")?,
            self.kernel("bitrev_kernel")?,
            self.kernel("level_kernel")?,
            self.kernel("scale_kernel")?,
            self.kernel("leaf_kernel")?,
            self.kernel("node_kernel")?,
            self.kernel("selected_column_kernel")?,
        ];
        let mut max_local = 0;
        for f in &functions {
            max_local =
                max_local.max(usize::try_from(f.local_size_bytes()?).map_err(|_| Error::Budget)?);
        }
        let stack = self.ctx.get_limit(sys::CUlimit::CU_LIMIT_STACK_SIZE)?;
        let attr = |a| usize::try_from(self.ctx.attribute(a)?).map_err(|_| Error::Budget);
        use sys::CUdevice_attribute as D;
        let sms = attr(D::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)?;
        let threads = attr(D::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_MULTIPROCESSOR)?;
        let backing = stack
            .checked_add(max_local)
            .and_then(usize::checked_next_power_of_two)
            .and_then(|n| n.checked_mul(sms))
            .and_then(|n| n.checked_mul(threads))
            .ok_or(Error::Budget)?;
        self.stream.synchronize()?;
        self.memory()?.admit(4, backing)?;
        let scratch = self.stream.alloc_zeros::<u32>(1)?;
        let (zero, z32, one) = (0u64, 0u32, 1u64);
        let grid = self.grid(usize::MAX);
        let tiled = LaunchConfig {
            block_dim: (32, 8, 1),
            ..grid
        };
        let [transpose, bitrev, level, scale, leaf, node, selected] = &functions;
        macro_rules! prime {
            ($kernel:expr, $shape:expr, $($arg:expr),+) => {{
                let mut launch = self.stream.launch_builder($kernel);
                $(launch.arg($arg);)+
                // SAFETY: arguments below mirror hiding.cu. Every loop has zero
                // items, and the butterfly half-width is one. No pointer is read.
                unsafe { launch.launch($shape) }?;
                self.check_peak()?;
            }};
        }
        let ptr = &scratch;
        prime!(transpose, tiled, ptr, ptr, &zero, &zero);
        prime!(bitrev, grid, ptr, &zero, &z32);
        prime!(level, grid, ptr, ptr, &one, &zero, &zero, &z32);
        prime!(scale, grid, ptr, &z32, &zero);
        prime!(leaf, grid, ptr, &zero, &zero, ptr, ptr, ptr, &z32, ptr);
        prime!(node, grid, ptr, ptr, &zero, &z32, ptr);
        prime!(selected, grid, ptr, ptr, &zero, &zero, &zero, &zero, ptr);
        Ok(())
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

    #[track_caller]
    pub(crate) fn allocation(&self, extra: usize) -> Result<MutexGuard<'static, ()>, Error> {
        let lock = ALLOCATION.lock().map_err(|_| Error::Budget)?;
        self.stream.synchronize()?;
        self.memory()?.admit(extra, 0)?;
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
    #[track_caller]
    pub(crate) fn check_peak(&self) -> Result<usize, Error> {
        self.stream.synchronize()?;
        self.memory()?.checked_peak()
    }
}

#[cfg(test)]
mod source_budget_tests {
    use super::*;
    use stele_kernels::{Backend, HidingBackend, SourceGeometry, M31};

    #[test]
    fn rejects_driver_backing_hidden_by_unused_pool_reservation() {
        let memory = Memory {
            total: 1000,
            outside_pool: 40,
            pool_reserved: 350,
            pool_used: 10,
            pool_high: 350,
        };
        assert!(memory.admit(4, 10).is_ok());
        assert!(matches!(memory.admit(4, 11), Err(Error::Budget)));
        assert!(matches!(memory.admit(usize::MAX, 0), Err(Error::Budget)));
        assert!(matches!(memory.admit(0, usize::MAX), Err(Error::Budget)));
    }

    #[test]
    #[ignore = "requires a dedicated fresh CUDA process"]
    fn accepts_primed_source_backing_before_any_private_original() -> Result<(), Error> {
        let device = Cuda::open()?;
        let initial = device.memory()?;
        let initial_stack = device.ctx.get_limit(sys::CUlimit::CU_LIMIT_STACK_SIZE)?;
        {
            let _guard = ALLOCATION.lock().expect("test owns device");
            device.prime_source_kernels()?;
        }
        device.stream.synchronize()?;
        let ready = device.memory()?;
        let stack = device.ctx.get_limit(sys::CUlimit::CU_LIMIT_STACK_SIZE)?;
        let leaf_local = device.kernel("leaf_kernel")?.local_size_bytes()?;
        eprintln!("source_a1_initial_outside_bytes={} source_a1_ready_outside_bytes={} initial_stack={initial_stack} ready_stack={stack} leaf_local_bytes={leaf_local}", initial.outside_pool, ready.outside_pool);
        // A deep multi-chunk column and enough leaves for the full production grid.
        for (id, rows, columns) in [(0, 2048, 1024), (1, 16, 1 << 17)] {
            let session = device.session();
            let g = SourceGeometry { id, rows, columns };
            let words = vec![M31::from_u64(5); rows * columns];
            let source = session.original(g, &words)?;
            let mut hashes = 0;
            let (tree, _) = session.prepare_columns(g, &source, &[3; 32], &mut hashes)?;
            assert_eq!(hashes, (8 * columns - 1) as u64);
            let response = session.selected_column(g, &tree, 4 * columns - 1)?;
            assert_eq!(response.symbols.len(), rows);
            let current = device.memory()?;
            eprintln!("source_a1_completed_id={id} outside_bytes={} pool_high_bytes={} physical_budget_bytes={}", current.outside_pool, current.pool_high, current.total / 5 * 2);
            assert!(
                current.outside_pool <= ready.outside_pool,
                "outside-pool allocation grew after priming"
            );
            assert_eq!(
                device.ctx.get_limit(sys::CUlimit::CU_LIMIT_STACK_SIZE)?,
                stack
            );
        }
        Ok(())
    }
}
