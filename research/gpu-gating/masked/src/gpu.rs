//! The device path (feature `cuda`): tables built and kept resident on the device,
//! folded in place, one round polynomial copied back per round (RFC-0014 §1: the CPU
//! is the reference and the values must be the same elements).
//!
//! The round kernel is generated per round shape (which factors are M31, which are
//! masked in this round) and compiled by NVRTC at run time, so every table index is a
//! register; the term products follow the CPU's mixed form (E16-34): M31 factors
//! multiplied in M31, then applied once to the QM31 product.
use crate::{Shape, Source, CM31, K, M31, QM31};
use cudarc::driver::{
    CudaContext, CudaFunction, CudaModule, CudaSlice, CudaStream, DevicePtr, DriverError,
    LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::{compile_ptx_with_opts, CompileOptions};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stele_reductions::stele_field::Field;
use stele_reductions::zk::claims::bench::mask_weight;

const KERNELS: &str = include_str!("kernels.cu");
const THREADS: u32 = 256;

/// `(x, r)` per factor, read back from the device.
pub type Tables = Vec<(Vec<K>, Vec<K>)>;

/// A device failure.
#[derive(Debug)]
pub enum Error {
    Driver(DriverError),
    Compile(String),
    /// A value read back from the device is not canonical.
    Value,
}

impl From<DriverError> for Error {
    fn from(e: DriverError) -> Self {
        Error::Driver(e)
    }
}

/// Whether the CUDA driver and NVRTC libraries can be loaded on this host.
pub fn available() -> bool {
    // SAFETY: these only try to open the shared libraries; no CUDA call is made.
    unsafe { cudarc::driver::sys::is_culib_present() && cudarc::nvrtc::sys::is_culib_present() }
}

fn limbs(v: K) -> [u32; 4] {
    [
        v.0 .0.as_u32(),
        v.0 .1.as_u32(),
        v.1 .0.as_u32(),
        v.1 .1.as_u32(),
    ]
}

fn element(l: &[u32]) -> Result<K, Error> {
    let m = |x: u32| M31::from_canonical(x).ok_or(Error::Value);
    Ok(QM31(CM31(m(l[0])?, m(l[1])?), CM31(m(l[2])?, m(l[3])?)))
}

fn base(x: u32) -> Result<K, Error> {
    M31::from_canonical(x)
        .map(|m| K::from_i64(i64::from(m.as_u32())))
        .ok_or(Error::Value)
}

/// A device table: M31 entries (one `u32` each) or QM31 entries (four `u32` each).
enum Buf {
    Base(CudaSlice<u32>),
    Ext(CudaSlice<u32>),
}

impl Buf {
    fn is_base(&self) -> bool {
        matches!(self, Buf::Base(_))
    }
    fn slice(&self) -> &CudaSlice<u32> {
        match self {
            Buf::Base(s) | Buf::Ext(s) => s,
        }
    }
}

struct Factor {
    x: Buf,
    r: Option<Buf>,
    v: Option<usize>,
}

/// One CUDA device with the static kernels loaded.
pub struct Device {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
    arch: Option<&'static str>,
    sms: u32,
    kernels: Arc<CudaModule>,
    rounds: RefCell<HashMap<String, CudaFunction>>,
    /// The device's name.
    pub name: String,
}

impl Device {
    /// Device 0; fails without a driver or device.
    pub fn new() -> Result<Self, Error> {
        let ctx = CudaContext::new(0)?;
        // SAFETY: one stream does all the work, so its order alone sequences every
        // read and write; no cross-stream event is needed.
        unsafe { ctx.disable_event_tracking() };
        let stream = ctx.default_stream();
        let arch = match ctx.compute_capability()? {
            (7, 0) => Some("compute_70"),
            (7, 5) => Some("compute_75"),
            (8, 0) => Some("compute_80"),
            (8, 6) => Some("compute_86"),
            (8, 9) => Some("compute_89"),
            (9, 0) => Some("compute_90"),
            _ => None,
        };
        let sms = ctx.attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
        )? as u32;
        let name = ctx.name()?;
        let kernels = Self::compile(&ctx, arch, KERNELS)?;
        Ok(Self {
            ctx,
            stream,
            arch,
            sms,
            kernels,
            rounds: RefCell::new(HashMap::new()),
            name,
        })
    }

    fn compile(
        ctx: &Arc<CudaContext>,
        arch: Option<&'static str>,
        src: &str,
    ) -> Result<Arc<CudaModule>, Error> {
        let opts = CompileOptions {
            arch,
            ..Default::default()
        };
        let ptx = compile_ptx_with_opts(src, opts).map_err(|e| Error::Compile(format!("{e:?}")))?;
        Ok(ctx.load_module(ptx)?)
    }

    fn function(&self, name: &str) -> Result<CudaFunction, Error> {
        Ok(self.kernels.load_function(name)?)
    }

    fn round_function(&self, src: &str) -> Result<CudaFunction, Error> {
        if let Some(f) = self.rounds.borrow().get(src) {
            return Ok(f.clone());
        }
        let module = Self::compile(&self.ctx, self.arch, &format!("{KERNELS}\n{src}"))?;
        let f = module.load_function("round_kernel")?;
        self.rounds.borrow_mut().insert(src.to_string(), f.clone());
        Ok(f)
    }

    fn grid(&self, n: usize) -> LaunchConfig {
        let blocks = n.div_ceil(THREADS as usize).clamp(1, self.sms as usize * 8) as u32;
        LaunchConfig {
            grid_dim: (blocks, 1, 1),
            block_dim: (THREADS, 1, 1),
            shared_mem_bytes: 0,
        }
    }

    /// Host-to-device copy of `words` u32s from pageable and from pinned host memory:
    /// the two wall times (the bus bound on the upload phase).
    pub fn h2d(&self, words: usize) -> Result<(Duration, Duration), Error> {
        let host: Vec<u32> = (0..words as u32).collect();
        let mut dst = self.stream.alloc_zeros::<u32>(words)?;
        self.stream.memcpy_htod(&host, &mut dst)?;
        self.sync()?;
        let start = Instant::now();
        self.stream.memcpy_htod(&host, &mut dst)?;
        self.sync()?;
        let pageable = start.elapsed();
        // SAFETY: the pinned buffer is written in full before it is read.
        let mut pinned = unsafe { self.ctx.alloc_pinned::<u32>(words) }?;
        pinned.as_mut_slice()?.copy_from_slice(&host);
        self.stream.memcpy_htod(&pinned, &mut dst)?;
        self.sync()?;
        let start = Instant::now();
        self.stream.memcpy_htod(&pinned, &mut dst)?;
        self.sync()?;
        Ok((pageable, start.elapsed()))
    }

    /// Wait for all queued work.
    pub fn sync(&self) -> Result<(), Error> {
        Ok(self.stream.synchronize()?)
    }

    fn ptr(&self, s: &CudaSlice<u32>) -> u64 {
        s.device_ptr(&self.stream).0
    }

    fn qm31s(&self, values: &[K]) -> Result<CudaSlice<u32>, Error> {
        let host: Vec<u32> = values.iter().flat_map(|v| limbs(*v)).collect();
        Ok(self.stream.clone_htod(&host)?)
    }

    /// Upload the shape's inputs, then build its tables on the device. Returns the
    /// summand and the two phases' wall times (upload, device build).
    pub fn build(&self, shape: &Shape) -> Result<(DeviceMasked<'_>, Duration, Duration), Error> {
        let len = 1usize << shape.n;
        // Phase 1: host to device (columns, layer values, points, periods, blocks).
        let start = Instant::now();
        let mut staged = Vec::new();
        for f in &shape.factors {
            let x = self.stage(&f.x, len)?;
            let r = match &f.mask {
                Some((m, _)) => Some(self.stage(m, len)?),
                None => None,
            };
            staged.push((x, r));
        }
        self.sync()?;
        let upload = start.elapsed();
        // Phase 2: device-side construction.
        let start = Instant::now();
        let mut factors = Vec::new();
        for (f, (x, r)) in shape.factors.iter().zip(staged) {
            let x = self.construct(&f.x, x, shape.n)?;
            let r = match (&f.mask, r) {
                (Some((m, _)), Some(r)) => Some(self.construct(m, r, shape.n)?),
                _ => None,
            };
            factors.push(Factor {
                x,
                r,
                v: f.mask.as_ref().map(|(_, v)| *v),
            });
        }
        let nodes = shape.degree + 1;
        let blocks = self.grid(len / 2).grid_dim.0 as usize;
        let coef: Vec<K> = shape.terms.iter().map(|(c, _)| *c).collect();
        let masked = DeviceMasked {
            dev: self,
            factors,
            terms: shape.terms.clone(),
            nodes,
            len,
            bound: 0,
            xs: self.stream.alloc_zeros::<u64>(shape.factors.len())?,
            rs: self.stream.alloc_zeros::<u64>(shape.factors.len())?,
            coef: self.qm31s(&coef)?,
            partials: self.stream.alloc_zeros::<u32>(blocks * nodes * 4)?,
            out: self.stream.alloc_zeros::<u32>(nodes * 4)?,
        };
        self.sync()?;
        Ok((masked, upload, start.elapsed()))
    }

    /// The uploaded part of a source; a column or layer is the table's own buffer.
    fn stage(&self, s: &Source, len: usize) -> Result<Vec<CudaSlice<u32>>, Error> {
        Ok(match s {
            Source::Eq { point, .. } => vec![self.qm31s(point)?],
            Source::Tile { period } => vec![self.qm31s(period)?],
            Source::Column { values } => {
                let host: Vec<u32> = values.iter().map(|m| m.as_u32()).collect();
                vec![self.stream.clone_htod(&host)?]
            }
            Source::Layer { half } => {
                let mut table = self.stream.alloc_zeros::<u32>(len * 4)?;
                let host: Vec<u32> = half.iter().flat_map(|v| limbs(*v)).collect();
                self.stream
                    .memcpy_htod(&host, &mut table.slice_mut(0..host.len()))?;
                vec![table]
            }
            Source::Mask { block, u } => {
                let host: Vec<u32> = block.iter().map(|m| m.as_u32()).collect();
                let u: Vec<u32> = u.iter().map(|q| *q as u32).collect();
                vec![self.stream.clone_htod(&host)?, self.stream.clone_htod(&u)?]
            }
        })
    }

    fn construct(
        &self,
        s: &Source,
        mut staged: Vec<CudaSlice<u32>>,
        n: usize,
    ) -> Result<Buf, Error> {
        let len = 1usize << n;
        let len64 = len as u64;
        Ok(match s {
            Source::Eq {
                point,
                scale,
                offset,
            } => {
                let out = self.stream.alloc_zeros::<u32>(len * 4)?;
                let count = 1u64 << point.len();
                let s = limbs(scale.unwrap_or(K::from_i64(1)));
                let dst = self.ptr(&out) + (*offset as u64) * 16;
                let src = self.ptr(&staged[0]);
                let nv = point.len() as i32;
                let f = self.function("eq_kernel")?;
                let mut b = self.stream.launch_builder(&f);
                b.arg(&dst).arg(&src).arg(&nv);
                b.arg(&s[0]).arg(&s[1]).arg(&s[2]).arg(&s[3]).arg(&count);
                // SAFETY: `dst` has `count` QM31 entries from `offset` (offset + count ≤
                // len); `src` holds `nv` QM31 entries.
                unsafe { b.launch(self.grid(count as usize)) }?;
                Buf::Ext(out)
            }
            Source::Tile { period } => {
                let out = self.stream.alloc_zeros::<u32>(len * 4)?;
                let (dst, src, mask) = (
                    self.ptr(&out),
                    self.ptr(&staged[0]),
                    period.len() as u64 - 1,
                );
                let f = self.function("tile_kernel")?;
                let mut b = self.stream.launch_builder(&f);
                b.arg(&dst).arg(&src).arg(&mask).arg(&len64);
                // SAFETY: `dst` has `len` entries; `period` is a power of two long.
                unsafe { b.launch(self.grid(len)) }?;
                Buf::Ext(out)
            }
            Source::Column { .. } => Buf::Base(staged.remove(0)),
            Source::Layer { .. } => {
                let table = staged.remove(0);
                let (x, half) = (self.ptr(&table), len64 / 2);
                let f = self.function("dup_kernel")?;
                let mut b = self.stream.launch_builder(&f);
                b.arg(&x).arg(&half);
                // SAFETY: `table` has `len` QM31 entries.
                unsafe { b.launch(self.grid(len / 2)) }?;
                Buf::Ext(table)
            }
            Source::Mask { u, .. } => {
                let out = self.stream.alloc_zeros::<u32>(len)?;
                let (dst, block, ud) = (self.ptr(&out), self.ptr(&staged[0]), self.ptr(&staged[1]));
                let (ulen, n) = (u.len() as i32, n as i32);
                let f = self.function("mask_kernel")?;
                let mut b = self.stream.launch_builder(&f);
                b.arg(&dst)
                    .arg(&block)
                    .arg(&ud)
                    .arg(&ulen)
                    .arg(&n)
                    .arg(&len64);
                // SAFETY: `dst` has `len` entries; `block` has `2^ulen`; `u` has `ulen`.
                unsafe { b.launch(self.grid(len)) }?;
                Buf::Base(out)
            }
        })
    }
}

/// The masked summand resident on the device.
pub struct DeviceMasked<'d> {
    dev: &'d Device,
    factors: Vec<Factor>,
    terms: Vec<(K, Vec<u32>)>,
    nodes: usize,
    len: usize,
    bound: usize,
    xs: CudaSlice<u64>,
    rs: CudaSlice<u64>,
    coef: CudaSlice<u32>,
    partials: CudaSlice<u32>,
    out: CudaSlice<u32>,
}

impl DeviceMasked<'_> {
    /// Compile every round kernel this summand will need (outside any timed region).
    pub fn prepare(&self) -> Result<(), Error> {
        let n = self.len.trailing_zeros() as usize;
        for round in 0..n {
            let xbase: Vec<bool> = self
                .factors
                .iter()
                .map(|f| round == 0 && f.x.is_base())
                .collect();
            let rnow: Vec<Option<bool>> = self
                .factors
                .iter()
                .map(|f| match (&f.r, f.v) {
                    (Some(r), Some(v)) if v == round => Some(round == 0 && r.is_base()),
                    _ => None,
                })
                .collect();
            self.dev
                .round_function(&round_source(&xbase, &rnow, &self.terms, self.nodes))?;
        }
        Ok(())
    }

    /// The round polynomial at nodes `0..=degree`.
    pub fn round(&mut self) -> Result<Vec<K>, Error> {
        let dev = self.dev;
        let half = self.len / 2;
        let xbase: Vec<bool> = self.factors.iter().map(|f| f.x.is_base()).collect();
        let rnow: Vec<Option<bool>> = self
            .factors
            .iter()
            .map(|f| match (&f.r, f.v) {
                (Some(r), Some(v)) if v == self.bound => Some(r.is_base()),
                _ => None,
            })
            .collect();
        let f = dev.round_function(&round_source(&xbase, &rnow, &self.terms, self.nodes))?;
        let xs: Vec<u64> = self.factors.iter().map(|f| dev.ptr(f.x.slice())).collect();
        let rs: Vec<u64> = self
            .factors
            .iter()
            .zip(&rnow)
            .map(|(f, now)| match (&f.r, now) {
                (Some(r), Some(_)) => dev.ptr(r.slice()),
                _ => 0,
            })
            .collect();
        dev.stream.memcpy_htod(&xs, &mut self.xs)?;
        dev.stream.memcpy_htod(&rs, &mut self.rs)?;
        let cfg = dev.grid(half);
        let (half64, blocks, nodes) = (half as u64, cfg.grid_dim.0 as i32, self.nodes as i32);
        let mut b = dev.stream.launch_builder(&f);
        b.arg(&self.xs)
            .arg(&self.rs)
            .arg(&self.coef)
            .arg(&half64)
            .arg(&mut self.partials);
        // SAFETY: every `xs[k]` table has `2·half` entries of its type, every nonzero
        // `rs[k]` too; `partials` has `blocks · nodes` QM31 entries.
        unsafe { b.launch(cfg) }?;
        let reduce = dev.function("reduce_kernel")?;
        let mut b = dev.stream.launch_builder(&reduce);
        b.arg(&self.partials)
            .arg(&blocks)
            .arg(&nodes)
            .arg(&mut self.out);
        let one = LaunchConfig {
            grid_dim: (1, 1, 1),
            block_dim: (32, 1, 1),
            shared_mem_bytes: 0,
        };
        // SAFETY: `nodes ≤ 32` threads read `blocks · nodes` partials and write `nodes`.
        unsafe { b.launch(one) }?;
        let host = dev.stream.clone_dtoh(&self.out)?;
        host.chunks(4).map(element).collect()
    }

    /// Bind the leading variable to `challenge` in place (a factor's first fold writes
    /// its QM31 table and drops the M31 one).
    pub fn fold(&mut self, challenge: K) -> Result<(), Error> {
        let dev = self.dev;
        let half = self.len / 2;
        let half64 = half as u64;
        let c = limbs(challenge);
        let kc = limbs(mask_weight(challenge));
        let cfg = dev.grid(half);
        for f in &mut self.factors {
            if f.v == Some(self.bound) {
                let r = f.r.take().ok_or(Error::Value)?;
                let out = match &f.x {
                    Buf::Ext(_) => None,
                    Buf::Base(_) => Some(dev.stream.alloc_zeros::<u32>(half * 4)?),
                };
                let x = dev.ptr(f.x.slice());
                let dst = out.as_ref().map_or(x, |o| dev.ptr(o));
                let (xb, rb, rp) = (
                    i32::from(f.x.is_base()),
                    i32::from(r.is_base()),
                    dev.ptr(r.slice()),
                );
                let k = dev.function("fold_mask")?;
                let mut b = dev.stream.launch_builder(&k);
                b.arg(&dst).arg(&x).arg(&xb).arg(&rp).arg(&rb).arg(&half64);
                b.arg(&c[0]).arg(&c[1]).arg(&c[2]).arg(&c[3]);
                b.arg(&kc[0]).arg(&kc[1]).arg(&kc[2]).arg(&kc[3]);
                // SAFETY: `x` and `r` have `2·half` entries of their types; `dst` has
                // `half` QM31 entries and is `x` only when `x` is QM31 (in place: each
                // thread reads i and i + half before writing i).
                unsafe { b.launch(cfg) }?;
                if let Some(o) = out {
                    f.x = Buf::Ext(o);
                }
                continue;
            }
            fold_one(dev, &mut f.x, half, &c, cfg)?;
            if let Some(r) = &mut f.r {
                fold_one(dev, r, half, &c, cfg)?;
            }
        }
        self.bound += 1;
        self.len = half;
        Ok(())
    }

    /// The current `(x, r)` tables, read back (r empty for a public or bound factor).
    pub fn tables(&self) -> Result<Tables, Error> {
        let read = |b: &Buf| -> Result<Vec<K>, Error> {
            let host = self.dev.stream.clone_dtoh(b.slice())?;
            match b {
                Buf::Base(_) => host[..self.len].iter().map(|x| base(*x)).collect(),
                Buf::Ext(_) => host[..self.len * 4].chunks(4).map(element).collect(),
            }
        };
        self.factors
            .iter()
            .map(|f| Ok((read(&f.x)?, f.r.as_ref().map_or(Ok(Vec::new()), read)?)))
            .collect()
    }
}

fn fold_one(
    dev: &Device,
    b: &mut Buf,
    half: usize,
    c: &[u32; 4],
    cfg: LaunchConfig,
) -> Result<(), Error> {
    let half64 = half as u64;
    match b {
        Buf::Ext(s) => {
            let x = dev.ptr(s);
            let k = dev.function("fold_ext")?;
            let mut l = dev.stream.launch_builder(&k);
            l.arg(&x)
                .arg(&half64)
                .arg(&c[0])
                .arg(&c[1])
                .arg(&c[2])
                .arg(&c[3]);
            // SAFETY: `x` has `2·half` QM31 entries; in place as in `fold_mask`.
            unsafe { l.launch(cfg) }?;
        }
        Buf::Base(s) => {
            let out = dev.stream.alloc_zeros::<u32>(half * 4)?;
            let (x, o) = (dev.ptr(s), dev.ptr(&out));
            let k = dev.function("fold_base")?;
            let mut l = dev.stream.launch_builder(&k);
            l.arg(&x)
                .arg(&o)
                .arg(&half64)
                .arg(&c[0])
                .arg(&c[1])
                .arg(&c[2])
                .arg(&c[3]);
            // SAFETY: `x` has `2·half` M31 entries, `out` `half` QM31 entries.
            unsafe { l.launch(cfg) }?;
            // The M31 table is freed here, ordered after the kernel on the one stream.
            *b = Buf::Ext(out);
        }
    }
    Ok(())
}

/// `κ(t) = t(1 − t)` at an integer node, as a canonical M31 value.
fn kappa_node(t: usize) -> u32 {
    let p = u64::from(M31::MODULUS);
    let v = (t as u64 * (t as u64 - 1)) % p;
    ((p - v) % p) as u32
}

/// The round kernel for one round shape: `xbase[k]` whether factor `k`'s table is M31,
/// `rnow[k]` whether it is masked in this round (and its mask table M31).
pub fn round_source(
    xbase: &[bool],
    rnow: &[Option<bool>],
    terms: &[(K, Vec<u32>)],
    nodes: usize,
) -> String {
    let one = K::from_i64(1);
    let minus = K::from_i64(-1);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "extern \"C\" __global__ void round_kernel(const u64 *xs, const u64 *rs, const u32 *coef, u64 half, u32 *partials) {{"
    );
    let _ = writeln!(s, "  __shared__ Q sh[{THREADS}];");
    for (i, (c, _)) in terms.iter().enumerate() {
        if *c != one && *c != minus {
            let _ = writeln!(s, "  Q c{i} = qload(coef, {i});");
        }
    }
    for t in 0..nodes {
        let _ = writeln!(s, "  Q acc{t} = qzero();");
    }
    let _ = writeln!(s, "  GRID_STRIDE(j, half) {{");
    let load = |s: &mut String, name: &str, slope: &str, table: &str, k: usize, b: bool| {
        let _ = if b {
            writeln!(s, "    u32 {name}{k} = ((const u32 *){table}[{k}])[j]; u32 {slope}{k} = msub(((const u32 *){table}[{k}])[j + half], {name}{k});")
        } else {
            writeln!(s, "    Q {name}{k} = qload((const u32 *){table}[{k}], j); Q {slope}{k} = qsub(qload((const u32 *){table}[{k}], j + half), {name}{k});")
        };
    };
    for k in 0..xbase.len() {
        load(&mut s, "x", "d", "xs", k, xbase[k]);
        if let Some(rb) = rnow[k] {
            load(&mut s, "r", "e", "rs", k, rb);
        }
    }
    // A value is M31 when its table is and, if masked now, its mask table is too.
    let vbase: Vec<bool> = (0..xbase.len())
        .map(|k| xbase[k] && rnow[k].is_none_or(|rb| rb))
        .collect();
    let add = |b: bool| if b { "madd" } else { "qadd" };
    for t in 0..nodes {
        let _ = writeln!(s, "    {{");
        if t > 0 {
            for k in 0..xbase.len() {
                let _ = writeln!(s, "      x{k} = {}(x{k}, d{k});", add(xbase[k]));
                if let Some(rb) = rnow[k] {
                    let _ = writeln!(s, "      r{k} = {}(r{k}, e{k});", add(rb));
                }
            }
        }
        for k in 0..xbase.len() {
            let ty = if vbase[k] { "u32" } else { "Q" };
            let value = match rnow[k] {
                // κ(0) = κ(1) = 0: the mask term vanishes on the cube.
                Some(rb) if t > 1 => {
                    let kap = kappa_node(t);
                    match (xbase[k], rb) {
                        (true, true) => format!("madd(x{k}, mmul({kap}u, r{k}))"),
                        (true, false) => format!("qadd(qembed(x{k}), qmulm(r{k}, {kap}u))"),
                        (false, true) => format!("qadd(x{k}, qembed(mmul({kap}u, r{k})))"),
                        (false, false) => format!("qadd(x{k}, qmulm(r{k}, {kap}u))"),
                    }
                }
                Some(_) if !vbase[k] && xbase[k] => format!("qembed(x{k})"),
                _ => format!("x{k}"),
            };
            let _ = writeln!(s, "      {ty} v{k} = {value};");
        }
        for (i, (c, factors)) in terms.iter().enumerate() {
            let m = factors
                .iter()
                .filter(|f| vbase[**f as usize])
                .map(|f| format!("v{f}"))
                .reduce(|a, b| format!("mmul({a}, {b})"));
            let q = factors
                .iter()
                .filter(|f| !vbase[**f as usize])
                .map(|f| format!("v{f}"))
                .reduce(|a, b| format!("qmul({a}, {b})"));
            let p = match (m, q) {
                (Some(m), Some(q)) => format!("qmulm({q}, {m})"),
                (Some(m), None) => format!("qembed({m})"),
                (None, Some(q)) => q,
                (None, None) => "qembed(1u)".to_string(),
            };
            let _ = if *c == one {
                writeln!(s, "      acc{t} = qadd(acc{t}, {p});")
            } else if *c == minus {
                writeln!(s, "      acc{t} = qsub(acc{t}, {p});")
            } else {
                writeln!(s, "      acc{t} = qadd(acc{t}, qmul(c{i}, {p}));")
            };
        }
        let _ = writeln!(s, "    }}");
    }
    let _ = writeln!(s, "  }}");
    for t in 0..nodes {
        let _ = writeln!(s, "  block_sum(sh, acc{t}, partials, {nodes}, {t});");
    }
    let _ = writeln!(s, "}}");
    s
}
