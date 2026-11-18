//! RFC-0013 A4/A5 and RFC-0014 §5. One checked CUDA relation per original protocol instance.
use crate::{
    gpu::{Device, DeviceMasked},
    K,
};
use std::{
    cell::RefCell,
    sync::OnceLock,
    time::{Duration, Instant},
};
use stele_reductions::zk::claims::{
    bench::Masked,
    t32_relation::{Backend, BACKEND},
};

static DEVICE: OnceLock<&'static Device> = OnceLock::new();
static STANDALONE: OnceLock<Device> = OnceLock::new();
fn device() -> &'static Device {
    DEVICE.get().expect("required proof device")
}

struct Active {
    id: usize,
    vars: u32,
    degree: usize,
    factors: usize,
    terms: usize,
    gpu: DeviceMasked<'static>,
    rounds: usize,
    folds: usize,
    finals: usize,
    values: usize,
    masks: usize,
    descriptors: usize,
    each_round: usize,
    peak: usize,
    host: Duration,
    build: Duration,
    arithmetic: Duration,
}
#[derive(Default)]
struct Proof {
    expected: usize,
    completed: usize,
    rounds: usize,
    folds: usize,
    finals: usize,
}
thread_local! {
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
    static PROOF: RefCell<Option<Proof>> = const { RefCell::new(None) };
}
pub fn install() {
    let now = Instant::now();
    let dev = STANDALONE.get_or_init(|| Device::new().expect("required standalone H100"));
    install_shared(dev);
    eprintln!("relation_gpu_cold ns={}", now.elapsed().as_nanos());
}
pub(crate) fn install_shared(dev: &'static Device) {
    assert!(dev.name.contains("H100") && DEVICE.set(dev).is_ok());
    assert!(BACKEND
        .set(Backend {
            begin,
            build,
            round,
            fold,
            finals,
            finish,
            end
        })
        .is_ok());
}
fn begin(expected: usize) {
    PROOF.with_borrow_mut(|p| {
        assert!(p
            .replace(Proof {
                expected,
                ..Default::default()
            })
            .is_none())
    });
}
fn build(id: usize, source: &Masked<K>, host: Duration) {
    PROOF.with_borrow(|p| {
        let p = p.as_ref().unwrap();
        assert!(p.completed == id && id < p.expected);
    });
    let start = Instant::now();
    let dev = device();
    let (gpu, work) = dev
        .relation(source)
        .expect("required actual relation on H100");
    gpu.prepare().expect("relation round function");
    dev.sync().unwrap();
    let build = start.elapsed();
    let state = Active {
        id,
        vars: source.variables(),
        degree: source.degree(),
        factors: source.tables().count(),
        terms: source.terms().len(),
        descriptors: gpu.descriptor_upload_bytes(),
        each_round: gpu.round_upload_bytes(),
        gpu,
        rounds: 0,
        folds: 0,
        finals: 0,
        values: work.values,
        masks: work.masks,
        peak: work.peak,
        host,
        build,
        arithmetic: Duration::ZERO,
    };
    ACTIVE.with_borrow_mut(|s| assert!(s.replace(state).is_none()));
}
fn round(id: usize) -> Vec<K> {
    ACTIVE.with_borrow_mut(|s| {
        let s = s.as_mut().unwrap();
        assert!(s.id == id && s.rounds == s.folds && s.rounds < s.vars as usize);
        let start = Instant::now();
        let values = s.gpu.round().expect("device relation polynomial");
        device().sync().unwrap();
        s.arithmetic += start.elapsed();
        assert_eq!(values.len(), s.degree + 1);
        s.rounds += 1;
        values
    })
}
fn fold(id: usize, point: K) {
    ACTIVE.with_borrow_mut(|s| {
        let s = s.as_mut().unwrap();
        assert!(s.id == id && s.rounds == s.folds + 1);
        let start = Instant::now();
        s.gpu.fold(point).expect("fold real challenge");
        device().sync().unwrap();
        s.arithmetic += start.elapsed();
        s.folds += 1;
    });
}
fn finals(id: usize) -> Vec<K> {
    ACTIVE.with_borrow_mut(|s| {
        let s = s.as_mut().unwrap();
        assert!(s.id == id && s.folds == s.vars as usize && s.finals == 0);
        let start = Instant::now();
        let values = s.gpu.final_values().expect("device relation finals");
        device().sync().unwrap();
        s.arithmetic += start.elapsed();
        assert_eq!(s.factors, values.len());
        s.finals = values.len();
        values
    })
}
fn finish(id: usize, cpu: Duration) {
    let s = ACTIVE.with_borrow_mut(|s| s.take().unwrap());
    assert!(s.id == id && s.finals == s.factors);
    let start = Instant::now();
    drop(s.gpu);
    device().sync().unwrap();
    let arithmetic = s.arithmetic + start.elapsed();
    let m = device().memory_sample().unwrap();
    assert!(
        (m.total - m.free).saturating_sub(m.reserved) + m.reserved_high <= m.total / 5 * 2,
        "relation pool cap"
    );
    let d2h = 16 * (s.rounds * (s.degree + 1) + s.finals);
    eprintln!("relation_gpu id={id} vars={} degree={} factors={} terms={} rounds={} folds={} finals={} admitted=1 cpu_returned=0 host_factors_ns={} build_ns={} device_ns={} cpu_oracle_ns={} values_h2d={} masks_h2d={} descriptors_h2d={} round_h2d={} d2h={d2h} peak_bytes={} total_bytes={} free_bytes={} pool_reserved={} pool_used={} pool_high={}",s.vars,s.degree,s.factors,s.terms,s.rounds,s.folds,s.finals,s.host.as_nanos(),s.build.as_nanos(),arithmetic.as_nanos(),cpu.as_nanos(),s.values,s.masks,s.descriptors,s.rounds*s.each_round,s.peak,m.total,m.free,m.reserved,m.used,m.reserved_high);
    PROOF.with_borrow_mut(|p| {
        let p = p.as_mut().unwrap();
        assert_eq!(p.completed, id);
        p.completed += 1;
        p.rounds += s.rounds;
        p.folds += s.folds;
        p.finals += s.finals;
    });
}
fn end(expected: usize) {
    assert!(ACTIVE.with_borrow(Option::is_none));
    let p = PROOF.with_borrow_mut(|p| p.take().unwrap());
    assert!(p.completed == expected && p.expected == expected);
    eprintln!(
        "relation_gpu_complete relations={expected} rounds={} folds={} finals={}",
        p.rounds, p.folds, p.finals
    );
}
