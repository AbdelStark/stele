//! RFC-0008 A7 / RFC-0014 A1. A single persistent tree, scoped to one lookup.
use super::DEVICE;
use crate::{
    gpu::{ConstructionWork, Device, DeviceMasked, Error},
    gpu_lookup::select::{self, Resident},
    K,
};
use std::{cell::RefCell, time::Instant};
use stele_reductions::zk::claims::{
    bench::GkrConstruction,
    t32_sample::{Event, OBSERVER},
};
thread_local! {static TREE:RefCell<Option<Resident<'static>>>=const{RefCell::new(None)};}

pub(super) fn install() {
    assert!(OBSERVER.set(observe).is_ok());
}
pub(super) fn build<'a>(
    dev: &'a Device,
    input: &GkrConstruction<'_, K>,
    step: usize,
    id: usize,
    leaf: bool,
) -> Result<(DeviceMasked<'a>, ConstructionWork), Error> {
    TREE.with_borrow(|hold| {
        if leaf {
            assert!(hold.is_none(), "resident tree survives to leaf");
            return dev.build_gkr_bounded(input);
        }
        let tree = hold.as_ref().expect("required resident tree");
        let built = dev.build_gkr_resident(input, id, tree);
        if let Ok((_, work)) = &built {
            assert!(
                work.layer_views > 0,
                "nonleaf step did not use a resident child"
            );
            eprintln!(
                "t32_child step={step} id={id} views={} view_bytes={} retained_bytes={}",
                work.layer_views,
                work.layer_bytes,
                tree.bytes()
            );
        }
        built
    })
}
fn observe(event: Event<'_>) {
    let dev = DEVICE.get().expect("required CUDA device");
    match event {
        Event::Lookup {
            id,
            input,
            layers,
            top,
            normalize,
        } => {
            assert!(
                TREE.with_borrow(Option::is_none),
                "overlapping lookup trees"
            );
            let now = Instant::now();
            let (t, qualification, compared, wall) = if let Some(expected) = top {
                let (got, t) = select::top(dev, input).expect("selected top");
                let elapsed = now.elapsed();
                assert!(
                    expected.iter().zip(&got).all(|(a, b)| *a == b),
                    "selected top mismatch {id}"
                );
                let release = Instant::now();
                drop(got);
                dev.sync().unwrap();
                (t, std::time::Duration::ZERO, 0, elapsed + release.elapsed())
            } else {
                let (tree, t) = select::resident(dev, id, input).expect("resident rebuild");
                let elapsed = now.elapsed();
                let start = Instant::now();
                let compared = tree
                    .compare_all(layers)
                    .expect("every resident pair equals CPU");
                let qualification = start.elapsed();
                assert_eq!(compared, tree.bytes());
                TREE.with(|state| assert!(state.replace(Some(tree)).is_none()));
                (t, qualification, compared, elapsed)
            };
            let kind = if top.is_some() { "top" } else { "rebuild" };
            let memory = dev.memory_sample().expect("lookup CUDA pool");
            eprintln!("t32_selected kind={kind} id={id} normalize_ns={} wall_ns={} stage_ns={} upload_ns={} tree_ns={} top_ns={} download_ns={} assemble_ns={} h2d_bytes={} d2h_bytes={} buffers_bytes={} retained_bytes={} compare_ns={} compare_bytes={compared} pool_used_high={} pool_reserved_high={} total_bytes={}",normalize.as_nanos(),wall.as_nanos(),t.stage.as_nanos(),t.upload.as_nanos(),t.tree.as_nanos(),t.top.as_nanos(),t.download.as_nanos(),t.assemble.as_nanos(),t.upload_bytes,t.download_bytes,t.buffer_peak_bytes,t.retained_bytes,qualification.as_nanos(),memory.used_high,memory.reserved_high,memory.total);
        }
        Event::Release(id) => TREE.with_borrow_mut(|slot| {
            let tree = slot.take().expect("leaf without resident tree");
            tree.check(dev, id).unwrap();
            let bytes = tree.bytes();
            let now = Instant::now();
            drop(tree);
            dev.sync().unwrap();
            eprintln!(
                "t32_lookup_release id={id} retained_bytes={bytes} release_ns={}",
                now.elapsed().as_nanos()
            );
        }),
    }
}
