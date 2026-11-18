"""Compose the existing genuine PCS and resident GKR observers on one CUDA context."""
from pathlib import Path
import runpy
import shutil
import sys

def install(root):
    root=Path(root).resolve()
    here=Path(__file__).resolve().parent
    runpy.run_path(str(here.parent/"t32-compact/install.py"))["install"](root)
    def replace(path, old, new):
        p=root/path
        s=p.read_text()
        if s.count(old)!=1:
            raise ValueError(f"original owner integration point {p.name}: {old[:62]}")
        p.write_text(s.replace(old,new))
    pcs=runpy.run_path(str(here.parent/"t32-source/install.py"))["install"](root,replace)
    masked=Path("research/gpu-gating/masked/src")
    device=masked/"t32_timing.rs"
    replace(device,"static DEVICE:",'#[path="source_timing.rs"] mod pcs;\n#[path="originals.rs"] pub(crate) mod originals;\nstatic DEVICE:')
    replace(device,"    resident::install();","    pcs::install();\n    resident::install();")
    replace(device,"    let m = dev.memory_sample()", """    let original_live = originals::with_originals(|owners| {
        assert!(owners.keys().copied().eq(0..4), "wrong originals held across GKR");
        owners.values().map(crate::gpu::OriginalMessage::bytes).sum::<usize>()
    });
    let m = dev.memory_sample()""")
    replace(device,"construction_bytes={} first_fold_bytes=", "original_live={original_live} construction_bytes={} first_fold_bytes=")
    shutil.copyfile(here/"originals.rs",root/masked/"originals.rs")
    visit=pcs.read_text()
    a=visit.index("use crate::")
    b=visit.index("    let start = now();",visit.index("fn visit("))
    visit=visit[:a]+'''use crate::{gpu::OriginalMessage, gpu_source::prepare_from_original, source::Shape};
use super::{DEVICE, originals};
use stele_reductions::stele_pcs::t32_source::{now, Visit, OBSERVER};
pub(super) fn install() {
    let start=now();
    assert!(OBSERVER.set(visit).is_ok());
    eprintln!("t32_source_cold ns={}", now()-start);
}
fn visit(input: Visit<'_>) {
    let entered=now();
    let mut registry=originals::lock();
'''+visit[b:]
    file=masked/"source_timing.rs"
    (root/file).write_text(visit)
    replace(file,"    let prepare_start = now();",'''    let upload_start=now();
    if !input.opening {
        assert!(!registry.owners.contains_key(&input.id), "duplicate pinned original");
        let owner=OriginalMessage::upload(dev,input.id,input.rows,input.cols,input.message).expect("pinned original upload");
        assert!(registry.owners.insert(input.id,owner).is_none() && registry.roots.insert(input.id,input.root).is_none());
    }
    let original_upload_ns=now()-upload_start;
    assert_eq!(registry.roots.get(&input.id),Some(&input.root),"source root identity");
    let owner=registry.owners.get(&input.id).expect("opening of certified source");
    let original_bytes=owner.bytes();
    let original_upload=if input.opening {0} else {original_bytes};
    let prepare_start = now();''')
    replace(file,"prepare_resident(dev, &shape, input.message)","prepare_from_original(dev, &shape, owner)")
    replace(file,"    drop(resident);",'''    drop(resident);
    if input.opening {
        drop(registry.owners.remove(&input.id).expect("source owner release"));
        assert!(registry.roots.remove(&input.id).is_some());
    }''')
    replace(file,"    assert_eq!(after.used, before.used);",'''    let originals_live=registry.owners.values().map(OriginalMessage::bytes).sum::<usize>();
    let lock_wait_ns=start-entered;
    let context_plus_reserved=outside+after.reserved_high;
    assert!(context_plus_reserved<=after.total*2/5, "source device budget");''')
    replace(file,'t32_source id={} opening={}', 't32_source original_bytes={original_bytes} original_upload={original_upload} original_upload_ns={original_upload_ns} lock_wait_ns={lock_wait_ns} originals_live={originals_live} id={} opening={}')
    batch=masked/"batch_timing.rs"
    replace(batch,"            message,","            message: _,")
    replace(batch,"batch::prepare_message(device, &src, message, claims, gammas)", "super::originals::with_source(&src, |owner| batch::prepare_original(device, &src, owner, claims, gammas))")
    replace(batch,'            eprintln!("t32_batch id={id}', '''            let original_id=src.descriptor().id;
            let original_bytes=src.rows()*src.columns()*4;
            eprintln!("t32_batch original_id={original_id} original_bytes={original_bytes} id={id}''')
    capture=Path("research/gpu-gating/t32-original/capture.py")
    shutil.copyfile(root/"research/gpu-gating/t32-resident/capture.py",root/capture)

if __name__=="__main__":
    install(sys.argv[1])
