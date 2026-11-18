"""Add selected lookup production and device child views to a fresh GKR probe."""
from pathlib import Path
import runpy
import shutil
import sys


def install(root):
    root=Path(root).resolve()
    here=Path(__file__).resolve().parent
    base=here.parent/"t32-stages"
    stages=runpy.run_path(str(base/"install.py"))
    stages["install"](root,gkr=True)

    def replace(path,old,new):
        p=root/path
        text=p.read_text()
        if text.count(old)!=1:
            raise ValueError(f"unexpected source at {path}: {old[:70]}")
        p.write_text(text.replace(old,new))
    claims="crates/stele-reductions/src/zk_claims.rs"
    replace("crates/stele-hash/src/lib.rs","pub trait ChallengeField: sealed::Target","pub trait ChallengeField: 'static + sealed::Target")
    shutil.copyfile(here/"observer.rs",root/"crates/stele-reductions/src/t32_sample.rs")
    with (root/claims).open("a") as f:
        f.write('\n#[path="t32_sample.rs"] pub mod t32_sample;\n')
    with (root/"crates/stele-reductions/src/zk_lookup.rs").open("a") as f:
        f.write((base/"lookup.inc.rs").read_text())
    replace(claims, "let layers = lookup::tree(lp, &data, beta, alpha);\n        detail.lap", "let cpu_lookup = std::time::Instant::now();\n        let layers = lookup::tree(lp, &data, beta, alpha);\n        detail.lap")
    replace(claims,"let [p, q, mut h] = lookup::top(lp, &layers)?;\n        drop(layers);",
            """let [p, q, mut h] = lookup::top(lp, &layers)?;
        std::eprintln!("t32_cpu_lookup kind=top id={l} ns={}",cpu_lookup.elapsed().as_nanos());
        lookup::sample(l,lp,&data,beta,alpha,&layers,Some([&p,&q,&h]));
        drop(layers);""")
    replace(claims, "tree = Some((l, lookup::tree(lp, &data, runs[l].beta, runs[l].alpha)));",
            """let cpu_lookup=std::time::Instant::now();
            let layers=lookup::tree(lp,&data,runs[l].beta,runs[l].alpha);
            std::eprintln!("t32_cpu_lookup kind=rebuild id={l} ns={}",cpu_lookup.elapsed().as_nanos());
            lookup::sample(l,lp,&data,runs[l].beta,runs[l].alpha,&layers,None);
            tree=Some((l,layers));""")
    replace(claims,"if step.is_leaf() {\n            tree = None;","if step.is_leaf() {\n            t32_sample::release(l);\n            tree = None;")
    device="research/gpu-gating/masked/src/t32_timing.rs"
    shutil.copyfile(here/"device.rs",root/"research/gpu-gating/masked/src/resident_timing.rs")
    replace(device,"static DEVICE:",'#[path="resident_timing.rs"] mod resident;\nstatic DEVICE:')
    replace(device,'    eprintln!("t32_gkr_cold', '    resident::install();\n    eprintln!("t32_gkr_cold')
    replace(device, "let built = dev.build_gkr_bounded(&input);", """let mut child = None;
    let built = resident::build(dev,&input,&mut child,step.lookup,step.leaf);""")
    replace(device, "    let build = now.elapsed();", """    let build = now.elapsed();
    if let Some(child) = child {
        eprintln!("t32_child step={} id={} views={} view_bytes={} retained_bytes={}", step.step, step.lookup, child.views, child.view_bytes, child.retained);
        if child.released {
            // Release and synchronization were charged once in the preceding build interval.
            eprintln!("t32_lookup_release id={} retained_bytes={} release_ns=0 after_child_step={}", step.lookup, child.retained, step.step);
        }
    }""")
    # The existing 40s batch observer gets the same Device and actual source
    # as the GKR observer. Construct the device context exactly once.
    stages["install_batch"](root,replace,"t32_batch_sample")
    source=(base/"observer.rs").read_text().replace("super::{bench::LookupInputs, Claim}","super::Claim")
    source=source[:source.index("    Lookup {")]+source[source.index("    Batch {"):]
    source=source[:source.index("pub(super) fn lookup")]+source[source.index("pub(super) fn batch"):]
    (root/"crates/stele-reductions/src/t32_batch_sample.rs").write_text(source)
    with (root/claims).open("a") as f:
        f.write('\n#[path="t32_batch_sample.rs"] pub mod t32_batch_sample;\n')
    batch=(base/"device.rs").read_text().replace("t32_sample::","t32_batch_sample::")
    first=batch.index("pub fn install() {")
    end=batch.index("fn observe(",first)
    batch=batch[:first]+'pub(super) fn install() { assert!(OBSERVER.set(observe).is_ok()); }\n\n'+batch[end:]
    first=batch.index("        Event::Lookup {")
    end=batch.index("        Event::Batch {",first)
    batch=batch[:first]+batch[end:]
    batch=batch.replace("static DEVICE: OnceLock<Device> = OnceLock::new();","use super::DEVICE;")
    batch=batch.replace("available, batch, Device, DeviceMasked", "batch, DeviceMasked").replace("gpu_lookup, Field","Field").replace("cell::RefCell, sync::OnceLock, time::Instant","cell::RefCell, time::Instant")
    (root/"research/gpu-gating/masked/src/batch_timing.rs").write_text(batch)
    replace(device,'#[path="resident_timing.rs"] mod resident;', '#[path="resident_timing.rs"] mod resident;\n#[path="batch_timing.rs"] mod batch;')
    replace(device,"    resident::install();","    resident::install();\n    batch::install();")
    shutil.copyfile(base/"capture.py",root/"research/gpu-gating/t32-resident/capture.py")


if __name__=="__main__":
    install(sys.argv[1])
