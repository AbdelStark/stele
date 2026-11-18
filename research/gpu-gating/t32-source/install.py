"""Attach a read-only observer to completed certificate/opening response blocks."""
from pathlib import Path
import shutil


def install(root, replace):
    here = Path(__file__).resolve().parent
    pcs = "crates/stele-pcs/src/"
    prep = pcs + "preparation.rs"
    shutil.copyfile(here / "observe.rs", root / (pcs + "t32_source.rs"))
    replace(pcs + "lib.rs", "extern crate alloc;", "extern crate alloc;\nextern crate std;\npub mod t32_source;")
    replace(prep, "    mask_polynomial: bool,", "    pub(crate) observed_preparation: Option<([u8; 32], u64, u64)>,\n    mask_polynomial: bool,")
    replace(prep, "        let count = source", "        let cpu_start = crate::t32_source::now();\n        let count = source")
    replace(prep, "        let source = rebuild(tree.root())?;", """        let source = rebuild(tree.root())?;
        let cpu_stop = crate::t32_source::now();
        if seed.is_some() {
            std::eprintln!("t32_source_prepare id={} cpu_start={cpu_start} cpu_stop={cpu_stop}", source.descriptor().id);
        }""")
    replace(prep, "            mask_polynomial: false,", """            observed_preparation: seed.map(|s| (*s, cpu_start, cpu_stop)),
            mask_polynomial: false,""")
    for filename, kind, owner in (("producer.rs", "Certificate", "prepared"), ("opening.rs", "Opening", "self")):
        path = pcs + filename
        loop = f"for _ in 0..source.queries(ProofKind::{kind})"
        replace(path, loop, "let mut source_indices = Vec::new();\n    " + loop)
        call = f"let response = {owner}.response(index)?;"
        replace(path, call, "source_indices.push(index);\n        " + call)
        end = f"t.absorb(AbsorbLabel::{kind}Columns, &proof[start..])"
        replace(path, end, f"{owner}.observe_responses(ProofKind::{kind}, &source_indices, &proof[start..]);\n    " + end)
    # The existing source preparation computes all simultaneous live buffer sizes
    # before any device allocation. Compare them with the live CUDA pool.
    replace("research/gpu-gating/masked/src/gpu_source.rs", "    // Upload.", "    dev.require_budget(buffer_peak_bytes)?;\n    // Upload.")
    return here / "device.rs"
