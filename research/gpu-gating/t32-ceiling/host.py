"""Calibrate the CPU work surrounding the early source encoders and ordinary batch faces."""
import argparse
from pathlib import Path


def install(root):
    if (root / ".git").exists():
        raise ValueError("expected a disposable source archive")
    def replace(path, old, new):
        p = root / path
        s = p.read_text()
        if s.count(old) != 1:
            raise ValueError("unexpected source at " + old)
        p.write_text(s.replace(old, new))
    prep = "crates/stele-pcs/src/preparation.rs"
    claims = "crates/stele-reductions/src/zk_claims.rs"
    replace(prep, "        let encoder = Encoder::from_code_id",
            "        extern crate std;\n        let arithmetic = std::time::Instant::now();\n"
            "        let encoder = Encoder::from_code_id")
    replace(prep, "        work.merkle_nodes_bytes = tree.owned_bytes();",
            '        std::eprintln!("source_material id={} ns={}", source.descriptor().id, arithmetic.elapsed().as_nanos());\n'
            '        work.merkle_nodes_bytes = tree.owned_bytes();')
    replace(claims, "    let mut prepared = (0..early)",
            "    extern crate std;\n    let source_start = std::time::Instant::now();\n    let mut prepared = (0..early)")
    replace(claims, '    detail.lap("zk/detail/sources_prepare");',
            '    std::eprintln!("early_sources count={early} ns={}", source_start.elapsed().as_nanos());\n'
            '    detail.lap("zk/detail/sources_prepare");')
    replace(claims, "    let i = batch_instance(id, prepared.source(), claims, gammas);",
            "    extern crate std;\n    let setup = std::time::Instant::now();\n"
            "    let i = batch_instance(id, prepared.source(), claims, gammas);\n"
            "    let copy = std::time::Instant::now();\n    let batch_face = face(prepared);\n"
            "    let copy_ns = copy.elapsed().as_nanos();")
    replace(claims, "Dense::new(&i, vec![weights, face(prepared)])", "Dense::new(&i, vec![weights, batch_face])")
    replace(claims, '    detail.lap("zk/detail/batch_face");',
            '    std::eprintln!("batch_setup id={id} total_ns={} copy_ns={copy_ns}", setup.elapsed().as_nanos());\n'
            '    detail.lap("zk/detail/batch_face");')


def retained(log):
    material = []
    sources = []
    batches = []
    for line in log.splitlines():
        kind, _, fields = line.partition(" ")
        if kind not in ("source_material", "early_sources", "batch_setup"):
            continue
        row = {k: int(v) for k, v in (x.split("=") for x in fields.split())}
        if kind == "source_material" and not sources:
            material.append((row["id"], row["ns"]))
        if kind == "early_sources":
            if [i for i, _ in material] != [0, 1] or row["count"] != 2:
                raise ValueError("wrong early source order")
            sources.append(row["ns"] - sum(n for _, n in material))
        if kind == "batch_setup":
            if not 0 < row["copy_ns"] <= row["total_ns"]:
                raise ValueError("overlapping batch interval")
            batches.append((row["id"], row["total_ns"] - row["copy_ns"]))
    if (len(sources) != 1 or sources[0] <= 0 or any(n <= 0 for _, n in material)
            or [i for i, _ in batches] != [1265, 1266, 1267]):
        raise ValueError("incomplete source or batch calibration")
    return dict(early_source_host_ns=sources[0], ordinary_batch_setup_host_ns=sum(n for _, n in batches))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive_root", type=Path)
    install(parser.parse_args().archive_root)
