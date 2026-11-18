"""Validate observed T32 stage coverage and sum matched CPU and H100 work."""
from collections import defaultdict
from pathlib import Path
import runpy


def summarize(log):
    rows = defaultdict(list)
    for line in log.splitlines():
        if line.startswith("t32_"):
            tag, *items = line.split()
            record = {}
            for item in items:
                key, val = item.split("=")
                if key in record or (key != "kind" and not val.isdecimal()):
                    raise ValueError("invalid stage counter")
                record[key] = val if key == "kind" else int(val)
            rows[tag[4:]].append(record)
    if set(rows) != {"cold", "lookup", "normalize_release", "cpu_lookup", "batch", "cpu_weights", "cpu_face", "round", "fold", "finals"}:
        raise ValueError("incomplete or unexpected stage types")
    if len(rows["cold"]) != 1 or rows["cold"][0]["ns"] <= 0:
        raise ValueError("invalid cold setup")
    summary = {"cold_ns": rows["cold"][0]["ns"]}
    for kind in ("top", "rebuild"):
        gpu = [r for r in rows["lookup"] if r["kind"] == kind]
        cpu = [r for r in rows["cpu_lookup"] if r["kind"] == kind]
        release = [r for r in rows["normalize_release"] if r["kind"] == kind]
        if any([r["id"] for r in visits] != list(range(21)) for visits in (gpu,cpu,release)):
            raise ValueError("incomplete or repeated tree visits")
        summary[kind] = {
            "cpu_ns": sum(r["ns"] for r in cpu),
            "gpu_ns": sum(r["normalize_ns"] + r["wall_ns"] for r in gpu) + sum(r["ns"] for r in release),
            "h2d_bytes": sum(r["h2d_bytes"] for r in gpu),
            "d2h_bytes": sum(r["d2h_bytes"] for r in gpu),
        }
    if any(len(rows[tag]) != 42 for tag in ("lookup","cpu_lookup","normalize_release")):
        raise ValueError("unexpected tree visits")
    summary.update(summarize_batches(rows))
    if any(summary[name][field] <= 0 for name in ("top", "rebuild") for field in ("cpu_ns", "gpu_ns")):
        raise ValueError("empty lookup interval")
    return summary


def summarize_batches(rows):
    summary = {}
    batches = rows["batch"]
    ids = [r["id"] for r in batches]
    if len(ids) != 3 or len(set(ids)) != 3:
        raise ValueError("incomplete claim batches")
    for name in ("cpu_weights", "cpu_face", "finals"):
        if [r["id"] for r in rows[name]] != ids:
            raise ValueError("incomplete batch stages")
    summary["batch_prepare"] = {
        "cpu_ns": sum(r["ns"] for name in ("cpu_weights", "cpu_face") for r in rows[name]),
        "gpu_ns": sum(r["wall_ns"] for r in batches),
        "h2d_bytes": sum(r["h2d_bytes"] + r["term_bytes"] for r in batches),
    }
    if any("runs" in b for b in batches):
        packing = runpy.run_path(str(Path(__file__).with_name("packing.py")))
        stats = packing["summarize"](batches)
        for field in ("pool_used_high", "pool_reserved_high"):
            stats[field + "_through_batches"] = max(r[field] for r in rows["finals"])
        if not 0 < stats["pool_used_high_through_batches"] <= stats["pool_reserved_high_through_batches"]:
            raise ValueError("invalid device allocator high water")
        summary["batch_packing"] = stats
    schedule = []
    descriptors = 0
    for batch, final in zip(batches, rows["finals"]):
        domain = batch["rows"] * batch["columns"] // 2
        if domain < 2 or domain & (domain - 1) or batch["positions"] == 0:
            raise ValueError("invalid batch domain")
        n = domain.bit_length() - 1
        if final["rounds"] != n:
            raise ValueError("incomplete batch finals")
        schedule.extend((batch["id"], i) for i in range(n))
        descriptors += n * batch["round_h2d_bytes"]
    for name in ("round", "fold"):
        if [(r["id"], r["index"]) for r in rows[name]] != schedule:
            raise ValueError("incomplete batch rounds or folds")
    dense = rows["round"] + rows["fold"] + rows["finals"]
    summary["batch_dense"] = {
        "cpu_ns": sum(r["cpu_ns"] for r in dense),
        "gpu_ns": sum(r["gpu_ns"] for r in dense),
        "h2d_bytes": descriptors,
        "d2h_bytes": sum(r["d2h_bytes"] for r in rows["round"] + rows["finals"]),
    }
    if any(summary[name][field] <= 0 for name in ("batch_prepare", "batch_dense") for field in ("cpu_ns", "gpu_ns")):
        raise ValueError("empty timing interval")
    return summary
