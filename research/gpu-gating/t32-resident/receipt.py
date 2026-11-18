"""Validate all 21 tree lifetimes and actual GKR device views on T32."""
from collections import defaultdict
from pathlib import Path
import runpy


def check_resident_steps(steps, children, retained):
    """Each lookup has one final leaf. All earlier steps have the same live tree."""
    expected = []
    for index, (step, on_device, lookup, held, variables) in enumerate(steps):
        is_leaf = index + 1 == len(steps) or steps[index + 1][2] != lookup
        if held != (None if is_leaf else lookup):
            raise ValueError("resident lookup lifetime differs from the GKR schedule")
        if is_leaf:
            # A non-first leaf has one selector coordinate. Its domain equals
            # the number of leaf pairs in the complete root-first tree.
            if retained[lookup] != 32 * ((2 << variables) - 1):
                raise ValueError("resident tree size differs from the leaf geometry")
        elif on_device:
            first = index == 0 or steps[index - 1][2] != lookup
            layer = variables if first else variables - 1
            # RFC-0008 A7 emits both child sides for each p and q factor.
            view_bytes = 4 * 32 * (2 << layer)
            expected.append((step, lookup, 4, view_bytes))
    if [(r["step"], r["id"], r["views"], r["view_bytes"]) for r in children] != expected:
        raise ValueError("missing or reordered resident child")
    if {row["id"] for row in children} != set(range(len(retained))):
        raise ValueError("missing qualified lookup")
    for row in children:
        if retained[row["id"]] != row["retained_bytes"]:
            raise ValueError("incomplete resident layer view")
    return sum(r["views"] for r in children), sum(r["view_bytes"] for r in children)


def check_final_child_releases(early, steps):
    # Each release must occur on the successfully built penultimate GKR step.
    expected = {}
    for current, following in zip(steps, steps[1:]):
        if current[1] and current[2] == following[2]:
            expected[current[2]] = current[0]
    if early != expected or set(early) != {s[2] for s in steps}:
        raise ValueError("missing or misplaced final child release")
    for current, following in zip(steps, steps[1:]):
        if early[current[2]] == current[0] and following[3] is not None:
            raise ValueError("final child release precedes another nonleaf")


def summarize(log):
    gkr_report=runpy.run_path(str(Path(__file__).resolve().parent.parent/"t32-gkr/receipt.py"))["summarize"]
    gkr=gkr_report("\n".join(line for line in log.splitlines() if line.startswith("t32_gkr_")))
    rows=defaultdict(list)
    steps = []
    seen=None
    early = {}
    pending = None
    for line in log.splitlines():
        if not line.startswith("t32_"):
            continue
        tag,*fields=line.split()
        vals={}
        for field in fields:
            k,v=field.split("=")
            if k in vals or (k!="kind" and not v.isdecimal()):
                raise ValueError("invalid resident counter")
            vals[k]=v if k=="kind" else int(v)
        if pending is not None and tag != "t32_gkr_step":
            raise ValueError("final child release did not complete a device step")
        if tag=="t32_selected" and vals["kind"]=="rebuild":
            if seen is not None:
                raise ValueError("overlapping resident tree")
            seen=vals["id"]
        if tag=="t32_child" and seen!=vals["id"]:
            raise ValueError("resident child outside lookup lifetime")
        if tag=="t32_lookup_release":
            if seen!=vals["id"]:
                raise ValueError("wrong tree release")
            if "after_child_step" in vals:
                key = (vals["after_child_step"], seen)
                if (seen in early or not rows["t32_child"]
                        or key != (rows["t32_child"][-1]["step"], rows["t32_child"][-1]["id"])
                        or vals["release_ns"] != 0):
                    raise ValueError("invalid final child release")
                pending = key
                early[seen] = key[0]
            seen=None
        if tag in ("t32_gkr_step","t32_gkr_skip"):
            held = seen
            if pending is not None:
                if pending != (vals["step"], vals["lookup"]):
                    raise ValueError("wrong final child step")
                held = vals["lookup"]  # Owned during construction, released before round zero.
                pending = None
            steps.append((vals["step"], tag == "t32_gkr_step", vals["lookup"], held, vals["variables"]))
        else:
            rows[tag].append(vals)
    if pending is not None:
        raise ValueError("incomplete final child step")
    if early:
        check_final_child_releases(early, steps)
    batch_names=("batch","cpu_weights","cpu_face","round","fold","finals")
    batch_rows={k:rows.pop("t32_"+k) for k in batch_names}
    batch_report=runpy.run_path(str(Path(__file__).resolve().parent.parent/"t32-stages/receipt.py"))["summarize_batches"](batch_rows)
    if seen is not None or set(rows)!={"t32_gkr_cold","t32_cpu_lookup","t32_selected","t32_normalize_release","t32_child","t32_lookup_release"}:
        raise ValueError("incomplete resident coverage")
    if [r["id"] for r in batch_rows["batch"]] != [1265,1266,1267] or [r["rounds"] for r in batch_rows["finals"]] != [28,28,13]:
        raise ValueError("wrong ordinary T32 source or round schedule")
    report={"gkr":gkr,**batch_report}
    packing=Path(__file__).resolve().parent.parent/"t32-stages/packing.py"
    if packing.exists():
        report["batch_packing"]=runpy.run_path(str(packing))["summarize"](batch_rows["batch"])
    for field in ("runs","run_checks","host_pack_bytes","device_build_bytes"):
        if all(field in row for row in batch_rows["batch"]):
            report["batch_prepare"][field]=sum(row[field] for row in batch_rows["batch"])
    for kind in ("top","rebuild"):
        visits={}
        for name in ("t32_cpu_lookup","t32_selected","t32_normalize_release"):
            visits[name]=[r for r in rows[name] if r["kind"]==kind]
            if [r["id"] for r in visits[name]]!=list(range(21)) or len(rows[name])!=42:
                raise ValueError("incomplete lookup visits")
        gpu=visits["t32_selected"]
        for r in gpu:
            if kind=="top" and (r["compare_bytes"] or r["retained_bytes"] or r["d2h_bytes"]!=416):
                raise ValueError("unexpected selected top size")
            if kind=="rebuild" and (r["d2h_bytes"] or r["compare_bytes"]!=r["retained_bytes"] or r["compare_bytes"]<=0):
                raise ValueError("incomplete resident qualification")
        report[kind]=dict(cpu_ns=sum(r["ns"] for r in visits["t32_cpu_lookup"]),
            gpu_ns=sum(r["normalize_ns"]+r["wall_ns"] for r in gpu)+sum(r["ns"] for r in visits["t32_normalize_release"]),
            h2d_bytes=sum(r["h2d_bytes"] for r in gpu),d2h_bytes=sum(r["d2h_bytes"] for r in gpu),
            qualification_d2h_bytes=sum(r["compare_bytes"] for r in gpu),qualification_ns=sum(r["compare_ns"] for r in gpu))
    memory=rows["t32_selected"]
    if any(not (0 < r["pool_used_high"] <= r["pool_reserved_high"] <= r["total_bytes"]) for r in memory):
        raise ValueError("invalid lookup pool counter")
    report["pool_used_high_through_gkr"]=max(gkr["pool_used_high"],max(r["pool_used_high"] for r in memory))
    report["pool_reserved_high_through_gkr"]=max(gkr["pool_reserved_high"],max(r["pool_reserved_high"] for r in memory))
    releases=rows["t32_lookup_release"]
    if [r["id"] for r in releases]!=list(range(21)):
        raise ValueError("incomplete tree releases")
    rebuilt=[r for r in rows["t32_selected"] if r["kind"]=="rebuild"]
    if [r["retained_bytes"] for r in releases]!=[r["retained_bytes"] for r in rebuilt]:
        raise ValueError("incorrect resident release footprint")
    report["rebuild"]["gpu_ns"]+=sum(r["release_ns"] for r in releases)
    report["child_views"], report["child_addressable_bytes"] = check_resident_steps(
        steps, rows["t32_child"], [r["retained_bytes"] for r in rebuilt]
    )
    # Queued asynchronous frees of transient lookup buffers can finish on the
    # first qualification readback. Charging all readbacks bounds that cost.
    report["rebuild"]["gpu_with_qualification_ns"] = (
        report["rebuild"]["gpu_ns"] + report["rebuild"]["qualification_ns"]
    )
    return report
