"""Validate all 21 tree lifetimes and actual GKR device views on T32."""
from collections import defaultdict
from pathlib import Path
import runpy


def summarize(log):
    gkr_report=runpy.run_path(str(Path(__file__).resolve().parent.parent/"t32-gkr/receipt.py"))["summarize"]
    gkr=gkr_report("\n".join(line for line in log.splitlines() if line.startswith("t32_gkr_")))
    rows=defaultdict(list)
    accepted={}
    seen=None
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
        if tag=="t32_selected" and vals["kind"]=="rebuild":
            if seen is not None:
                raise ValueError("overlapping resident tree")
            seen=vals["id"]
        if tag=="t32_child" and seen!=vals["id"]:
            raise ValueError("resident child outside lookup lifetime")
        if tag=="t32_lookup_release":
            if seen!=vals["id"]:
                raise ValueError("wrong tree release")
            seen=None
        if tag in ("t32_gkr_step","t32_gkr_skip"):
            accepted[vals["step"]]=(tag=="t32_gkr_step",vals["lookup"],seen is not None)
        else:
            rows[tag].append(vals)
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
    expected=[(s,i) for s,(ok,i,held) in accepted.items() if ok and held]
    child=rows["t32_child"]
    if [(r["step"],r["id"]) for r in child]!=expected or any(r["views"]<=0 or r["view_bytes"]<=0 or r["retained_bytes"]!=rebuilt[r["id"]]["retained_bytes"] for r in child):
        raise ValueError("missing or wrong resident child views")
    if not child or set(r["id"] for r in child)!=set(range(21)):
        raise ValueError("insufficient resident lookup coverage")
    report["child_views"]=sum(r["views"] for r in child)
    report["child_addressable_bytes"]=sum(r["view_bytes"] for r in child)
    return report
