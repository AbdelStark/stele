"""Account each original column read and every explicit GKR H2D copy on T32."""
from pathlib import Path
import runpy


def summarize(log):
    base=Path(__file__).resolve().parent.parent
    result=runpy.run_path(str(base/"t32-original/receipt.py"))["summarize"](log)
    aliases=runpy.run_path(str(base/"t32-alias/receipt.py"))["device_summary"](log)
    result["lookup_original_views"]=aliases
    def rows(prefix):
        return [dict((k,int(v)) for k,v in (item.split("=") for item in line.split()[1:]))
                for line in log.splitlines() if line.startswith(prefix+" ")]
    records=rows("gkr_inputs")
    ordinary=rows("t32_gkr_step")
    ids=list(range(385))
    if [r["step"] for r in records]!=ids or [r["step"] for r in ordinary]!=ids:
        raise ValueError("incomplete GKR source-copy accounting")
    leaf=[r for r in records if r["leaf"]==1]
    if [r["lookup"] for r in leaf]!=list(range(21)):
        raise ValueError("wrong original GKR leaf schedule")
    for r,v in zip(leaf,aliases["lookups"]):
        # On this workload every lookup leg has a distinct actual base column.
        if v["unique"]!=v["legs"] or r["original_views"]!=v["legs"] or r["addressable_bytes"]!=v["checked_bytes"] or r["column"]!=0:
            raise ValueError("GKR original column multiplicity/extent mismatch")
    sums={}
    categories=("equality","block_challenge","block_mask","column","mask","layer","table_challenge","table","selector")
    for r,v in zip(records,ordinary):
        if not r["leaf"] and (r["original_views"] or r["addressable_bytes"]):
            raise ValueError("nonleaf borrowed a statement leaf column")
        if r["leaf"] not in (0,1) or r["lookup"]!=v["lookup"] or r["inputs"]!=v["input_bytes"] or r["descriptors"]!=v["descriptor_bytes"] or sum(r[k] for k in categories)!=r["inputs"] or r["coordinates"]+r["terms"]!=r["descriptors"]:
            raise ValueError("GKR explicit copy totals failed to reconcile")
        for k in (*categories,"coordinates","terms","inputs","descriptors","original_views","addressable_bytes"):
            sums[k]=sums.get(k,0)+r[k]
    result["gkr_source_inputs"]=sums
    return result
