"""Reconcile every private occurrence or shared layer window against the AF transfer census."""
from pathlib import Path
import runpy


def summarize(log):
    base=Path(__file__).resolve().parent.parent
    result=runpy.run_path(str(base/"t32-gkr-original/receipt.py"))["summarize"](log)
    def rows(tag):
        return [dict((k,int(v)) for k,v in (f.split("=") for f in line.split()[1:]))
                for line in log.splitlines() if line.startswith(tag+" ")]
    actual=rows("gkr_private")
    inputs=rows("gkr_inputs")
    if [r["step"] for r in actual]!=list(range(385)):
        raise ValueError("incomplete private GKR source coverage")
    sums={key:0 for key in ("mask_views","mask_bytes","block_views","block_bytes")}
    for r,i in zip(actual,inputs,strict=True):
        if r["checked_windows"] != r["mask_views"] + r["block_views"] or r["checked_bytes"] != r["mask_bytes"] + r["block_bytes"] or r["qualification_ns"] <= 0:
            raise ValueError("GKR private view differs from full original CPU comparison")
        if i["mask"] or i["block_mask"] or (i["block_challenge"]!=16*r["block_views"]):
            raise ValueError("private GKR upload or missing block challenge")
        if r["block_bytes"]!=64*r["block_views"] or not (r["mask_views"]>0 and 0<r["mask_bytes"]<=32*r["mask_views"]):
            raise ValueError("invalid T32 private window width")
        for key in sums:
            sums[key]+=r[key]
    sums["qualification_ns"]=sum(r["qualification_ns"] for r in actual)
    result["private_gkr_views"]=sums
    return result
