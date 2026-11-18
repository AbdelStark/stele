"""Verify every phase reuses the actual source certificate owner from one pinned upload."""
from pathlib import Path
import runpy

def summarize(log):
    base=Path(__file__).resolve().parent.parent
    source_log="\n".join(s for s in log.splitlines() if s.startswith("t32_source"))
    other="\n".join(s for s in log.splitlines() if not s.startswith("t32_source"))
    source=runpy.run_path(str(base/"t32-source/receipt.py"))["summarize"](source_log)
    resident=runpy.run_path(str(base/"t32-resident/receipt.py"))["summarize"](other)
    states=runpy.run_path(str(base/"t32-resident/test_memory.py"))["check_memory"](other)
    if source["immutable_message_visits"] != 5 or source["queries"] != 1570:
        raise ValueError("incomplete original uploads or queries")
    live={}
    batches=[]
    binding={}
    total=0
    for line in log.splitlines():
        if not line.startswith(("t32_source ", "t32_batch ", "t32_gkr_step ")):
            continue
        tag,*fields=line.split()
        row={k:int(v) for k,v in (f.split("=") for f in fields)}
        if tag=="t32_source":
            i=row["id"]
            if row["opening"]:
                if live.pop(i,None) != row["original_bytes"] or row["original_upload"] != 0:
                    raise ValueError("opening lacks its pinned source")
            else:
                if i in live or i in binding or row["original_upload"] != row["original_bytes"]:
                    raise ValueError("repeated source upload")
                live[i]=binding[i]=row["original_bytes"]
                total+=row["original_upload"]
            if sum(live.values()) != row["originals_live"]:
                raise ValueError("wrong live original byte count")
        elif tag=="t32_batch":
            i=row["original_id"]
            if live.get(i)!=row["original_bytes"]:
                raise ValueError("ordinary batch lacks its certified original")
            batches.append((row["id"],i))
        elif set(live)!={0,1,2,3} or row["original_live"] != sum(live.values()):
            raise ValueError("GKR without all four original sources")
    if live or batches != [(1265,0),(1266,1),(1267,2)] or total!=4_299_292_672:
        raise ValueError("incomplete original lifetime")
    if resident["batch_packing"]["message_bytes"] != 0:
        raise ValueError("batch uploaded an original twice")
    return dict(**resident,source=source,original_uploads=len(binding),original_payload_bytes=total,
                original_live_bytes_during_gkr=sum(binding[i] for i in range(4)),
                original_gkr_steps=len(states))
