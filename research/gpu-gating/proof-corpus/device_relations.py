"""RFC-0014 §5. Authenticate the origin of the relation messages in one complete proof."""
import re


def numbers(line):
    row = {}
    for word in line.split()[1:]:
        key, value = word.split("=", 1)
        if key in row or not value.isascii() or not value.isdecimal():
            raise ValueError("invalid device relation counter")
        row[key] = int(value)
    return row


def summarize(log, verifier):
    rows = [numbers(s) for s in log.splitlines() if s.startswith("relation_gpu ")]
    end = [numbers(s) for s in log.splitlines() if s.startswith("relation_gpu_complete ")]
    sizes = re.findall(r"^dev-zk: (\d+) relation instances, \d+ GKR steps, \d+ batches, (\d+) proof bytes$",
                       verifier, re.MULTILINE)
    if len(sizes) != 1 or not rows or len(rows) != int(sizes[0][0]) or len(end) != 1:
        raise ValueError("incomplete device relation proof")
    if [r["id"] for r in rows] != sorted({r["id"] for r in rows}):
        raise ValueError("duplicated or reordered device relation")
    for r in rows:
        if (r["admitted"] != 1 or r["cpu_returned"] != 0 or r["rounds"] != r["vars"]
                or r["folds"] != r["vars"] or r["finals"] != r["factors"]
                or r["d2h"] < 16 * (r["rounds"] + r["finals"])):
            raise ValueError("CPU return or incomplete device rounds, folds or finals")
    total = {k: sum(r[k] for r in rows) for k in ("rounds", "folds", "finals")}
    if (total["rounds"] <= 0 or total["finals"] <= 0 or end[0]["relations"] != len(rows)
            or any(end[0][k] != v for k, v in total.items())):
        raise ValueError("device totals disagree")
    return dict(relations=len(rows), proof_bytes=int(sizes[0][1]), **total)
