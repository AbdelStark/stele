"""Account for every CPU GKR step and both the charged and unaccelerated costs."""
from collections import Counter


def summarize(log):
    rows = []
    cold = []
    for line in log.splitlines():
        if not line.startswith("t32_"):
            continue
        kind, *items = line.split()
        row = {}
        for item in items:
            key, value = item.split("=")
            if key in row or not value.isdecimal():
                raise ValueError("invalid GKR counter")
            row[key] = int(value)
        if kind == "t32_gkr_cold":
            cold.append(row["ns"])
        elif kind in ("t32_gkr_step", "t32_gkr_skip"):
            row["accepted"] = kind == "t32_gkr_step"
            rows.append(row)
        else:
            raise ValueError("unexpected workload stage")
    if len(cold) != 1 or cold[0] <= 0 or [row["step"] for row in rows] != list(range(385)):
        raise ValueError("incomplete GKR steps or cold setup")
    ids = [row["lookup"] for row in rows]
    if ids != sorted(ids) or set(ids) != set(range(21)):
        raise ValueError("wrong lookup schedule")
    totals = Counter()
    gpu = []
    for row in rows:
        if not 0 < row["variables"] <= 30 or not row["cpu_wall_ns"]:
            raise ValueError("invalid GKR geometry or CPU wall")
        totals["cpu_factors_ns"] += row["cpu_factors_ns"]
        totals["cpu_rounds_wall_ns"] += row["cpu_wall_ns"]
        if not row["accepted"]:
            if row["required_bytes"] <= row["available_bytes"]:
                raise ValueError("unjustified budget rejection")
            totals["retained_cpu_ns"] += row["cpu_wall_ns"] + row["cpu_factors_ns"]
            totals["device_path_ns"] += row["attempt_ns"]
            continue
        if not (0 < row["cpu_arithmetic_ns"] <= row["cpu_wall_ns"]
                and 0 < row["retained_bytes"] <= row["planned_bytes"] <= row["total_bytes"] * 2 // 5
                and 0 < row["pool_used_high"] <= row["pool_reserved_high"] <= row["total_bytes"]
                and row["input_bytes"] and row["descriptor_bytes"] and row["d2h_bytes"]):
            raise ValueError("invalid GKR stage costs")
        gpu.append(row)
        totals["retained_cpu_ns"] += row["cpu_wall_ns"] - row["cpu_arithmetic_ns"]
        for key in ("build_ns", "round_ns", "fold_ns", "finish_ns"):
            totals["device_path_ns"] += row[key]
        totals["h2d_bytes"] += row["input_bytes"] + row["descriptor_bytes"] + row["round_h2d_bytes"]
        totals["d2h_bytes"] += row["d2h_bytes"]
    if not gpu:
        raise ValueError("no actual device work")
    return {"cold_ns": cold[0], "steps": len(rows), "on_device": len(gpu),
            "budget_rejections": len(rows) - len(gpu), "charged": dict(totals),
            "pool_reserved_high": max(row["pool_reserved_high"] for row in gpu),
            "pool_used_high": max(row["pool_used_high"] for row in gpu)}
