"""RFC-0014 A1: reconcile byte counts and tile work with the actual H100 schedule."""


def summarize(batches):
    if len(batches) != 3:
        raise ValueError("expected all three T32 batch sources")
    totals = dict(positions=0, runs=0, run_checks=0, packed_weights_bytes=0,
                  gamma_bytes=0, schedule_bytes=0, message_bytes=0, h2d_bytes=0,
                  index_ns=0, group_ns=0, upload_ns=0, build_ns=0, setup_ns=0,
                  max_host_pack_bytes=0, max_device_build_bytes=0)
    for b in batches:
        rows, columns, tile = b["rows"], b["columns"], b["tile"]
        if any(n <= 0 or n & (n-1) for n in (rows, columns, tile)) or min(rows, columns) < 2:
            raise ValueError("invalid power-of-two batch geometry")
        message = rows * columns * 4
        half = rows * columns // 4
        entries, claims, runs = b["positions"], b["claims"], b["runs"]
        if not 0 < runs <= entries <= b["run_checks"] or b["run_checks"] != min(half, tile) * runs:
            raise ValueError("inconsistent T32 tile schedule")
        weights = entries * 16
        gamma = claims * 16
        schedule = runs * 32 + (1 + (half + tile - 1) // tile) * 8
        h2d = message + weights + gamma + schedule
        if b["index_ns"] > b["group_ns"]:
            raise ValueError("index timing exceeds its containing stage")
        if not claims or h2d != b["h2d_bytes"] or b["host_pack_bytes"] < h2d:
            raise ValueError("inconsistent source packing or transfer")
        if b["device_build_bytes"] != h2d + 20 * (2 * half):
            raise ValueError("inconsistent construction allocation")
        for key in ("positions", "runs", "run_checks", "index_ns", "group_ns", "upload_ns", "build_ns", "setup_ns"):
            totals[key] += b[key]
        for key, count in (("packed_weights_bytes", weights), ("gamma_bytes", gamma),
                           ("schedule_bytes", schedule), ("message_bytes", message), ("h2d_bytes", h2d)):
            totals[key] += count
        for key in ("host_pack_bytes", "device_build_bytes"):
            totals["max_" + key] = max(totals["max_" + key], b[key])
    return totals
