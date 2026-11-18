"""Account for actual T32 source preparation and both selected-response visits."""
from collections import defaultdict


def interval_union(intervals):
    stop = total = 0
    for left, right in sorted(intervals):
        if left >= right:
            raise ValueError("invalid preparation interval")
        total += max(0, right - max(stop, left))
        stop = max(stop, right)
    return total


def summarize(log):
    cold, preparations, visits = [], {}, defaultdict(dict)
    rows_expected = {0: 4096, 1: 4096, 2: 16, 3: 128, 1268: 16}
    for line in log.splitlines():
        if not line.startswith("t32_"):
            continue
        tag, *words = line.split()
        row = {}
        for word in words:
            key, value = word.split("=")
            if key in row or not value.isdecimal():
                raise ValueError("invalid source counter")
            row[key] = int(value)
        if tag == "t32_source_cold":
            cold.append(row["ns"])
            continue
        id_ = row["id"]
        if tag == "t32_source_prepare":
            if id_ in preparations:
                raise ValueError("duplicate original preparation")
            preparations[id_] = (row["cpu_start"], row["cpu_stop"])
            continue
        if tag != "t32_source" or row["opening"] not in (0, 1) or row["opening"] in visits[id_]:
            raise ValueError("unexpected/duplicate source visit")
        rows, cols, queries = row["rows"], row["cols"], row["queries"]
        if rows != rows_expected.get(id_) or cols < 2 or (cols & (cols - 1)) or (id_ in (0, 1) and cols != 131072):
            raise ValueError("unexpected source geometry")
        count = 4 * cols
        depth = count.bit_length() - 1
        # Every inverse/forward level, the eight-word key, the salt block and two prefixes.
        metadata = 4 * ((cols - 1) + (count - 1) + 8 + 16) + 2 * 43
        message = rows * cols * 4
        encoded = count * rows * 4
        nodes = (2 * count - 1) * 32
        wire = queries * (32 + rows * 4 + depth * 32)
        if (queries != (92 if row["opening"] else 222) or row["response_bytes"] != wire
                or row["d2h"] != 32 + wire - queries * 32 or row["h2d"] != metadata + message):
            raise ValueError("source transfer does not cover actual queries")
        if not (row["retained"] == encoded + nodes and row["peak"] == metadata + encoded + max(message, nodes)
                and row["retained"] <= row["peak"] <= row["device_total"] * 2 // 5
                and 0 < row["used_high"] <= row["reserved_high"]
                and row["reserved_high"] + row["outside_pool"] <= row["device_total"] * 2 // 5):
            raise ValueError("incorrect or over-budget device memory")
        prepare = sum(row[key] for key in ("upload_ns", "encode_ns", "merkle_ns"))
        charged = sum(row[key] for key in ("prepare_ns", "release_ns", "download_ns", "assemble_ns"))
        if row["prepare_ns"] < prepare or row["stop"] - row["start"] < charged + row["observe_ns"]:
            raise ValueError("incorrect device interval")
        visits[id_][row["opening"]] = row
    if (len(cold) != 1 or cold[0] <= 0 or set(preparations) != set(rows_expected)
            or set(visits) != set(rows_expected) or any(set(pair) != {0, 1} for pair in visits.values())):
        raise ValueError("incomplete hiding source coverage")
    all_rows = []
    for id_, pair in sorted(visits.items()):
        cert, opening = pair[0], pair[1]
        if cert["stop"] > opening["start"]:
            raise ValueError("reordered source visits")
        for key in ("rows", "cols", "h2d", "retained", "peak", "device_total", "cpu_start", "cpu_stop"):
            if cert[key] != opening[key]:
                raise ValueError("source changed between visits")
        for r in (cert, opening):
            if (r["cpu_start"], r["cpu_stop"]) != preparations[id_] or r["cpu_stop"] > r["start"]:
                raise ValueError("different CPU material")
            all_rows.append(r)
    device_intervals = [(r["start"], r["stop"]) for r in all_rows]
    full = sum(b - a for a, b in device_intervals)
    if interval_union(device_intervals) != full:
        raise ValueError("overlapping resident sources")
    return dict(cold_ns=cold[0], preparations=len(preparations), visits=len(all_rows),
                immutable_message_visits=len(all_rows), queries=sum(r["queries"] for r in all_rows),
                cpu_preparation_wall_ns=interval_union(preparations.values()),
                device_ns=full - sum(r["observe_ns"] for r in all_rows),
                host_oracle_compare_ns=sum(r["observe_ns"] for r in all_rows),
                upload_bytes=sum(r["h2d"] for r in all_rows), download_bytes=sum(r["d2h"] for r in all_rows),
                max_buffer_bytes=max(r["peak"] for r in all_rows),
                max_pool_reserved_bytes=max(r["reserved_high"] for r in all_rows),
                sources=all_rows)
