"""Reconstruct the three observed payloads from the qualified 6781 schedule."""
import statistics


# Rows, committed columns, claim and original sparse-position counts, tile runs.
SHAPES = {
    1265: (4096, 131072, 12688, 221697374, 1751280),
    1266: (4096, 131072, 403, 176284236, 1377812),
    1267: (16, 1024, 126, 4536, 217),
}


def fields(line):
    return {k: v if k == "method" else int(v)
            for k, v in (item.split("=") for item in line.split()[1:])}


def require(ok):
    if not ok:
        raise ValueError("incomplete, inconsistent or wrong T32 batch sample")


def summarize(log):
    def rows(prefix):
        return [fields(line) for line in log.splitlines() if line.startswith(prefix + " ")]
    sources, matches, samples = rows("host_source"), rows("host_match"), rows("host_pack")
    require([r["id"] for r in sources] == list(SHAPES))
    require([r["id"] for r in matches] == list(SHAPES))
    require([r["id"] for r in samples] == [i for i in SHAPES for _ in range(8)])
    totals = {method: [0]*4 for method in ("serial", "parallel")}
    for source, match in zip(sources, matches):
        id = source["id"]
        shape = SHAPES[id]
        require(tuple(match[k] for k in ("rows", "columns", "claims", "positions", "runs")) == shape)
        r, c, claims, positions, runs = shape
        offsets = (r*c//4 + 127)//128 + 1
        payload = r*c*4 + positions*16 + claims*16 + runs*32 + offsets*8
        require(match["offsets"] == offsets and match["payload_bytes"] == payload)
        require(match["tuples_bytes"] == match["tuple_width"] * positions)
        require(match["tuple_capacity_bytes"] >= match["tuples_bytes"])
        require(match["descriptor_bytes"] > 0 and match["message_bytes"] == r*c*4)
        require(match["gamma_bytes"] == claims*16 and match["claim_headers_bytes"] > 0)
        for j, sample in enumerate(row for row in samples if row["id"] == id):
            rep, order = divmod(j, 2)
            method = ("serial", "parallel")[(id + rep + order) % 2]
            require((sample["rep"], sample["order"], sample["method"]) == (rep, order, method))
            require(sample["h2d_payload_bytes"] == payload and sample["output_bytes"] >= payload)
            require(sample["scratch_bytes"] == ((claims+1)*8 if method == "parallel" else 0))
            require(sample["group_ns"] >= sum(sample[k+"_ns"] for k in
                    ("index", "alloc", "split", "runs", "message", "weights")))
            require(sample["wall_ns"] >= sum(sample[k+"_ns"] for k in ("decode", "group", "drop")))
            # Add actual encoding once to each alternative; decode and release already in wall.
            totals[method][rep] += source["encode_ns"] + sample["wall_ns"]
    medians = {method: statistics.median(values) for method, values in totals.items()}
    return {"source_encoding": sources, "elementwise_matches": matches, "samples": samples,
            "three_batch_totals_ns": totals, "median_three_batch_ns": medians,
            "parallel_wins_all_pairs": all(b < a for a, b in zip(totals["serial"], totals["parallel"]))}
