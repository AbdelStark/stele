"""Account each original column read and every explicit GKR H2D copy on T32."""
from pathlib import Path
import runpy


FIELDS = ("equality", "block_challenge", "block_mask", "column", "mask", "layer",
          "table_challenge", "table", "selector")
DESCRIPTORS = ("coordinates", "terms")


def account_inputs(records, ordinary, lookups):
    """The original CPU schedule identifies the final GKR step of each lookup."""
    expected = [row["id"] for row in lookups]
    if len(records) != len(ordinary) or len(set(expected)) != len(expected):
        raise ValueError("incomplete GKR source-copy accounting")
    lookup_ids = [row["lookup"] for row in ordinary]
    leaf_indices = {i for i, lookup in enumerate(lookup_ids)
                    if i + 1 == len(lookup_ids) or lookup != lookup_ids[i + 1]}
    if [lookup_ids[i] for i in sorted(leaf_indices)] != expected:
        raise ValueError("unrecognized CPU lookup schedule")
    columns = {row["id"]: row for row in lookups}
    totals = dict.fromkeys((*FIELDS, *DESCRIPTORS, "inputs", "descriptors",
                            "original_views", "addressable_bytes"), 0)
    for i, (record, reference) in enumerate(zip(records, ordinary)):
        if any(record[field] < 0 for field in totals):
            raise ValueError("negative GKR transfer or view extent")
        if record["leaf"] != int(i in leaf_indices) or record["lookup"] != lookup_ids[i]:
            raise ValueError("wrong original GKR leaf schedule")
        if i in leaf_indices:
            # All original lookup legs on this public T32 plan have distinct base columns.
            view = columns[record["lookup"]]
            if (view["unique"] != view["legs"] or record["original_views"] != view["legs"]
                    or record["addressable_bytes"] != view["checked_bytes"] or record["column"]):
                raise ValueError("GKR original column multiplicity/extent mismatch")
        elif record["original_views"] or record["addressable_bytes"]:
            raise ValueError("nonleaf borrowed a statement leaf column")
        if (record["inputs"] != reference["input_bytes"]
                or record["descriptors"] != reference["descriptor_bytes"]
                or sum(record[k] for k in FIELDS) != record["inputs"]
                or sum(record[k] for k in DESCRIPTORS) != record["descriptors"]):
            raise ValueError("GKR explicit copy totals failed to reconcile")
        for key in totals:
            totals[key] += record[key]
    return totals


def summarize(log):
    base = Path(__file__).resolve().parent.parent
    result = runpy.run_path(str(base / "t32-original/receipt.py"))["summarize"](log)
    aliases = runpy.run_path(str(base / "t32-alias/receipt.py"))["device_summary"](log)

    def rows(prefix):
        return [dict((k, int(v)) for k, v in (item.split("=") for item in line.split()[1:]))
                for line in log.splitlines() if line.startswith(prefix + " ")]

    records = rows("gkr_inputs")
    ordinary = rows("t32_gkr_step")
    ids = list(range(385))
    if [r["step"] for r in records] != ids or [r["step"] for r in ordinary] != ids:
        raise ValueError("incomplete GKR source-copy accounting")
    result["lookup_original_views"] = aliases
    result["gkr_source_inputs"] = account_inputs(records, ordinary, aliases["lookups"])
    return result
