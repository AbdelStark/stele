"""Check that all original lookup families compared every base limb."""
def summarize(log):
    def rows(prefix):
        return [dict((a, int(b)) for a, b in (word.split("=") for word in s.split()[1:]))
                for s in log.splitlines() if s.startswith(prefix+" ")]
    layout = rows("alias_layout")
    lookups = rows("alias_lookup")
    if len(layout) != 1 or [x["id"] for x in lookups] != list(range(21)):
        raise ValueError("missing T32 original lookup/plan")
    for x in lookups:
        if not (0 < x["unique"] <= x["legs"] and 0 <= x["straddling"] <= x["unique"] and
                0 < x["cells"] and x["checked_bytes"] == 4*x["cells"] and x["source_mask"] > 0 and
                x["source_mask"] < (1 << layout[0]["sources"])):
            raise ValueError("inconsistent source geometry receipt")
    if not any(x["straddling"] for x in lookups):
        raise ValueError("missing original data-row crossings")
    return {"layout": layout[0], "lookups": lookups}
