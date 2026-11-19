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


# H2D bytes for each actual compact top/rebuild in the 6784 source ledger evidence.
BASELINE = (2365372,661328,21344,1049884,4982228,385197584,87265440,37588052,14009100,
            13266628,20288844,13951944,35366960,12052456,856840,25172508,770352,3806276,
            1313188,74308,13117156)


def device_summary(log):
    cpu = summarize(log)
    visits = [dict(w.split("=") for w in line.split()[1:]) for line in log.splitlines()
              if line.startswith("t32_selected ")]
    checks = {}
    for kind in ("top","rebuild"):
        family = [r for r in visits if r["kind"] == kind]
        if [int(r["id"]) for r in family] != list(range(21)):
            raise ValueError("incomplete source lookup visit family")
        for r,c,old in zip(family,cpu["lookups"],BASELINE):
            legs=c["legs"]
            if (int(r["original_legs"]) != legs or int(r["view_bytes"]) != 24*legs or
                    int(r["h2d_bytes"]) != old-c["checked_bytes"]+24*legs):
                raise ValueError("wrong original lookup input or transferred bytes")
        checks[kind] = sum(int(r["h2d_bytes"]) for r in family)
    return dict(**cpu, original_legs=sum(x["legs"] for x in cpu["lookups"]),
                original_checked_bytes=sum(x["checked_bytes"] for x in cpu["lookups"]),
                view_bytes_per_family=24*sum(x["legs"] for x in cpu["lookups"]),
                charged_layout_ns=cpu["layout"]["ns"],
                qualification_ns=sum(x["ns"] for x in cpu["lookups"]), h2d_by_family=checks)
