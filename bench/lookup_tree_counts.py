"""RFC-0014 A6. Check top, rebuild and retained-child calls against the verified A7 scope."""
import re

FIELDS = ("tops", "rebuilds", "child_views", "child_released", "h2d_bytes", "d2h_bytes",
          "planned_peak_bytes", "observed_peak_bytes")


def check_lookup_work(fields, verified, limit):
    checks = [int(x) for x in re.findall(r"^LU\tcheck (\d+)\t", verified, re.M)]
    groups = [list() for _ in checks]
    steps = re.findall(r"^SC\tcheck (\d+) step (\d+)\t", verified, re.M)
    if not checks or checks != list(range(len(checks))):
        raise ValueError("missing verified lookup roots")
    for expected, (group, step) in enumerate(steps):
        group = int(group)
        if group >= len(checks) or expected != int(step):
            raise ValueError("incorrect verified lookup step")
        groups[group].append(expected)
    if any(not group or group != list(range(group[0], group[0] + len(group))) for group in groups):
        raise ValueError("missing or noncontiguous verified lookup steps")
    rebuilds = sum(len(group) > 1 for group in groups)
    geometry = (len(checks), rebuilds, 4 * (len(steps) - len(checks)), rebuilds)
    # QM31 has four limbs and c_D = log2(D) = 2. A7's k0=c_D+1 yields eight [p,q] pairs.
    if (set(fields) != set(FIELDS) or tuple(fields[k] for k in FIELDS[:4]) != geometry
            or fields["d2h_bytes"] != len(checks) * 8 * 32 or fields["h2d_bytes"] <= 0
            or not 0 < fields["planned_peak_bytes"] <= limit
            or not 0 < fields["observed_peak_bytes"] <= limit):
        raise ValueError("lookup tree work differs from the authenticated proof schedule or cap")
    return fields
