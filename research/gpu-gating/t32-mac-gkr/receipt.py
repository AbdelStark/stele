"""Reconcile disjoint GKR costs against the H100 geometry used for calibration."""
from collections import Counter


def counters(line):
    fields = [field.split('=', 1) for field in line.split()[1:]]
    if any(len(item) != 2 or not item[1].isdecimal() for item in fields):
        raise ValueError('invalid timing counter')
    row = {key: int(value) for key, value in fields}
    if len(row) != len(fields):
        raise ValueError('duplicate counter')
    return row


def summarize(mac_log, h100_log):
    rows = [counters(l) for l in mac_log.splitlines() if l.startswith('mac_gkr ')]
    observed = [counters(l) for l in h100_log.splitlines()
                if l.startswith(('t32_gkr_step ', 't32_gkr_skip '))]
    if len(rows) != 385 or len(observed) != 385:
        raise ValueError('incomplete GKR inventory')
    totals = Counter()
    for index, (r, ref) in enumerate(zip(rows, observed)):
        if ((r['step'], r['lookup'], r['vars']) != (index, ref['lookup'], ref['variables'])
                or ref['step'] != index or r['compact'] not in (0, 1)
                or not 1 <= r['vars'] <= 30 or r['calls'] != 2 * r['vars']):
            raise ValueError('changed step geometry')
        if not (0 < r['table_ns'] <= r['factor_ns'] and 0 < r['arithmetic_ns'] <= r['rounds_ns']):
            raise ValueError('overlapping or empty interval')
        for name in ('factor_ns','table_ns','rounds_ns','arithmetic_ns'):
            totals[name] += r[name]
        totals['host_factor_ns'] += r['factor_ns'] - r['table_ns']
        totals['host_round_ns'] += r['rounds_ns'] - r['arithmetic_ns']
        if r['compact']:
            totals['compact_host_factor_ns'] += r['factor_ns'] - r['table_ns']
    lookups = [r['lookup'] for r in rows]
    if lookups != sorted(lookups) or set(lookups) != set(range(21)):
        raise ValueError('wrong lookup order')
    if [bool(r['compact']) for r in rows] != [i == 384 or lookups[i+1] != l for i,l in enumerate(lookups)]:
        raise ValueError('wrong compact leaf membership')
    return dict(totals)
