"""Reconcile device-authored relations with the original CPU proof's independent geometry."""
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import json


def records(log, name):
    for line in log.splitlines():
        if not line.startswith(name + ' '):
            continue
        pairs = [word.split('=', 1) for word in line.split()[1:]]
        values = {key: int(value) for key, value in pairs}
        if len(values) != len(pairs) or any(n < 0 for n in values.values()):
            raise ValueError('invalid device receipt')
        yield values


def expected_shape(r):
    n, degree, masks, terms = (r[k] for k in ('variables','degree','masks','terms'))
    if r['field'] != 4 or r['compact']:
        raise ValueError('expected ordinary QM31 relations')
    descriptors = 4*(len(terms)+1+max(1,sum(map(len,terms))))+16*max(1,len(terms))
    return n, degree, len(masks), len(terms), 4*(1 << n)*sum(v is not None for v in masks), descriptors


def summarize(log, inventory):
    rows = list(records(log, 'relation_gpu'))
    total, = records(log, 'relation_gpu_complete')
    expected = Counter()
    for shape in inventory['shapes']:
        if shape['kind'] == 'relation':
            expected[expected_shape(shape)] += shape['count']
    keys=('vars','degree','factors','terms','masks_h2d','descriptors_h2d')
    if Counter(tuple(r[k] for k in keys) for r in rows) != expected or sum(expected.values()) != inventory['declared']['relations']:
        raise ValueError('relation geometry differs from original CPU inventory')
    if [r['id'] for r in rows] != list(range(len(rows))) or total != dict(relations=len(rows), **{
            key:sum(r[key] for r in rows) for key in ('rounds','folds','finals')}):
        raise ValueError('incomplete relation sequence')
    groups=defaultdict(Counter)
    for r in rows:
        n, factors, degree = r['vars'], r['factors'], r['degree']
        if (r['admitted'] != 1 or r['cpu_returned'] or r['rounds'] != n or r['folds'] != n or r['finals'] != factors
                or r['values_h2d'] != 16*(1 << n)*factors or r['round_h2d'] != 20*n*factors
                or r['d2h'] != 16*(n*(degree+1)+factors)):
            raise ValueError('incomplete or incorrect device return or transfer')
        if (r['peak_bytes'] < r['values_h2d']+r['masks_h2d']+r['descriptors_h2d']+20*factors
                or not 0 <= r['pool_used'] <= r['pool_reserved'] <= r['pool_high'] <= r['total_bytes']
                or r['free_bytes'] > r['total_bytes'] or r['total_bytes'] <= 0
                or max(0,r['total_bytes']-r['free_bytes']-r['pool_reserved'])+r['pool_high'] > r['total_bytes']//5*2):
            raise ValueError('unqualified relation memory peak')
        times=('host_factors_ns','build_ns','device_ns','cpu_oracle_ns')
        if min(r[k] for k in times) <= 0:
            raise ValueError('incomplete timing')
        group=groups[n]
        group['relations'] += 1
        for key in (*times,'rounds','folds','finals','values_h2d','masks_h2d','descriptors_h2d','round_h2d','d2h'):
            group[key] += r[key]
        group['paired_device_faster'] += r['build_ns']+r['device_ns'] < r['cpu_oracle_ns']
        group['largest_preflight_bytes']=max(group['largest_preflight_bytes'],r['peak_bytes'])
        group['largest_pool_high_bytes']=max(group['largest_pool_high_bytes'],r['pool_high'])
    return dict(coverage=total, by_variables={str(n):v for n,v in sorted(groups.items())},
                paired_comparison='Both routes require the original host factor construction. Device time includes staging, synchronized rounds, folds, finals and release.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('log',type=Path)
    p.add_argument('cpu_ledger',type=Path)
    a=p.parse_args()
    inventory=json.loads(a.cpu_ledger.read_text())['model_config']['stage_inventory']
    print(json.dumps(summarize(a.log.read_text(),inventory),indent=2,sort_keys=True))
