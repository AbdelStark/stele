#!/usr/bin/env python3
"""E16-35: medians of the box runs and the dev-zk stories42M Amdahl ceiling (ADR-123).

  python3 summarize.py <box out dir> [<mac out dir>]

Box files: gpu-<shape>-<n>-<rep>.txt, cpu-main-..., cpu-pr364-... (run.sh); Mac files:
cpu-mac-<shape>-<n>-<rep>.txt. Times in the files are integer nanoseconds.
"""
import re
import statistics
import sys
from pathlib import Path

SHAPES, SIZES = ('relation', 'gkr'), (20, 22, 24, 26, 27)
# bench/ledger/e16-22-dev-zk-stories42m-t32-mac-after.json stage laps (ns).
LAPS = {'gkr': 173_236_000_000, 'relations': 35_174_000_000, 'trees': 24_957_000_000,
        'batches': 21_352_000_000, 'sources': 103_531_000_000}
WALL = 465_720_000_000
# Bytes a shape uploads (columns or layer halves; the points, periods and blocks are
# under 2 KiB), and the box's measured pageable host-to-device rate (h2d.txt, 1 GiB).
UPLOAD_BYTES = {'relation': lambda n: 3 * 4 << n, 'gkr': lambda n: 4 * 16 << (n - 1)}
PAGEABLE_BYTES_PER_S = 1_073_741_824 / 0.0605
# E16-21 ratios (bench/ledger/e16-21-gpu-gating.json), lowest and highest measured.
E16_21 = {'rounds-only': (25.4, 76.1), 'upload-inclusive': (2.9, 15.9)}


def read(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        m = re.fullmatch(r'([a-z_]+)(?:\[(\d+)\])?=(.*)', line)
        if m:
            key, idx, val = m.groups()
            if idx is None:
                out[key] = val
            else:
                out.setdefault(key, {})[int(idx)] = int(val)
    return out


def median_run(files, key):
    runs = [read(f) for f in files if f.exists()]
    runs = [r for r in runs if key in r]
    if not runs:
        return None
    return sorted(runs, key=lambda r: int(r[key]))[len(runs) // 2]


def ceiling(s_masked, s_rest):
    masked = LAPS['gkr'] + LAPS['relations']
    rest = LAPS['trees'] + LAPS['batches'] + LAPS['sources']
    resid = WALL - masked - rest
    return WALL / (resid + masked / s_masked + (0 if s_rest is None else rest / s_rest))


def main():
    box = Path(sys.argv[1])
    mac = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    table = {}
    for shape in SHAPES:
        for n in SIZES:
            files = lambda kind: [box / f'{kind}-{shape}-{n}-{rep}.txt' for rep in (1, 2, 3)]
            g = median_run(files('gpu'), 'gpu_rounds_total_ns')
            c = median_run(files('cpu-main'), 'cpu_rounds_total_ns')
            p = median_run(files('cpu-pr364'), 'cpu_rounds_total_ns')
            m = median_run([mac / f'cpu-mac-{shape}-{n}-{rep}.txt' for rep in (1, 2, 3)],
                           'cpu_rounds_total_ns') if mac else None
            if not (g and c):
                continue
            row = {'gpu': int(g['gpu_rounds_total_ns']), 'upload': int(g['gpu_upload_ns']),
                   'bus': int(UPLOAD_BYTES[shape](n) / PAGEABLE_BYTES_PER_S * 1e9),
                   'build': int(g['gpu_build_ns']), 'cpu_main': int(c['cpu_rounds_total_ns']),
                   'cpu_build': int(c['cpu_build_ns']), 'threads': c['cpu_threads'],
                   'gpu_r0': g['gpu_round_ns'][0] + g['gpu_fold_ns'][0],
                   'cpu_r0': c['cpu_round_ns'][0] + c['cpu_fold_ns'][0],
                   'gpu_r1': g['gpu_round_ns'][1] + g['gpu_fold_ns'][1],
                   'cpu_r1': c['cpu_round_ns'][1] + c['cpu_fold_ns'][1],
                   'fnv': (g['fnv'], c['fnv'], p['fnv'] if p else None)}
            if p:
                row['cpu_pr364'] = int(p['cpu_rounds_total_ns'])
                row['cpu_pr364_build'] = int(p['cpu_build_ns'])
            if m:
                row['cpu_mac'] = int(m['cpu_rounds_total_ns'])
                row['cpu_mac_build'] = int(m['cpu_build_ns'])
            table[(shape, n)] = row
    for (shape, n), r in table.items():
        dev = r['gpu']
        cpu = best_rounds(r)
        print(f"{shape:8} 2^{n}: CPU rounds main {r['cpu_main']/1e9:.3f} s, pr364 {r.get('cpu_pr364', 0)/1e9:.3f} s, "
              f"CPU build {r['cpu_build']/1e9:.3f} s; GPU rounds {dev/1e9:.4f} s, upload {r['upload']/1e9:.3f} s, "
              f"build {r['build']/1e9:.4f} s, bus-bound upload {r['bus']/1e9:.3f} s; rounds-only {cpu/dev:.1f}x; stage (build+rounds, upload counted) "
              f"{best_stage(r)/(dev+r['upload']+r['build']):.1f}x; at bus-bound upload {best_stage(r)/(dev+r['bus']+r['build']):.1f}x; stage without upload {best_stage(r)/(dev+r['build']):.1f}x; "
              f"round 0 {r['cpu_r0']/r['gpu_r0']:.1f}x, round 1 {r['cpu_r1']/r['gpu_r1']:.1f}x; "
              f"fnv equal {len(set(x for x in r['fnv'] if x)) == 1}"
              + (f"; Mac CPU rounds {r['cpu_mac']/1e9:.3f} s, build {r['cpu_mac_build']/1e9:.3f} s" if 'cpu_mac' in r else ''))
    big = [r for (s, n), r in table.items() if n >= 24]
    if not big:
        return
    hosts = [('box CPU', best_rounds, best_stage)]
    if all('cpu_mac' in r for r in big):
        hosts.append(('Mac CPU (the laps host)', lambda r: r['cpu_mac'], lambda r: r['cpu_mac'] + r['cpu_mac_build']))
    for label, rounds, stage in hosts:
        ratios = {'rounds-only, resident': [rounds(r) / r['gpu'] for r in big],
                  'stage, device-built, no upload': [stage(r) / (r['gpu'] + r['build']) for r in big],
                  'stage, device-built, bus-bound upload': [stage(r) / (r['gpu'] + r['build'] + r['bus']) for r in big],
                  'stage, device-built, measured upload phase': [stage(r) / (r['gpu'] + r['build'] + r['upload']) for r in big]}
        print(f'\n{label}, sizes 2^24..2^27:')
        for name, v in ratios.items():
            lo, hi = min(v), max(v)
            print(f'  {name}: s {lo:.1f}..{hi:.1f}; ceiling, every offloadable stage at s: '
                  f'{ceiling(lo, lo):.2f}x..{ceiling(hi, hi):.2f}x; masked+GKR at s, rest at E16-21 rounds-only '
                  f'{ceiling(lo, E16_21["rounds-only"][0]):.2f}x..{ceiling(hi, E16_21["rounds-only"][1]):.2f}x, '
                  f'at E16-21 upload-inclusive {ceiling(lo, E16_21["upload-inclusive"][0]):.2f}x..'
                  f'{ceiling(hi, E16_21["upload-inclusive"][1]):.2f}x; rest on CPU {ceiling(lo, 1):.2f}x..{ceiling(hi, 1):.2f}x')
    print(f'\nunbounded (every offloadable stage free): {ceiling(float("inf"), None):.2f}x')


def best_rounds(r):
    return min(r['cpu_main'], r.get('cpu_pr364', r['cpu_main']))


def best_stage(r):
    return min(r['cpu_main'] + r['cpu_build'], r.get('cpu_pr364', 10**30) + r.get('cpu_pr364_build', 0))


if __name__ == '__main__':
    main()
