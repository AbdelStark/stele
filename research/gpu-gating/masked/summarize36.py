#!/usr/bin/env python3
"""E16-36: medians of the box runs and the dev-zk stories42M ceiling on current main (ADR-127).

  python3 summarize36.py <box out dir> <mac out dir>

Box files (run36.sh): source-{gpu,cpu}-11-<m>-<rep>.txt, gpu-/cpu-main-<shape>-<n>-<rep>.txt.
Mac files: source-cpu-11-16-<rep>.txt, cpu-mac-<shape>-<n>-<rep>.txt. Integer ns.
"""
import re
import sys
from pathlib import Path

# bench/ledger/e16-36-dev-zk-stories42m-t32-mac.json laps (ns), one run on main after E16-34.
LAPS = {'gkr': 153_188_000_000, 'relations': 22_452_000_000, 'sources': 28_341_000_000,
        'trees': 7_410_000_000, 'batches': 9_332_000_000}
WALL = 306_160_000_000
# E16-21 ratios (bench/ledger/e16-21-gpu-gating.json), lowest and highest measured.
E16_21 = {'rounds-only': (25.4, 76.1), 'upload-inclusive': (2.9, 15.9)}


def read(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        m = re.fullmatch(r'([a-z_0-9]+)(?:\[(\d+)\])?=(.*)', line)
        if m:
            key, idx, val = m.groups()
            if idx is None:
                out[key] = val
            else:
                out.setdefault(key, {})[int(idx)] = int(val)
    return out


def median(files, key):
    runs = [read(f) for f in files if f.exists()]
    runs = sorted((r for r in runs if key in r), key=lambda r: int(r[key]))
    return runs[len(runs) // 2] if runs else None


def device_m(s_rel, s_gkr):
    """Device seconds-in-ns of M, each stage at its own measured ratio."""
    return LAPS['relations'] / s_rel + LAPS['gkr'] / s_gkr


def ceiling(s_rel, s_gkr, s_src, s_rest):
    """T' over the laps: relations at s_rel, ZK-GKR at s_gkr, sources at s_src, LogUp
    trees and claim batches at s_rest."""
    m = LAPS['gkr'] + LAPS['relations']
    rest = LAPS['trees'] + LAPS['batches']
    r = WALL - m - rest - LAPS['sources']
    return WALL / (r + device_m(s_rel, s_gkr) + LAPS['sources'] / s_src + rest / s_rest)


def needed(s_rel, s_gkr, s_src):
    """s_L >= L / (T/3 - r - sum M_i/s_i - S/s_src): trees and batches' ratio for 3x."""
    m = LAPS['gkr'] + LAPS['relations']
    rest = LAPS['trees'] + LAPS['batches']
    r = WALL - m - rest - LAPS['sources']
    budget = WALL / 3 - r - device_m(s_rel, s_gkr) - LAPS['sources'] / s_src
    return rest / budget if budget > 0 else float('inf')


def main():
    box, mac = Path(sys.argv[1]), Path(sys.argv[2])
    print('source preparation (ell 11; box CPU = production prepare + certificate):')
    src = {}
    for m in (15, 16, 17):
        g = median([box / f'source-gpu-11-{m}-{r}.txt' for r in (1, 2, 3)], 'gpu_encode_ns')
        c = median([box / f'source-cpu-11-{m}-{r}.txt' for r in (1, 2, 3)], 'cpu_prepare_ns')
        if not (g and c):
            continue
        dev = int(g['gpu_encode_ns']) + int(g['gpu_merkle_ns'])
        prep, cert = int(c['cpu_prepare_ns']), int(c['cpu_certify_ns'])
        src[m] = (prep, cert, dev, int(g['gpu_upload_ns']))
        print(f'  m {m}: CPU prepare {prep/1e9:.3f} s + certify {cert/1e9:.3f} s; GPU encode '
              f"{int(g['gpu_encode_ns'])/1e9:.3f} s + Merkle {int(g['gpu_merkle_ns'])/1e9:.3f} s, upload "
              f"{int(g['gpu_upload_ns'])/1e9:.3f} s; prepare {prep/dev:.1f}x; stage (certify on CPU) "
              f'{(prep+cert)/(dev+cert):.1f}x; with upload {(prep+cert)/(dev+cert+int(g["gpu_upload_ns"])):.1f}x')
    mm = median([mac / f'source-cpu-11-16-{r}.txt' for r in (1, 2, 3)], 'cpu_prepare_ns')
    s_src = None
    if mm and 16 in src:
        prep, cert = int(mm['cpu_prepare_ns']), int(mm['cpu_certify_ns'])
        dev = src[16][2]
        s_src = (prep + cert) / (dev + cert)
        s_src_up = (prep + cert) / (dev + cert + src[16][3])
        print(f'  Mac m 16: prepare {prep/1e9:.3f} s + certify {cert/1e9:.3f} s; stage ratio vs device {s_src:.1f}x '
              f'(with the measured upload phase {s_src_up:.1f}x)')
    print('masked rounds (rounds only, production code both sides):')
    ratios, by_stage = [], {'relation': [], 'gkr': []}
    for shape in ('relation', 'gkr'):
        for n in (24, 26, 27):
            g = median([box / f'gpu-{shape}-{n}-{r}.txt' for r in (1, 2, 3)], 'gpu_rounds_total_ns')
            c = median([box / f'cpu-main-{shape}-{n}-{r}.txt' for r in (1, 2, 3)], 'cpu_rounds_total_ns')
            m = median([mac / f'cpu-mac-{shape}-{n}-{r}.txt' for r in (1, 2, 3)], 'cpu_rounds_total_ns')
            if not (g and c):
                continue
            dev = int(g['gpu_rounds_total_ns'])
            line = f"  {shape} 2^{n}: box CPU {int(c['cpu_rounds_total_ns'])/1e9:.3f} s, GPU {dev/1e9:.4f} s, {int(c['cpu_rounds_total_ns'])/dev:.1f}x"
            if m:
                ratios.append(int(m['cpu_rounds_total_ns']) / dev)
                line += f"; Mac CPU {int(m['cpu_rounds_total_ns'])/1e9:.3f} s, {ratios[-1]:.1f}x"
            by_stage[shape].append(int(c['cpu_rounds_total_ns']) / dev)
            print(line)
    m_total = LAPS['gkr'] + LAPS['relations']
    rest = LAPS['trees'] + LAPS['batches']
    r = WALL - m_total - rest - LAPS['sources']
    print(f'\nlaps: wall {WALL/1e9:.2f} s; M {m_total/1e9:.2f}, sources {LAPS["sources"]/1e9:.2f}, '
          f'trees + batches {rest/1e9:.2f}, residual r {r/1e9:.2f} s')
    print(f'unbounded (every offloadable stage free): {WALL/r:.2f}x')
    print(f'M and sources free, trees and batches on the CPU: {WALL/(r+rest):.3f}x')
    if not s_src:
        return
    # The Mac masked calibration did not run (host load 8-11): the ratios are against the
    # box CPU, which ran these rounds faster than the Mac in E16-35, so they understate the
    # device's gain on the laps host and bias the ceiling toward NO-GO.
    lo = (min(by_stage['relation']), min(by_stage['gkr']))
    hi = (max(by_stage['relation']), max(by_stage['gkr']))
    print(f'box-calibrated: relations {lo[0]:.1f}..{hi[0]:.1f}x, ZK-GKR {lo[1]:.1f}..{hi[1]:.1f}x; '
          f's_src {s_src:.2f}x (Mac-calibrated)')
    print(f'  measured, trees and batches on the CPU: {ceiling(*lo, s_src, 1):.3f}x..{ceiling(*hi, s_src, 1):.3f}x')
    for name, (a, b) in E16_21.items():
        print(f'  trees and batches at E16-21 {name} (unmeasured): {ceiling(*lo, s_src, a):.2f}x..{ceiling(*hi, s_src, b):.2f}x')
    print(f'  3x needs trees and batches at s_L >= {needed(*hi, s_src):.2f}x..{needed(*lo, s_src):.2f}x')
    # ADR-123's Mac-calibrated rounds-only range (before E16-34), uniform over M.
    for s_m in (39.7, 83.4):
        print(f'  with M at ADR-123 Mac-calibrated {s_m}x: 3x needs s_L >= {needed(s_m, s_m, s_src):.2f}x')

if __name__ == '__main__':
    main()
