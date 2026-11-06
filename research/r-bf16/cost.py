"""RFC-0019 R-BF16 (task E15-04): projected cost of proving exact bf16 serving arithmetic vs CQIS.

Projection only (INV: no benchmark number without a ledger): every constant is a planning value
from docs/cost-model.md section 1, and the per-MAC counts come from reduction.Meter. Prints the table
used in REPORT.md and asserts the claims the report makes from it.
Usage: python3 research/r-bf16/cost.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reduction as g

R = 3e12                    # Mops/s, one H100 at the planning utilisation
BW = 3.3e12                 # HBM bytes/s
C_W, C_A, C_X, C_C = 4, 200, 110, 30
C_LU = (60, 150)            # Mops per lookup: cost-model c_a = 1.5-3 lookups x 60-150 Mops
N = 4096 + 512              # positions: cost-model section 3 request, batch 1

# name: (L, d, d_ff, h, h_kv, d_h, V); Llama-3.1 configurations
MODELS = {
    'Llama-3.1-8B': (32, 4096, 14336, 32, 8, 128, 128256),
    'Llama-3.1-70B': (80, 8192, 28672, 64, 8, 128, 128256),
    'Llama-3.1-405B': (126, 16384, 53248, 128, 8, 128, 128256),
}


def cqis(L, d, dff, h, hkv, dh, V):
    """docs/cost-model.md section 2, evaluated from its own formulas."""
    P = L * (2 * d * d + 2 * d * hkv * dh + 3 * d * dff) + 2 * V * d
    n_act = 7 * d + 4 * hkv * dh + 4 * dff
    n_attn = N * N / 2 * h * L
    cut = N * d * L
    t = dict(weights=max(P * C_W / R, P / BW), act=N * L * n_act * C_A / R,
             attn=n_attn * C_X / R, cuts=cut * C_C / R + 2 * cut * 4 / R)
    return P, n_act, n_attn, sum(t.values()), t


def macs(L, d, dff, h, hkv, dh, V):
    """Multiply-accumulates of one causal pass: every linear layer incl. LM head, plus QK^T and PV."""
    linear = L * (2 * d * d + 2 * d * hkv * dh + 3 * d * dff) + d * V
    attention = L * h * dh * 2 * (N * (N + 1) // 2)
    return N * linear + attention


def main():
    m = g.Meter()
    g.run((0, 2**23, -23), (0, 128, -7), (0, 128, -7), m)
    lookups, committed = m.c['lookups'], m.c['committed']
    per_mac = [lookups * c + committed * C_C for c in C_LU]
    floor = C_LU[0]                                      # idealised: one lookup, nothing committed
    print(f'reduction per MAC: {lookups} lookups, {committed} committed; '
          f'{per_mac[0]}-{per_mac[1]} Mops (floor {floor})')
    print('| Model | MACs | T_CQIS (s) | T_bf16 floor (s) | T_bf16 reduction (s) | ratio floor | ratio reduction | '
          'reduction witness (PB) |')
    print('|---|---|---|---|---|---|---|---|')
    ratios = {}
    for name, shape in MODELS.items():
        P, n_act, n_attn, t_cqis, parts = cqis(*shape)
        k = macs(*shape)
        lo, hi = k * per_mac[0] / R, k * per_mac[1] / R
        fl = k * floor / R
        ratios[name] = (fl / t_cqis, lo / t_cqis, hi / t_cqis)
        print(f'| {name} | {k:.2e} | {t_cqis:.1f} | {fl:.0f} | {lo:.0f}-{hi:.0f} | '
              f'{fl / t_cqis:.0f}x | {lo / t_cqis:.0f}-{hi / t_cqis:.0f}x | {k * committed * 4 / 1e15:.1f} |')
        print(f'    (P={P:.2e}, n*L*N_act={N * shape[0] * n_act:.2e}, N_attn={n_attn:.2e}, '
              + ', '.join(f'T_{a}={b:.2f}' for a, b in parts.items()) + ')')
    # claims made in REPORT.md
    assert (lookups, committed) == (26, 42)
    assert all(r[0] > 500 for r in ratios.values()), 'floor ratio below 500x'
    assert all(2e4 < r[1] and r[2] < 2e5 for r in ratios.values()), 'reduction ratio outside 2e4-2e5'
    assert ratios['Llama-3.1-8B'] < ratios['Llama-3.1-70B'] < ratios['Llama-3.1-405B'], 'ratio not growing'


if __name__ == '__main__':
    main()
