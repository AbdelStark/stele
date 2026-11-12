"""Projected dev-zk hiding-source bytes against the data-row exponent ell (8-layer window).

A hiding source of 2^S data entries has 2^ell data rows and 2^(S-ell) data columns; its
message M' is 2R x 2C (R = 2^ell, C = 2^(S-ell)), its code Circle rate 1/4 (N = 4*2C).
Measured wire: one combined row of 2C QM31 values (16 bytes) per certificate and per
opening, plus q responses of 4*2R + 32*log2 N + 32 (salt) bytes each.
Constraints: R >= 2D (A2, D = 4 for QM31); the lifetime weight source R >= (P+1)D and
q_c + P*q_o <= C - 1 (A6); otherwise q_c + q_o <= C - 1.
"""
import math

P = 8
D = 4
POLICY = {'policy 1 (now)': (314, 130), 'policy 2': (222, 92)}
# (name, S, openings: number of combined rows besides the certificate, lifetime)
SOURCES = [('witness (0)', 24, 1, False), ('weights (1)', 19, 1, True),
           ('top (2)', 12, 1, False), ('shared (3)', 19, 1, False)]
MEASURED = {'witness (0)': (8, 21), 'weights (1)': (64, 13), 'top (2)': (8, 9), 'shared (3)': (8, 16)}


def cost(S, ell, q, openings):
    R, C = 1 << ell, 1 << (S - ell)
    n = 4 * 2 * C
    response = 4 * 2 * R + 32 * int(math.log2(n)) + 32
    qc, qo = q
    return (1 + openings) * 16 * 2 * C + (qc + openings * qo) * response


def ok(S, ell, q, lifetime):
    R, C = 1 << ell, 1 << (S - ell)
    qc, qo = q
    if lifetime:
        return R >= (P + 1) * D and qc + P * qo <= C - 1
    return R >= 2 * D and qc + qo <= C - 1


for policy, q in POLICY.items():
    total_now = total_best = 0
    print(f'== {policy}: q_c/q_o = {q[0]}/{q[1]}')
    for name, S, openings, lifetime in SOURCES:
        R0, C0 = MEASURED[name]
        now = cost(S, int(math.log2(R0)), q, openings)
        best = min((cost(S, ell, q, openings), ell) for ell in range(1, S) if ok(S, ell, q, lifetime))
        total_now += now
        total_best += best[0]
        print(f'{name:12s} S={S}: current ell={int(math.log2(R0))} {now / 1e6:8.2f} MB'
              f' | best ell={best[1]} {best[0] / 1e6:6.2f} MB')
    print(f'sources total: current geometry {total_now / 1e6:.1f} MB, best {total_best / 1e6:.2f} MB')
