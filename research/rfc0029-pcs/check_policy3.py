#!/usr/bin/env python3
"""RFC-0029 Policy 3 exact-integer parameter checker and recursive proof-size model (task E19-01).

Governing specs: RFC-0029 §§1-5, RFC-0010 A2/A3/A17, RFC-0030 §3.
All query counts, proximity caps, and byte minimisations use exact integer / Fraction
arithmetic; floating-point formatting is for human reading only.

  python3 research/rfc0029-pcs/check_policy3.py          # print parameter and size tables
  python3 research/rfc0029-pcs/check_policy3.py --check  # verify exact bounds and pinned receipts
"""
from fractions import Fraction
import sys

P = (1 << 31) - 1  # M31 prime: 2^31 - 1
HASH_BYTES = 32
DEFAULT_BLOWUPS = (2, 3, 4)
# RFC-0030 §3: exact QM31 cap for 100-bit per-round security: floor(p^4 / 2^100) = 2^24 - 1.
QM31_CAP_100 = (P**4) // (1 << 100)
assert QM31_CAP_100 == (1 << 24) - 1


def circle_params(m: int, b: int) -> tuple[int, int, int, int]:
    """Return (C, N, D, e) for coefficient-form Circle RS with C=2^m, N=2^(m+b) (RFC-0029 §5)."""
    if m < 0 or b < 1:
        raise ValueError(f"invalid circle parameters m={m}, b={b}")
    c = 1 << m
    n = 1 << (m + b)
    d = n if c == 1 else n - c
    e = (d - 1) // 3
    if not (0 <= e and 3 * e < d):
        raise AssertionError("radius violates e < D/3")
    return c, n, d, e


def least_q(n: int, miss: int, target_bits: int, cap: int = 1 << 16) -> int:
    """Exact least positive integer q with 2^target_bits * miss^q <= n^q, asserting failure at q-1."""
    if not (0 < miss < n):
        raise ValueError(f"miss={miss} must satisfy 0 < miss < n={n}")
    if target_bits <= 0:
        raise ValueError(f"target_bits={target_bits} must be positive")
    lhs = 1 << target_bits
    rhs = 1
    q = 0
    while lhs > rhs:
        q += 1
        if q > cap:
            raise ValueError(f"query cap {cap} exceeded for n={n}, miss={miss}, T={target_bits}")
        lhs *= miss
        rhs *= n
    # Exact verification of both the passing count q and the failing count q - 1.
    assert (1 << target_bits) * (miss**q) <= n**q
    if q > 1:
        assert (1 << target_bits) * (miss ** (q - 1)) > n ** (q - 1)
    return q


def policy3_fresh_q(m: int, b: int, target_bits: int = 100) -> tuple[int, int, int, int, int]:
    """Policy 3 fresh / recursion level count q and (C, N, D, e) (RFC-0029 §5)."""
    c, n, d, e = circle_params(m, b)
    far_miss = n - e - 1
    near_miss = n - d + e
    # RFC-0029 §5: far-case count covers near case because N - D + e <= N - e - 1 for e < D/3.
    assert near_miss <= far_miss
    q = least_q(n, far_miss, target_bits)
    assert (1 << target_bits) * (near_miss**q) <= n**q
    return q, c, n, d, e


def policy3_certified_q(
    m: int, b: int, e_cert: int, target_bits: int = 100
) -> tuple[int, int]:
    """Policy 3 certified mode: (q_cert, q_open) for certified radius 0 <= e_cert <= floor((D-1)/3)."""
    _, n, d, e_max = circle_params(m, b)
    if not (0 <= e_cert <= e_max):
        raise ValueError(f"e_cert={e_cert} out of [0, {e_max}]")
    q_cert = least_q(n, n - e_cert - 1, target_bits)
    q_open = least_q(n, n - d + e_cert, target_bits)
    return q_cert, q_open


def field_cap(degree: int, target_bits: int) -> int:
    """Exact RFC-0030 §3 numerator cap floor(|K| / 2^target_bits) for K = M31^degree."""
    return (P**degree) // (1 << target_bits)


def proximity_numerator(ell: int, e: int, per_round: bool) -> int:
    """Proximity-round numerator: 2*ell*(e+1) (ell-fold) or 2*(e+1) (per-round Q50)."""
    return 2 * (e + 1) if per_round else 2 * ell * (e + 1)


def level_proof_bytes(
    lvl: int,
    ell: int,
    m: int,
    b: int,
    q: int,
    ext_degree: int,
    blocks: int = 1,
) -> int:
    """Exact RFC-0029 §3 level proof bytes:
    - level root committed for u_{i+1}: 32 B
    - row-round sumcheck (levels >= 1): ell rounds * 3 field elements (degree 2)
    - q queried columns: elem_i * R_i + 32 * k_i * (m_i + b_i),
      with elem_0 = 4 B (M31) and elem_{i>=1} = 4 * ext_degree B.
    """
    elem_ext = 4 * ext_degree
    elem = 4 if lvl == 0 else elem_ext
    rows = 1 << ell
    sc_bytes = (ell * 3 * elem_ext) if lvl >= 1 else 0
    col_bytes = q * (elem * rows + HASH_BYTES * blocks * (m + b))
    return HASH_BYTES + sc_bytes + col_bytes


def minimise_recursive_proof(
    total_bits: int,
    ext_degree: int = 4,
    target_bits: int = 100,
    capped: bool = True,
    per_round: bool = False,
    blowups: tuple[int, ...] = DEFAULT_BLOWUPS,
    level0_blocks: int = 1,
) -> tuple[int, list[tuple]]:
    """Exact DP over (ell_i, m_i, b_i) minimising total RFC-0029 §3 proof bytes.

    Level 0 is an M31 matrix (4 B/elem); levels >= 1 are K = M31^ext_degree matrices
    (4 * ext_degree B/elem). When `level0_blocks > 1` (k segments of equal row length
    joined at level 1), `total_bits` is the total witness log-size across all k segments
    and level 0 opens `level0_blocks` Merkle paths per query (RFC-0029 §2).
    """
    cap = field_cap(ext_degree, target_bits)
    elem_ext = 4 * ext_degree
    q_cache: dict[tuple[int, int], tuple[int, int]] = {}

    def get_qe(m: int, b: int) -> tuple[int, int]:
        key = (m, b)
        if key not in q_cache:
            q, _, _, _, e = policy3_fresh_q(m, b, target_bits)
            q_cache[key] = (q, e)
        return q_cache[key]

    memo: dict[tuple[int, int], tuple[int, list[tuple]] | None] = {}

    def solve(n_bits: int, lvl: int) -> tuple[int, list[tuple]] | None:
        key = (n_bits, lvl)
        if key in memo:
            return memo[key]
        best: tuple[int, list[tuple]] | None = None
        if lvl >= 1:
            final_bytes = elem_ext * (1 << n_bits)
            best = (final_bytes, [("final", n_bits, final_bytes)])
        k = level0_blocks if lvl == 0 else 1
        # At level 0 with k = 2^s segments, each segment has 2^(ell - s) rows if split evenly,
        # so total column height across all k segments is still 2^ell elements and each query
        # carries k Merkle paths of height m + b.
        for b in blowups:
            for ell in range(1, n_bits):
                m = n_bits - ell
                if m < 1:
                    continue
                q, e = get_qe(m, b)
                if capped:
                    if proximity_numerator(ell, e, per_round) > cap:
                        continue
                    # Consistency batch (beta): q <= cap; block batch (gamma): k - 1 <= cap.
                    if q > cap or (k - 1) > cap:
                        continue
                lvl_bytes = level_proof_bytes(lvl, ell, m, b, q, ext_degree, blocks=k)
                sub = solve(m, lvl + 1)
                if sub is None:
                    continue
                total = lvl_bytes + sub[0]
                if best is None or total < best[0]:
                    best = (total, [(lvl, ell, m, b, q, e, lvl_bytes)] + sub[1])
        memo[key] = best
        return best

    res = solve(total_bits, 0)
    if res is None:
        raise ValueError(f"no feasible plan for 2^{total_bits} (deg={ext_degree}, T={target_bits})")
    return res


def minimise_certified_weight_opening(
    total_bits: int,
    ext_degree: int = 4,
    target_bits: int = 100,
    capped: bool = True,
    per_round: bool = False,
    blowups: tuple[int, ...] = (2,),
) -> tuple[int, dict]:
    """Exact certified-mode opening size for a model source of 2^total_bits M31 entries.

    At level 0, chooses certified radius e_c in {e_max, e_max//2, e_max//4, e_max//8, 0}
    to trade one-time registration q_cert for per-proof level-0 q_open, then recurses
    in fresh mode from level 1 onward (RFC-0029 §§1.3, 5).
    """
    cap = field_cap(ext_degree, target_bits)
    best: tuple[int, dict] | None = None
    for b in blowups:
        for ell in range(1, total_bits):
            m = total_bits - ell
            if m < 1:
                continue
            _, n, d, e_max = circle_params(m, b)
            tail_bytes, tail_plan = _minimise_from_level1(
                m, ext_degree, target_bits, capped, per_round, DEFAULT_BLOWUPS
            )
            candidates = sorted(
                {e for e in (e_max, e_max // 2, e_max // 4, e_max // 8) if e >= 1}
            )
            for e_c in candidates:
                if capped and proximity_numerator(ell, e_c, per_round) > cap:
                    continue
                q_cert, q_open = policy3_certified_q(m, b, e_c, target_bits)
                if capped and q_open > cap:
                    continue
                lvl0 = level_proof_bytes(0, ell, m, b, q_open, ext_degree, blocks=1)
                total = lvl0 + tail_bytes
                if best is None or total < best[0]:
                    best = (
                        total,
                        {
                            "ell": ell,
                            "m": m,
                            "b": b,
                            "e_c": e_c,
                            "e_max": e_max,
                            "q_cert": q_cert,
                            "q_open": q_open,
                            "lvl0_bytes": lvl0,
                            "tail_bytes": tail_bytes,
                            "tail_plan": tail_plan,
                        },
                    )
    assert best is not None
    return best


def _minimise_from_level1(
    u1_bits: int,
    ext_degree: int,
    target_bits: int,
    capped: bool,
    per_round: bool,
    blowups: tuple[int, ...],
) -> tuple[int, list[tuple]]:
    cap = field_cap(ext_degree, target_bits)
    elem_ext = 4 * ext_degree
    memo: dict[tuple[int, int], tuple[int, list[tuple]]] = {}

    def solve(n_bits: int, lvl: int) -> tuple[int, list[tuple]]:
        key = (n_bits, lvl)
        if key in memo:
            return memo[key]
        final_bytes = elem_ext * (1 << n_bits)
        best: tuple[int, list[tuple]] = (final_bytes, [("final", n_bits, final_bytes)])
        for b in blowups:
            for ell in range(1, n_bits):
                m = n_bits - ell
                if m < 1:
                    continue
                q, _, _, _, e = policy3_fresh_q(m, b, target_bits)
                if capped and (proximity_numerator(ell, e, per_round) > cap or q > cap):
                    continue
                lvl_bytes = level_proof_bytes(lvl, ell, m, b, q, ext_degree, blocks=1)
                sub = solve(m, lvl + 1)
                cand = lvl_bytes + sub[0]
                if cand < best[0]:
                    best = (cand, [(lvl, ell, m, b, q, e, lvl_bytes)] + sub[1])
        memo[key] = best
        return best

    return solve(u1_bits, 1)


def fmt_mib(n_bytes: int) -> str:
    return f"{n_bytes / (1024 * 1024):.3f} MiB"


# Exact pinned byte receipts for regression and cross-check (`--check`).
PINNED_RECEIPTS = {
    # (total_bits, deg, T, capped, per_round, blowups): exact_bytes
    (20, 4, 100, False, False, DEFAULT_BLOWUPS): 299_376,
    (20, 4, 100, True, False, DEFAULT_BLOWUPS): 299_376,
    (24, 4, 100, False, False, DEFAULT_BLOWUPS): 474_320,
    (24, 4, 100, True, False, DEFAULT_BLOWUPS): 474_320,
    (28, 4, 100, False, False, DEFAULT_BLOWUPS): 663_984,
    (28, 4, 100, True, False, DEFAULT_BLOWUPS): 984_768,
    (30, 4, 100, False, False, DEFAULT_BLOWUPS): 767_552,
    (30, 4, 100, True, False, DEFAULT_BLOWUPS): 2_465_472,
    (32, 4, 100, False, False, DEFAULT_BLOWUPS): 877_328,
    (32, 4, 100, True, False, DEFAULT_BLOWUPS): 8_388_288,
    (32, 4, 100, True, True, DEFAULT_BLOWUPS): 1_646_816,
    (32, 6, 100, True, False, DEFAULT_BLOWUPS): 996_696,
    (32, 8, 100, True, False, DEFAULT_BLOWUPS): 1_085_280,
    (33, 4, 100, True, False, DEFAULT_BLOWUPS): 16_285_376,
    (33, 4, 100, True, True, DEFAULT_BLOWUPS): 2_633_952,
    (33, 6, 100, True, False, DEFAULT_BLOWUPS): 1_050_872,
    (33, 8, 100, True, False, DEFAULT_BLOWUPS): 1_150_496,
    (34, 4, 100, True, False, DEFAULT_BLOWUPS): 32_079_552,
    (34, 4, 100, True, True, DEFAULT_BLOWUPS): 4_608_224,
    (34, 6, 100, True, False, DEFAULT_BLOWUPS): 1_110_144,
    (34, 8, 100, True, False, DEFAULT_BLOWUPS): 1_221_632,
}


def run_checks() -> None:
    # 1. RFC-0029 §1.1 & §5 exact reference query counts at rate 1/4 (b=2):
    # 241 for 100 bits and 314 for 130 bits (m >= 10).
    for m in range(10, 26):
        q100, _, n, d, e = policy3_fresh_q(m, 2, 100)
        q130, _, _, _, _ = policy3_fresh_q(m, 2, 130)
        assert q100 == 241, f"m={m}: expected q100=241, got {q100}"
        assert q130 == 314, f"m={m}: expected q130=314, got {q130}"
        # Explicit proximity-bound check: 2 * ell * (e + 1) / |K| matches Fraction exactness.
        assert Fraction(2 * 10 * (e + 1), P**4) == Fraction(20 * (e + 1), P**4)
        assert n == 1 << (m + 2) and d == n - (1 << m)

    # Check b=3 (rate 1/8) and b=4 (rate 1/16) asymptotics and q-1 failures.
    for b, expected_q100 in ((2, 241), (3, 202), (4, 185)):
        q, _, _, _, _ = policy3_fresh_q(16, b, 100)
        assert q == expected_q100, f"b={b}: expected {expected_q100}, got {q}"

    # Check C=1 edge case (D = N, RFC-0029 §5).
    q_c1, c1, n1, d1, e1 = policy3_fresh_q(0, 2, 100)
    assert (c1, n1, d1, e1) == (1, 4, 4, 1) and q_c1 == 100

    # Check certified mode monotonicity: smaller e_c -> more q_cert, fewer q_open.
    _, _, _, e_max = circle_params(16, 2)
    qc_max, qo_max = policy3_certified_q(16, 2, e_max, 100)
    qc_half, qo_half = policy3_certified_q(16, 2, e_max // 2, 100)
    qc_quarter, qo_quarter = policy3_certified_q(16, 2, e_max // 4, 100)
    assert qc_max < qc_half < qc_quarter
    assert qo_max > qo_half > qo_quarter
    assert qo_max <= policy3_fresh_q(16, 2, 100)[0]

    # 2. Verify all pinned recursive proof-size receipts for 2^20..2^34.
    for key, expected in PINNED_RECEIPTS.items():
        n_bits, deg, t_bits, capped, per_round, blowups = key
        actual, _ = minimise_recursive_proof(
            n_bits,
            ext_degree=deg,
            target_bits=t_bits,
            capped=capped,
            per_round=per_round,
            blowups=blowups,
        )
        assert actual == expected, f"key={key}: expected {expected}, got {actual}"

    # 3. Bet B3 kill criterion check (docs/plan.md §2):
    # A 2^32-cell witness under RFC-0030 §3 caps at 100 bits must stay under 8 MiB (8,388,608 B).
    eight_mib = 8 * 1024 * 1024
    qm31_capped_32, _ = minimise_recursive_proof(32, ext_degree=4, target_bits=100, capped=True)
    qm31_per_round_32, _ = minimise_recursive_proof(
        32, ext_degree=4, target_bits=100, capped=True, per_round=True
    )
    ext6_32, _ = minimise_recursive_proof(32, ext_degree=6, target_bits=100, capped=True)
    om31_32, _ = minimise_recursive_proof(32, ext_degree=8, target_bits=100, capped=True)
    assert qm31_capped_32 < eight_mib
    assert qm31_per_round_32 < 2 * 1024 * 1024
    assert ext6_32 < 1024 * 1024
    assert om31_32 < 2 * 1024 * 1024

    # 4. Verify rate-1/4-only (b=2) and multi-segment (k=32) & certified model source checks run cleanly.
    b2_32_capped, _ = minimise_recursive_proof(32, ext_degree=4, capped=True, blowups=(2,))
    assert b2_32_capped < 9 * 1024 * 1024
    seg32_30, _ = minimise_recursive_proof(30, ext_degree=4, capped=True, level0_blocks=32)
    assert seg32_30 < 8 * 1024 * 1024
    cert_33, cert_info = minimise_certified_weight_opening(33, ext_degree=4, capped=True, per_round=True)
    assert cert_33 < 2 * 1024 * 1024 and cert_info["q_open"] < 150

    # 5. Treaty T=128 on OM31 (deg=8) clears 128 bits under 2 MiB even at 2^34.
    treaty_34, _ = minimise_recursive_proof(34, ext_degree=8, target_bits=128, capped=True)
    assert treaty_34 < 2 * 1024 * 1024

    print(
        "rfc0029 check_policy3: OK "
        f"(2^32 QM31 capped={qm31_capped_32:,} B, per-round={qm31_per_round_32:,} B, "
        f"Ext6={ext6_32:,} B, OM31={om31_32:,} B; Bet B3 < 8 MiB satisfied)"
    )


def print_report() -> None:
    print("# RFC-0029 Policy 3 Parameter & Recursive Size Report (E19-01)\n")
    print("## 1. Policy 3 fresh query counts (exact least q, failure verified at q - 1)\n")
    print("| Rate | Blow-up `b` | `m = 16` `D` | `e = floor((D-1)/3)` | `q (T=100)` | `q (T=130)` |")
    print("|---|---:|---:|---:|---:|---:|")
    for b in DEFAULT_BLOWUPS:
        q100, _, _, d, e = policy3_fresh_q(16, b, 100)
        q130, _, _, _, _ = policy3_fresh_q(16, b, 130)
        print(f"| 1/{1 << b} | {b} | {d:,} | {e:,} | {q100} | {q130} |")

    print("\n## 2. Recursive opening proof bytes (`2^20` to `2^34` M31 entries, `T = 100`, `b in {2,3,4}`)\n")
    print(
        "| Entries | QM31 uncapped | QM31 capped (`2*ell*(e+1)`) | "
        "QM31 capped per-round (`2*(e+1)`) | QM31 `b=2` capped | Ext6 Q50 capped | OM31 Q50 capped |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|")
    for n in range(20, 35):
        u, _ = minimise_recursive_proof(n, ext_degree=4, capped=False)
        c, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=False)
        pr, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=True)
        b2, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, blowups=(2,))
        e6, _ = minimise_recursive_proof(n, ext_degree=6, capped=True)
        o8, _ = minimise_recursive_proof(n, ext_degree=8, capped=True)
        print(
            f"| 2^{n} | {u:,} ({fmt_mib(u)}) | {c:,} ({fmt_mib(c)}) | "
            f"{pr:,} ({fmt_mib(pr)}) | {b2:,} ({fmt_mib(b2)}) | "
            f"{e6:,} ({fmt_mib(e6)}) | {o8:,} ({fmt_mib(o8)}) |"
        )

    print("\n## 3. Q50 wider-field breakdown at `2^32`..`2^34` entries (`T = 100`, plus OM31 `T = 128`)\n")
    print("| Entries | QM31 capped (`2*ell*(e+1)`) | QM31 per-round | Ext6 (`p^6`, 24 B) | OM31 (`p^8`, 32 B) | OM31 treaty (`T=128`) |")
    print("|---|---:|---:|---:|---:|---:|")
    for n in (32, 33, 34):
        c, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=False)
        pr, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=True)
        e6, _ = minimise_recursive_proof(n, ext_degree=6, capped=True)
        o8, _ = minimise_recursive_proof(n, ext_degree=8, capped=True)
        t8, _ = minimise_recursive_proof(n, ext_degree=8, target_bits=128, capped=True)
        print(
            f"| 2^{n} | {fmt_mib(c)} | {fmt_mib(pr)} | {fmt_mib(e6)} | {fmt_mib(o8)} | {fmt_mib(t8)} |"
        )

    print("\n## 4. Certified model sources (rate 1/4 at level 0, `T = 100`, per-round cap)\n")
    print("| Model entries | `(ell, m, b)` | `e_c` / `e_max` | `q_cert` | `q_open` | Opening bytes |")
    print("|---|---|---|---:|---:|---:|")
    for n in (29, 30, 31, 32, 33):
        total, info = minimise_certified_weight_opening(n, ext_degree=4, capped=True, per_round=True)
        print(
            f"| 2^{n} | ({info['ell']}, {info['m']}, {info['b']}) | "
            f"{info['e_c']:,} / {info['e_max']:,} | {info['q_cert']} | {info['q_open']} | "
            f"{total:,} ({fmt_mib(total)}) |"
        )

    print("\n## 5. Multi-segment level-0 batching (`k` segments of equal row length, `T = 100`)\n")
    print("| Total witness | Segments `k` | QM31 capped (`2*ell*(e+1)`) | QM31 per-round | Ext6 Q50 |")
    print("|---|---:|---:|---:|---:|")
    for n, k in ((26, 8), (28, 32), (30, 32), (32, 32)):
        c, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, level0_blocks=k)
        pr, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=True, level0_blocks=k)
        e6, _ = minimise_recursive_proof(n, ext_degree=6, capped=True, level0_blocks=k)
        print(f"| 2^{n} | {k} | {fmt_mib(c)} | {fmt_mib(pr)} | {fmt_mib(e6)} |")


if __name__ == "__main__":
    if "--check" in sys.argv:
        run_checks()
    else:
        print_report()
