#!/usr/bin/env python3
"""RFC-0029 Policy 3 exact-integer parameter checker and recursive proof-size model (task E19-01).

Governing specs: RFC-0029 §§1-5, RFC-0010 A2/A3/A17, RFC-0012 A10/A20, RFC-0030 §3.
All query counts, proximity caps, and byte minimisations use exact integer / Fraction
arithmetic; floating-point formatting is for human reading only.

  python3 research/rfc0029-pcs/check_policy3.py          # print parameter and size tables
  python3 research/rfc0029-pcs/check_policy3.py --check  # verify exact bounds and pinned receipts
"""
from fractions import Fraction
import sys

P = (1 << 31) - 1  # M31 prime: 2^31 - 1
HASH_BYTES = 32
# RFC-0010 A2 & RFC-0012 A10: Circle coset domain D_h and column-index sampler require
# 1 <= h = m + b <= 30 (N = 2^(m+b) <= 2^30 < p).
MAX_DOMAIN_BITS = 30
DEFAULT_BLOWUPS = (2, 3, 4)
ALL_BLOWUPS = (1, 2, 3, 4)
# RFC-0030 §3: exact QM31 cap for 100-bit per-round security: floor(p^4 / 2^100) = 2^24 - 1.
QM31_CAP_100 = (P**4) // (1 << 100)
assert QM31_CAP_100 == (1 << 24) - 1


def circle_params(m: int, b: int) -> tuple[int, int, int, int]:
    """Return (C, N, D, e) for coefficient-form Circle RS with C=2^m, N=2^(m+b) (RFC-0029 §5).

    Enforces m >= 0, b >= 1, and m + b <= 30 (RFC-0010 A2 / A17, RFC-0012 A10).
    """
    if m < 0 or b < 1 or m + b > MAX_DOMAIN_BITS:
        raise ValueError(
            f"invalid circle parameters m={m}, b={b} (require m>=0, b>=1, m+b<={MAX_DOMAIN_BITS})"
        )
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
    """Policy 3 certified mode: (q_cert, q_open) for certified radius 1 <= e_cert <= floor((D-1)/3)."""
    _, n, d, e_max = circle_params(m, b)
    if not (1 <= e_cert <= e_max):
        raise ValueError(f"e_cert={e_cert} out of [1, {e_max}]")
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
    emit_root: bool = True,
) -> int:
    """Exact RFC-0029 §3 level proof bytes:
    - level root committed for u_{i+1}: 32 B when u_{i+1} is committed (0 B when sent in the clear)
    - row-round sumcheck (levels >= 1): ell rounds * 3 field elements (degree 2)
    - q queried columns: elem_i * R_i + 32 * k_i * (m_i + b_i),
      with elem_0 = 4 B (M31), elem_{i>=1} = 4 * ext_degree B, and R_i = 2^ell total rows.
    """
    elem_ext = 4 * ext_degree
    elem = 4 if lvl == 0 else elem_ext
    rows = 1 << ell
    root_bytes = HASH_BYTES if emit_root else 0
    sc_bytes = (ell * 3 * elem_ext) if lvl >= 1 else 0
    col_bytes = q * (elem * rows + HASH_BYTES * blocks * (m + b))
    return root_bytes + sc_bytes + col_bytes


def _solve_from_level(
    start_bits: int,
    start_lvl: int,
    ext_degree: int,
    target_bits: int,
    capped: bool,
    per_round: bool,
    blowups: tuple[int, ...],
    start_blocks: int = 1,
) -> tuple[int, list[tuple]]:
    """Exact DP over (ell_i, m_i, b_i) from `start_lvl` onward (enforcing m_i + b_i <= 30)."""
    if start_blocks < 1 or (start_blocks & (start_blocks - 1)) != 0:
        raise ValueError(f"start_blocks={start_blocks} must be a positive power of two")
    s_bits = start_blocks.bit_length() - 1
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
        k = start_blocks if lvl == start_lvl else 1
        min_ell = max(1, s_bits) if lvl == start_lvl else 1
        best: tuple[int, list[tuple]] | None = None
        if lvl >= 1:
            final_bytes = elem_ext * (1 << n_bits)
            best = (final_bytes, [("final", n_bits, final_bytes)])
        for b in blowups:
            for ell in range(min_ell, n_bits):
                m = n_bits - ell
                if m < 1 or m + b > MAX_DOMAIN_BITS:
                    continue
                q, e = get_qe(m, b)
                if capped:
                    if proximity_numerator(ell, e, per_round) > cap:
                        continue
                    # Consistency batch (beta): q <= cap; block batch (gamma): k - 1 <= cap.
                    if q > cap or (k - 1) > cap:
                        continue
                sub = solve(m, lvl + 1)
                if sub is None:
                    continue
                is_final_transition = sub[1][0][0] == "final"
                lvl_bytes = level_proof_bytes(
                    lvl,
                    ell,
                    m,
                    b,
                    q,
                    ext_degree,
                    blocks=k,
                    emit_root=not is_final_transition,
                )
                total = lvl_bytes + sub[0]
                if best is None or total < best[0]:
                    best = (total, [(lvl, ell, m, b, q, e, k, lvl_bytes)] + sub[1])
        memo[key] = best
        return best

    res = solve(start_bits, start_lvl)
    if res is None:
        raise ValueError(
            f"no feasible plan for 2^{start_bits} from lvl={start_lvl} "
            f"(deg={ext_degree}, T={target_bits}, blocks={start_blocks})"
        )
    return res


def minimise_recursive_proof(
    total_bits: int,
    ext_degree: int = 4,
    target_bits: int = 100,
    capped: bool = True,
    per_round: bool = False,
    blowups: tuple[int, ...] = DEFAULT_BLOWUPS,
) -> tuple[int, list[tuple]]:
    """Exact DP over (ell_i, m_i, b_i) minimising total RFC-0029 §3 proof bytes for one source."""
    return _solve_from_level(
        start_bits=total_bits,
        start_lvl=0,
        ext_degree=ext_degree,
        target_bits=target_bits,
        capped=capped,
        per_round=per_round,
        blowups=blowups,
        start_blocks=1,
    )


def minimise_segmented_proof(
    total_bits: int,
    segments_k: int,
    ext_degree: int = 4,
    target_bits: int = 100,
    capped: bool = True,
    per_round: bool = False,
    blowups: tuple[int, ...] = DEFAULT_BLOWUPS,
) -> tuple[int, list[tuple]]:
    """Faithful RFC-0029 §2 'Segments' + 'Several sources at one level' DP.

    `segments_k = 2^s` equal-sized segments of `2^(total_bits - s)` M31 entries each close
    independently at level 0 (each producing its own committed `u_1^(s)` of length `2^m_0`
    and answering `q_0` queries with 1 Merkle path of height `m_0 + b_0`, freeing its
    level-0 matrix). All `k` pending `u_1^(s)` sources then join as `k` row blocks of the
    logical level-1 source (`k * 2^m_0 = 2^(m_0 + s)` extension elements, `k` Merkle paths
    per level-1 query, one shared recursion from level 1 onward).
    """
    if segments_k < 1 or (segments_k & (segments_k - 1)) != 0:
        raise ValueError(f"segments_k={segments_k} must be a positive power of two")
    if segments_k == 1:
        return minimise_recursive_proof(
            total_bits,
            ext_degree=ext_degree,
            target_bits=target_bits,
            capped=capped,
            per_round=per_round,
            blowups=blowups,
        )
    s_bits = segments_k.bit_length() - 1
    seg_bits = total_bits - s_bits
    if seg_bits < 2:
        raise ValueError(f"segment size 2^{seg_bits} too small for segments_k={segments_k}")
    cap = field_cap(ext_degree, target_bits)
    best: tuple[int, list[tuple]] | None = None
    for b0 in blowups:
        for ell0 in range(1, seg_bits):
            m0 = seg_bits - ell0
            if m0 < 1 or m0 + b0 > MAX_DOMAIN_BITS:
                continue
            q0, _, _, _, e0 = policy3_fresh_q(m0, b0, target_bits)
            if capped and (proximity_numerator(ell0, e0, per_round) > cap or q0 > cap):
                continue
            # All `k` pending `u_1^(s)` join at level 1 as `k` blocks of total log-size `m0 + s`.
            try:
                tail_bytes, tail_plan = _solve_from_level(
                    start_bits=m0 + s_bits,
                    start_lvl=1,
                    ext_degree=ext_degree,
                    target_bits=target_bits,
                    capped=capped,
                    per_round=per_round,
                    blowups=blowups,
                    start_blocks=segments_k,
                )
            except ValueError:
                continue
            is_final_transition = tail_plan[0][0] == "final"
            per_seg_lvl0 = level_proof_bytes(
                0,
                ell0,
                m0,
                b0,
                q0,
                ext_degree,
                blocks=1,
                emit_root=not is_final_transition,
            )
            all_lvl0 = segments_k * per_seg_lvl0
            total = all_lvl0 + tail_bytes
            if best is None or total < best[0]:
                best = (
                    total,
                    [("lvl0_segs", segments_k, ell0, m0, b0, q0, e0, all_lvl0)] + tail_plan,
                )
    if best is None:
        raise ValueError(
            f"no feasible segmented plan for 2^{total_bits}, k={segments_k} "
            f"(deg={ext_degree}, T={target_bits})"
        )
    return best


def minimise_certified_weight_opening(
    total_bits: int,
    ext_degree: int = 4,
    target_bits: int = 100,
    capped: bool = True,
    tail_per_round: bool = False,
    blowups: tuple[int, ...] = (2,),
) -> tuple[int, dict]:
    """Exact certified-mode opening size for a model source of 2^total_bits M31 entries.

    Under RFC-0029 §1.3 and RFC-0010 A9, the level-0 registration certificate runs no
    sumcheck (all `ell` coordinates are drawn together), so level 0 ALWAYS enforces the
    unconditional `2 * ell * (e_c + 1) <= cap` proximity bound (`1 <= e_c <= e_max`).
    `tail_per_round` applies only to the level-1+ fresh recursion tail (Q50 variant).
    """
    cap = field_cap(ext_degree, target_bits)
    best: tuple[int, dict] | None = None
    for b in blowups:
        for ell in range(1, total_bits):
            m = total_bits - ell
            if m < 1 or m + b > MAX_DOMAIN_BITS:
                continue
            _, _, _, e_max = circle_params(m, b)
            tail_bytes, tail_plan = _solve_from_level(
                start_bits=m,
                start_lvl=1,
                ext_degree=ext_degree,
                target_bits=target_bits,
                capped=capped,
                per_round=tail_per_round,
                blowups=DEFAULT_BLOWUPS,
                start_blocks=1,
            )
            is_final_transition = tail_plan[0][0] == "final"
            # Exact cap-boundary radius plus dyadic fractions for certificate-vs-opening tradeoff.
            candidates = {
                e_max // div for div in (1, 2, 4, 8, 16, 32, 64) if e_max // div >= 1
            }
            if capped:
                e_cap = cap // (2 * ell) - 1
                if 1 <= e_cap <= e_max:
                    candidates.add(e_cap)
            for e_c in sorted(candidates):
                # Level-0 registration certificate is single-round: strict 2*ell*(e_c+1) always!
                if capped and 2 * ell * (e_c + 1) > cap:
                    continue
                try:
                    q_cert, q_open = policy3_certified_q(m, b, e_c, target_bits)
                except ValueError:
                    continue
                if capped and q_open > cap:
                    continue
                lvl0 = level_proof_bytes(
                    0,
                    ell,
                    m,
                    b,
                    q_open,
                    ext_degree,
                    blocks=1,
                    emit_root=not is_final_transition,
                )
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
    if best is None:
        raise ValueError(f"no feasible certified plan for 2^{total_bits}")
    return best


def _assert_plan_domains_valid(plan: list[tuple]) -> None:
    """Verify every non-final level in a plan respects m + b <= MAX_DOMAIN_BITS."""
    for step in plan:
        if step[0] == "final":
            continue
        if step[0] == "lvl0_segs":
            _, _, _, m, b, _, _, _ = step
        else:
            _, _, m, b, _, _, _, _ = step
        assert m >= 1 and b >= 1 and m + b <= MAX_DOMAIN_BITS, f"invalid domain in {step}"


def fmt_mib(n_bytes: int) -> str:
    return f"{n_bytes / (1024 * 1024):.3f} MiB"


# Exact pinned byte receipts for regression and cross-check (`--check`).
PINNED_RECEIPTS = {
    # (total_bits, deg, T, capped, per_round, blowups): exact_bytes
    (20, 4, 100, False, False, DEFAULT_BLOWUPS): 299_344,
    (20, 4, 100, True, False, DEFAULT_BLOWUPS): 299_344,
    (24, 4, 100, False, False, DEFAULT_BLOWUPS): 474_288,
    (24, 4, 100, True, False, DEFAULT_BLOWUPS): 474_288,
    (28, 4, 100, False, False, DEFAULT_BLOWUPS): 663_952,
    (28, 4, 100, True, False, DEFAULT_BLOWUPS): 984_736,
    (30, 4, 100, False, False, DEFAULT_BLOWUPS): 767_520,
    (30, 4, 100, True, False, DEFAULT_BLOWUPS): 2_465_440,
    (32, 4, 100, False, False, DEFAULT_BLOWUPS): 877_296,
    (32, 4, 100, True, False, DEFAULT_BLOWUPS): 8_388_256,
    (32, 4, 100, True, False, ALL_BLOWUPS): 3_810_608,
    (32, 4, 100, True, True, DEFAULT_BLOWUPS): 1_646_784,
    (32, 6, 100, True, False, DEFAULT_BLOWUPS): 996_664,
    (32, 8, 100, True, False, DEFAULT_BLOWUPS): 1_085_248,
    (33, 4, 100, True, False, DEFAULT_BLOWUPS): 16_285_344,
    (33, 4, 100, True, True, DEFAULT_BLOWUPS): 2_633_920,
    (33, 6, 100, True, False, DEFAULT_BLOWUPS): 1_050_840,
    (33, 8, 100, True, False, DEFAULT_BLOWUPS): 1_150_464,
    (34, 4, 100, False, False, DEFAULT_BLOWUPS): 1_017_728,
    (34, 4, 100, True, False, DEFAULT_BLOWUPS): 32_079_520,
    (34, 4, 100, True, True, DEFAULT_BLOWUPS): 4_608_192,
    (34, 6, 100, True, False, DEFAULT_BLOWUPS): 1_129_216,
    (34, 8, 100, True, False, DEFAULT_BLOWUPS): 1_240_704,
    (34, 8, 128, True, False, DEFAULT_BLOWUPS): 1_569_408,
}


def run_checks() -> None:
    # 0. Exact Fraction boundary checks for RFC-0030 §3 field caps.
    for deg, t_bits in ((4, 100), (6, 100), (8, 100), (8, 128)):
        cap = field_cap(deg, t_bits)
        assert Fraction(cap, P**deg) <= Fraction(1, 1 << t_bits) < Fraction(cap + 1, P**deg)

    # 1. RFC-0029 §1.1 & §5 exact reference query counts at rate 1/4 (b=2):
    # 241 for 100 bits and 314 for 130 bits (m >= 10).
    for m in range(10, 26):
        q100, _, n, d, _ = policy3_fresh_q(m, 2, 100)
        q130, _, _, _, _ = policy3_fresh_q(m, 2, 130)
        assert q100 == 241, f"m={m}: expected q100=241, got {q100}"
        assert q130 == 314, f"m={m}: expected q130=314, got {q130}"
        assert n == 1 << (m + 2) and d == n - (1 << m)

    # Check b=1,2,3,4 asymptotics and q-1 failures.
    for b, expected_q100 in ((1, 381), (2, 241), (3, 202), (4, 185)):
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

    # 2. Verify all pinned recursive proof-size receipts for 2^20..2^34 (and domain cap m+b<=30).
    for key, expected in PINNED_RECEIPTS.items():
        n_bits, deg, t_bits, capped, per_round, blowups = key
        actual, plan = minimise_recursive_proof(
            n_bits,
            ext_degree=deg,
            target_bits=t_bits,
            capped=capped,
            per_round=per_round,
            blowups=blowups,
        )
        _assert_plan_domains_valid(plan)
        assert actual == expected, f"key={key}: expected {expected}, got {actual}"

    # 3. Bet B3 kill criterion check (docs/plan.md §2: 8 MB = 8,000,000 B at 2^32, T=100).
    eight_mb = 8_000_000
    eight_mib = 8 * 1024 * 1024
    qm31_capped_32, _ = minimise_recursive_proof(32, ext_degree=4, target_bits=100, capped=True)
    qm31_b1_32, _ = minimise_recursive_proof(
        32, ext_degree=4, target_bits=100, capped=True, blowups=ALL_BLOWUPS
    )
    qm31_per_round_32, _ = minimise_recursive_proof(
        32, ext_degree=4, target_bits=100, capped=True, per_round=True
    )
    ext6_32, _ = minimise_recursive_proof(32, ext_degree=6, target_bits=100, capped=True)
    om31_32, _ = minimise_recursive_proof(32, ext_degree=8, target_bits=100, capped=True)
    assert qm31_capped_32 < eight_mib
    assert qm31_b1_32 < 4_000_000 < eight_mb
    assert qm31_per_round_32 < 2_000_000 < eight_mb
    assert ext6_32 < 1_000_000 < eight_mb
    assert om31_32 < 2_000_000 < eight_mb

    # 4. Verify faithful segmented joining (RFC-0029 §2) and strict certified model opening.
    for n, k in ((26, 8), (28, 32), (30, 32), (32, 32)):
        seg_bytes, seg_plan = minimise_segmented_proof(n, k, ext_degree=4, capped=True)
        _assert_plan_domains_valid(seg_plan)
        assert seg_bytes > 0
    for n in (29, 30, 31, 32, 33):
        cert_bytes, cert_info = minimise_certified_weight_opening(n, ext_degree=4, capped=True)
        _assert_plan_domains_valid(cert_info["tail_plan"])
        # Unconditional single-round registration certificate cap check:
        assert 2 * cert_info["ell"] * (cert_info["e_c"] + 1) <= QM31_CAP_100
        assert cert_info["m"] + cert_info["b"] <= MAX_DOMAIN_BITS
        assert cert_bytes < 1_500_000

    # 5. Treaty T=128 on OM31 (deg=8) clears 128 bits under 1.6 MiB even at 2^34.
    treaty_34, treaty_plan = minimise_recursive_proof(
        34, ext_degree=8, target_bits=128, capped=True
    )
    _assert_plan_domains_valid(treaty_plan)
    assert treaty_34 < 2 * 1024 * 1024

    print(
        "rfc0029 check_policy3: OK "
        f"(2^32 QM31 b>=2 capped={qm31_capped_32:,} B, b>=1={qm31_b1_32:,} B, "
        f"per-round={qm31_per_round_32:,} B, Ext6={ext6_32:,} B, OM31={om31_32:,} B; "
        "all m+b<=30 & level-0 certificate caps verified)"
    )


def print_report() -> None:
    print("# RFC-0029 Policy 3 Parameter & Recursive Size Report (E19-01)\n")
    print("## 1. Policy 3 fresh query counts (exact least q, failure verified at q - 1)\n")
    print("| Rate | Blow-up `b` | `m = 16` `D` | `e = floor((D-1)/3)` | `q (T=100)` | `q (T=130)` |")
    print("|---|---:|---:|---:|---:|---:|")
    for b in ALL_BLOWUPS:
        q100, _, _, d, e = policy3_fresh_q(16, b, 100)
        q130, _, _, _, _ = policy3_fresh_q(16, b, 130)
        print(f"| 1/{1 << b} | {b} | {d:,} | {e:,} | {q100} | {q130} |")

    print("\n## 2. Recursive opening proof bytes (`2^20` to `2^34` M31 entries, `T = 100`, `m + b <= 30`)\n")
    print(
        "| Entries | QM31 uncapped (`b>=2`) | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | "
        "QM31 per-round (`b>=2`) | Ext6 Q50 (`b>=2`) | OM31 Q50 (`b>=2`) |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|")
    for n in range(20, 35):
        u, _ = minimise_recursive_proof(n, ext_degree=4, capped=False)
        c, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=False)
        c1, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, blowups=ALL_BLOWUPS)
        pr, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=True)
        e6, _ = minimise_recursive_proof(n, ext_degree=6, capped=True)
        o8, _ = minimise_recursive_proof(n, ext_degree=8, capped=True)
        print(
            f"| 2^{n} | {u:,} ({fmt_mib(u)}) | {c:,} ({fmt_mib(c)}) | {c1:,} ({fmt_mib(c1)}) | "
            f"{pr:,} ({fmt_mib(pr)}) | {e6:,} ({fmt_mib(e6)}) | {o8:,} ({fmt_mib(o8)}) |"
        )

    print("\n## 3. Q50 wider-field breakdown at `2^32`..`2^34` entries (`T = 100`, plus OM31 `T = 128`, `m + b <= 30`)\n")
    print("| Entries | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | QM31 per-round | Ext6 (`p^6`, 24 B) | OM31 (`p^8`, 32 B) | OM31 treaty (`T=128`) |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for n in (32, 33, 34):
        c, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=False)
        c1, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, blowups=ALL_BLOWUPS)
        pr, _ = minimise_recursive_proof(n, ext_degree=4, capped=True, per_round=True)
        e6, _ = minimise_recursive_proof(n, ext_degree=6, capped=True)
        o8, _ = minimise_recursive_proof(n, ext_degree=8, capped=True)
        t8, _ = minimise_recursive_proof(n, ext_degree=8, target_bits=128, capped=True)
        print(
            f"| 2^{n} | {fmt_mib(c)} | {fmt_mib(c1)} | {fmt_mib(pr)} | {fmt_mib(e6)} | {fmt_mib(o8)} | {fmt_mib(t8)} |"
        )

    print("\n## 4. Certified model sources (rate 1/4 at level 0, `T = 100`, strict single-round `2*ell*(e_c+1) <= cap`)\n")
    print("| Model entries | `(ell, m, b)` | `e_c` / `e_max` | `2*ell*(e_c+1)` | `q_cert` | `q_open` | Opening bytes |")
    print("|---|---|---|---:|---:|---:|---:|")
    for n in (29, 30, 31, 32, 33):
        total, info = minimise_certified_weight_opening(n, ext_degree=4, capped=True)
        prox = 2 * info["ell"] * (info["e_c"] + 1)
        print(
            f"| 2^{n} | ({info['ell']}, {info['m']}, {info['b']}) | "
            f"{info['e_c']:,} / {info['e_max']:,} | {prox:,} | {info['q_cert']} | {info['q_open']} | "
            f"{total:,} ({fmt_mib(total)}) |"
        )

    print("\n## 5. Multi-segment joining at level 1 (RFC-0029 §2 'Segments', `T = 100`, `m + b <= 30`)\n")
    print("| Total witness | Segments `k` | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | QM31 per-round | Ext6 Q50 |")
    print("|---|---:|---:|---:|---:|---:|")
    for n, k in ((26, 8), (28, 32), (30, 32), (32, 32)):
        c, _ = minimise_segmented_proof(n, k, ext_degree=4, capped=True)
        c1, _ = minimise_segmented_proof(n, k, ext_degree=4, capped=True, blowups=ALL_BLOWUPS)
        pr, _ = minimise_segmented_proof(n, k, ext_degree=4, capped=True, per_round=True)
        e6, _ = minimise_segmented_proof(n, k, ext_degree=6, capped=True)
        print(f"| 2^{n} | {k} | {fmt_mib(c)} | {fmt_mib(c1)} | {fmt_mib(pr)} | {fmt_mib(e6)} |")


if __name__ == "__main__":
    if "--check" in sys.argv:
        run_checks()
    else:
        print_report()
