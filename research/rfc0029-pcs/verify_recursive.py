# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Independent Python verifier for RFC-0029 §2 fresh-mode recursive Circle RS openings (task E19-03).

Reproduces Rust `stele_pcs::recursive::{verify_fresh_at_point, verify_fresh_claims}` decisions
(honest acceptance + transcript continuation and exact rejection on NC-0630..0634) straight from
the specs: RFC-0003 §2, RFC-0010 A2/A17, RFC-0012 A1/A3/A10/A20, RFC-0029 §§2, 5.

Usage:
  uv run --offline --script research/rfc0029-pcs/verify_recursive.py
  cargo run -q -p stele-pcs --example recursive_oracle -- --vectors | \\
    uv run --offline --script research/rfc0029-pcs/verify_recursive.py --stdin
"""
from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import sys
from blake3 import blake3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check_policy3 import MAX_DOMAIN_BITS, P, circle_params, policy3_fresh_q  # noqa: E402

INV2 = 1 << 30  # 2^-1 mod (2^31 - 1)
PURPOSE = b"stele/v0.1/field-source"
INIT_LABEL = b"stele/v0.1/transcript/init"
PUBLIC_LABEL = b"stele/v0.1/public"
CODE_PREFIX = b"stele/circle-coeff-m31/v1"

# RFC-0012 A1/A10/A20 registered transcript labels used by RFC-0029.
L_INSTANCE = b"stele/v0.1/sumcheck/instance"
L_ROUND = b"stele/v0.1/sumcheck/round"
L_FINAL = b"stele/v0.1/sumcheck/final"
L_SUMCHECK = b"stele/v0.1/sumcheck/challenge"
L_BATCH = b"stele/v0.1/sumcheck/batch"
L_BATCH_COEFF = b"stele/v0.1/sumcheck/batch-coefficient"
L_OPENING = b"stele/v0.1/pcs/opening"
L_OPENING_COL = b"stele/v0.1/pcs/opening-column"
L_OPENING_COLS = b"stele/v0.1/pcs/opening-columns"
L_FIELD_SOURCES = b"stele/v0.1/pcs/sources"
L_LEVEL_ROOT = b"stele/v0.1/pcs/level-root"
L_LEVEL_BETA = b"stele/v0.1/pcs/level-beta"


class VerifyError(Exception):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


# ---------- QM31 arithmetic (RFC-0003 §2: CM31 = M31[i]/(i^2+1), QM31 = CM31[u]/(u^2-(2+i))) ----------

QM31 = tuple[int, int, int, int]
Q_ZERO: QM31 = (0, 0, 0, 0)
Q_ONE: QM31 = (1, 0, 0, 0)


def q_add(x: QM31, y: QM31) -> QM31:
    return ((x[0] + y[0]) % P, (x[1] + y[1]) % P, (x[2] + y[2]) % P, (x[3] + y[3]) % P)


def q_sub(x: QM31, y: QM31) -> QM31:
    return ((x[0] - y[0]) % P, (x[1] - y[1]) % P, (x[2] - y[2]) % P, (x[3] - y[3]) % P)


def q_neg(x: QM31) -> QM31:
    return ((-x[0]) % P, (-x[1]) % P, (-x[2]) % P, (-x[3]) % P)


def q_mul_m31(x: QM31, s: int) -> QM31:
    return ((x[0] * s) % P, (x[1] * s) % P, (x[2] * s) % P, (x[3] * s) % P)


def q_mul(x: QM31, y: QM31) -> QM31:
    a0, a1, b0, b1 = x
    c0, c1, d0, d1 = y
    ac0 = (a0 * c0 - a1 * c1) % P
    ac1 = (a0 * c1 + a1 * c0) % P
    bd0 = (b0 * d0 - b1 * d1) % P
    bd1 = (b0 * d1 + b1 * d0) % P
    r0 = (ac0 + 2 * bd0 - bd1) % P
    r1 = (ac1 + bd0 + 2 * bd1) % P
    s0 = (a0 * d0 - a1 * d1 + b0 * c0 - b1 * c1) % P
    s1 = (a0 * d1 + a1 * d0 + b0 * c1 + b1 * c0) % P
    return (r0, r1, s0, s1)


def q_to_bytes(x: QM31) -> bytes:
    return struct.pack("<4I", *x)


def q_from_bytes(buf: bytes) -> QM31:
    if len(buf) != 16:
        raise VerifyError("ProofShape")
    limbs = struct.unpack("<4I", buf)
    if any(v >= P for v in limbs):
        raise VerifyError("NoncanonicalField")
    return limbs  # type: ignore[return-value]


def m31_from_bytes(buf: bytes) -> int:
    (v,) = struct.unpack("<I", buf)
    if v >= P:
        raise VerifyError("NoncanonicalField")
    return v


def eq_table(point: list[QM31]) -> list[QM31]:
    table = [Q_ONE]
    for r in point:
        nxt: list[QM31] = []
        for parent in table:
            right = q_mul(parent, r)
            nxt.append(q_sub(parent, right))
            nxt.append(right)
        table = nxt
    return table


def eq_eval(left: list[QM31], right: list[QM31]) -> QM31:
    acc = Q_ONE
    for a, b in zip(left, right, strict=True):
        acc = q_mul(acc, q_add(q_mul(q_sub(Q_ONE, a), q_sub(Q_ONE, b)), q_mul(a, b)))
    return acc


def interp_deg2(y0: QM31, y1: QM31, y2: QM31, r: QM31) -> QM31:
    r_m1 = q_sub(r, Q_ONE)
    r_m2 = q_sub(r, (2, 0, 0, 0))
    t0 = q_mul_m31(q_mul(y0, q_mul(r_m1, r_m2)), INV2)
    t1 = q_neg(q_mul(y1, q_mul(r, r_m2)))
    t2 = q_mul_m31(q_mul(y2, q_mul(r, r_m1)), INV2)
    return q_add(q_add(t0, t1), t2)


# ---------- Coefficient-form Circle RS (RFC-0010 A2 & RFC-0029 §1.2) ----------

CIRCLE_GEN = (1717986917, 1288490189)


def circle_mul(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    return ((a[0] * b[0] - a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)


def circle_pow(exp: int) -> tuple[int, int]:
    g = CIRCLE_GEN
    val = (1, 0)
    while exp:
        if exp & 1:
            val = circle_mul(val, g)
        g = circle_mul(g, g)
        exp >>= 1
    return val


def circle_twiddles(log: int) -> list[list[int]]:
    if log == 0:
        return []
    half = 1 << (log - 1)
    ys = []
    xs = []
    pt = circle_pow(1 << (30 - log))
    step = circle_mul(pt, pt)
    for j in range(half):
        ys.append(pt[1])
        if j < half // 2:
            xs.append(pt[0])
        pt = circle_mul(pt, step)
    levels = [ys]
    if xs:
        levels.append(xs)
    for lvl in range(2, log):
        prev = levels[lvl - 1]
        levels.append([(2 * x * x - 1) % P for x in prev[: len(prev) // 2]])
    return levels


def bit_reverse_list(vals: list[QM31], log: int) -> list[QM31]:
    out = list(vals)
    for j in range(len(out)):
        rev = int(f"{j:0{log}b}"[::-1], 2) if log else 0
        if j < rev:
            out[j], out[rev] = out[rev], out[j]
    return out


def circle_coeff_encode_qm31(m: int, b: int, row: list[QM31]) -> list[QM31]:
    log = m + b
    n = 1 << log
    vals = list(row) + [Q_ZERO] * (n - len(row))
    if n == 1:
        return vals
    tw = circle_twiddles(log)
    vals = bit_reverse_list(vals, log)
    for level in reversed(tw):
        half = len(level)
        width = 2 * half
        for base in range(0, n, width):
            vals[base + half : base + width] = reversed(vals[base + half : base + width])
            for j, twiddle in enumerate(level):
                opp = width - 1 - j
                a = vals[base + j]
                b_val = q_mul_m31(vals[base + opp], twiddle)
                vals[base + j] = q_add(a, b_val)
                vals[base + opp] = q_sub(a, b_val)
    return vals


def circle_basis_factors_msb(m: int, b: int, column: int) -> list[int]:
    if m == 0:
        return []
    log = m + b
    half0 = 1 << (log - 1)
    if column < half0:
        cur, neg_y = column, False
    else:
        cur, neg_y = 2 * half0 - 1 - column, True
    pt = circle_pow((2 * cur + 1) << (30 - log))
    factors = [(-pt[1]) % P if neg_y else pt[1]]
    if m >= 2:
        x_val = pt[0]
        factors.append(x_val)
        for _ in range(2, m):
            x_val = (2 * x_val * x_val - 1) % P
            factors.append(x_val)
    factors.reverse()
    return factors


def fill_basis_table(factors_msb: list[int]) -> list[int]:
    out = [1]
    for f in factors_msb:
        nxt = []
        for parent in out:
            nxt.append(parent)
            nxt.append((parent * f) % P)
        out = nxt
    return out


# ---------- RFC-0012 A1/A10/A20 Transcript & RFC-0012 A3 Merkle ----------


class Transcript:
    def __init__(self, public: bytes) -> None:
        init = blake3(INIT_LABEL).digest()
        self.state = self._frame(init, 0, PUBLIC_LABEL, public)

    @staticmethod
    def _frame(state: bytes, tag: int, label: bytes, payload: bytes) -> bytes:
        h = blake3()
        h.update(state)
        h.update(bytes([tag]))
        h.update(struct.pack("<I", len(label)))
        h.update(label)
        h.update(struct.pack("<Q", len(payload)))
        h.update(payload)
        return h.digest()

    @staticmethod
    def _xof(state: bytes, tag: int, label: bytes, payload: bytes, length: int) -> bytes:
        h = blake3()
        h.update(state)
        h.update(bytes([tag]))
        h.update(struct.pack("<I", len(label)))
        h.update(label)
        h.update(struct.pack("<Q", len(payload)))
        h.update(payload)
        return h.digest(length=length)

    def absorb(self, label: bytes, payload: bytes) -> None:
        self.state = self._frame(self.state, 0, label, payload)

    def challenge(self, label: bytes) -> QM31:
        raw = self._xof(self.state, 1, label, bytes([4]), 256)
        limbs: list[int] = []
        consumed = 0
        for consumed, (word,) in enumerate(struct.iter_unpack("<I", raw), 1):
            limb = word & P
            if limb < P:
                limbs.append(limb)
                if len(limbs) == 4:
                    break
        if len(limbs) != 4:
            raise VerifyError("Transcript")
        val: QM31 = (limbs[0], limbs[1], limbs[2], limbs[3])
        payload = bytes([4]) + struct.pack("<I", consumed) + q_to_bytes(val)
        self.state = self._frame(self.state, 2, label, payload)
        return val

    def opening_column(self, length: int) -> int:
        threshold = P - (length - 1)
        for _ in range(64):
            first = self.challenge(L_OPENING_COL)[0]
            if first < threshold:
                return first % length
        raise VerifyError("Transcript")


def merkle_verify(tree_id: int, count: int, width: int, root: bytes, index: int, payload: bytes, siblings: list[bytes]) -> None:
    def start(tag: int) -> blake3:
        h = blake3()
        h.update(bytes([tag]))
        h.update(b"stele/v0.1/merkle")
        h.update(bytes([0]))  # Kind::Columns
        h.update(struct.pack("<QQQ", tree_id, count, width))
        return h

    h = start(0)
    h.update(struct.pack("<Q", index))
    h.update(bytes([1 if index < count else 0]))
    h.update(payload)
    cur = h.digest()
    idx = index
    for depth, sib in enumerate(siblings, 1):
        left, right = (cur, sib) if (idx & 1) == 0 else (sib, cur)
        hn = start(1)
        hn.update(struct.pack("<IQ", depth, idx >> 1))
        hn.update(left)
        hn.update(right)
        cur = hn.digest()
        idx >>= 1
    if cur != root:
        raise VerifyError("RootMismatch")


# ---------- Version-4 source context & RFC-0029 §2 verifier ----------


def parse_source(raw: bytes) -> dict:
    if len(raw) < 114 or raw[:23] != PURPOSE:
        raise VerifyError("UnsupportedSource")
    if raw[23] != 4 or raw[24] != 4 or raw[77] != 0 or raw[78] != 3:
        raise VerifyError("UnsupportedSource")
    (source_id,) = struct.unpack_from("<Q", raw, 25)
    ell0 = raw[33]
    code_id = raw[34:61]
    if code_id[:25] != CODE_PREFIX:
        raise VerifyError("UnsupportedSource")
    m0, b0 = code_id[25], code_id[26]
    r0, c0 = struct.unpack_from("<QQ", raw, 61)
    if r0 != (1 << ell0) or c0 != (1 << m0):
        raise VerifyError("UnsupportedSource")
    root0 = raw[79:111]
    (target_bits,) = struct.unpack_from("<H", raw, 111)
    level_count = raw[113]
    if level_count == 0 or len(raw) != 114 + 7 * level_count:
        raise VerifyError("UnsupportedSource")
    levels = []
    queries = []
    for i in range(level_count):
        ell, m, b, rand_c, mask_r = struct.unpack_from("<BBBHH", raw, 114 + 7 * i)
        if ell == 0 or b not in (1, 2, 3, 4) or m + b > MAX_DOMAIN_BITS or rand_c != 0 or mask_r != 0:
            raise VerifyError("UnsupportedSource")
        if i + 1 < level_count and m == 0:
            raise VerifyError("UnsupportedSource")
        q, _, _, _, _ = policy3_fresh_q(m, b, target_bits)
        levels.append((ell, m, b))
        queries.append(q)
    if levels[0] != (ell0, m0, b0):
        raise VerifyError("UnsupportedSource")
    for i in range(level_count - 1):
        if levels[i + 1][0] + levels[i + 1][1] != levels[i][1]:
            raise VerifyError("UnsupportedSource")
    return {
        "id": source_id,
        "root": root0,
        "target_bits": target_bits,
        "levels": levels,
        "queries": queries,
        "raw": raw,
    }


def expected_proof_size(src: dict) -> int:
    levels = src["levels"]
    queries = src["queries"]
    l = len(levels)
    total = 2 + 3 * l
    for i, ((ell, m, b), q) in enumerate(zip(levels, queries, strict=True)):
        elem = 4 if i == 0 else 16
        if i >= 1:
            total += ell * 3 * 16
        total += 32 if i + 1 < l else (1 << m) * 16
        total += q * (elem * (1 << ell) + 32 * (m + b))
    return total


def check_header(src: dict, proof: bytes) -> int:
    levels = src["levels"]
    hdr_len = 2 + 3 * len(levels)
    if len(proof) != expected_proof_size(src) or len(proof) < hdr_len:
        raise VerifyError("ProofShape")
    if proof[0] != 4 or proof[1] != len(levels):
        raise VerifyError("ProofShape")
    for i, (ell, m, b) in enumerate(levels):
        if (proof[2 + 3 * i], proof[3 + 3 * i], proof[4 + 3 * i]) != (ell, m, b):
            raise VerifyError("ProofShape")
    return hdr_len


def verify_fresh_at_point(
    t: Transcript, src: dict, opening_id: int, point: list[QM31], value: QM31, proof: bytes
) -> None:
    cursor = check_header(src, proof)
    levels = src["levels"]
    queries = src["queries"]
    l = len(levels)
    ell0, m0, _ = levels[0]
    if len(point) != ell0 + m0:
        raise VerifyError("MessageShape")

    stmt = struct.pack("<Q", opening_id) + src["raw"] + b"".join(q_to_bytes(p) for p in point) + q_to_bytes(value)
    t.absorb(L_OPENING, stmt)

    # Terms: ("eq", coeff, point_tail) | ("basis", coeff, factors_msb_tail)
    terms: list[tuple] = [("eq", Q_ONE, list(point[ell0:]))]
    cur_root = src["root"]
    cur_claim = value

    for i in range(l):
        ell, m, b = levels[i]
        q_i = queries[i]
        _, n_i, _, _ = circle_params(m, b)
        if i == 0:
            eq_row = eq_table(point[:ell0])
        else:
            inst = struct.pack("<QBBB", opening_id, i, ell, 2) + q_to_bytes(cur_claim)
            t.absorb(L_INSTANCE, inst)
            r_i: list[QM31] = []
            for rnd in range(ell):
                chunk = proof[cursor : cursor + 48]
                cursor += 48
                y0, y1, y2 = q_from_bytes(chunk[:16]), q_from_bytes(chunk[16:32]), q_from_bytes(chunk[32:48])
                if q_add(y0, y1) != cur_claim:
                    raise VerifyError("RoundSumMismatch")
                t.absorb(L_ROUND, struct.pack("<QI", opening_id, rnd) + chunk)
                r = t.challenge(L_SUMCHECK)
                cur_claim = interp_deg2(y0, y1, y2, r)
                r_i.append(r)
            new_terms = []
            for kind, coeff, data in terms:
                if kind == "eq":
                    c2 = q_mul(coeff, eq_eval(data[:ell], r_i))
                    new_terms.append(("eq", c2, data[ell:]))
                else:
                    acc = Q_ONE
                    for f, x in zip(data[:ell], r_i, strict=True):
                        acc = q_mul(acc, q_add(q_sub(Q_ONE, x), q_mul_m31(x, f)))
                    new_terms.append(("basis", q_mul(coeff, acc), data[ell:]))
            terms = new_terms
            eq_row = eq_table(r_i)

        next_root = b""
        u_final: list[QM31] | None = None
        if i + 1 < l:
            next_root = proof[cursor : cursor + 32]
            cursor += 32
            t.absorb(L_LEVEL_ROOT, next_root)
        else:
            u_bytes = proof[cursor : cursor + (1 << m) * 16]
            cursor += (1 << m) * 16
            u_final = [q_from_bytes(u_bytes[k : k + 16]) for k in range(0, len(u_bytes), 16)]
            t.absorb(L_LEVEL_ROOT, u_bytes)

        elem_i = 4 if i == 0 else 16
        width = (1 << ell) * elem_i
        path_h = m + b
        path_b = path_h * 32
        resp_start = cursor
        tree_id = src["id"] ^ (i << 56)
        queried: list[int] = []
        ys: list[QM31] = []
        for _ in range(q_i):
            idx = t.opening_column(n_i)
            payload = proof[cursor : cursor + width]
            cursor += width
            sib_bytes = proof[cursor : cursor + path_b]
            cursor += path_b
            siblings = [sib_bytes[k : k + 32] for k in range(0, path_b, 32)]
            merkle_verify(tree_id, n_i, width, cur_root, idx, payload, siblings)
            y = Q_ZERO
            if i == 0:
                for row_idx, w in enumerate(eq_row):
                    v = m31_from_bytes(payload[row_idx * 4 : row_idx * 4 + 4])
                    y = q_add(y, q_mul_m31(w, v))
            else:
                for row_idx, w in enumerate(eq_row):
                    v = q_from_bytes(payload[row_idx * 16 : row_idx * 16 + 16])
                    y = q_add(y, q_mul(w, v))
            queried.append(idx)
            ys.append(y)
        t.absorb(L_OPENING_COLS, proof[resp_start:cursor])

        if i + 1 < l:
            beta = t.challenge(L_LEVEL_BETA)
            bp = beta
            for idx, y in zip(queried, ys, strict=True):
                cur_claim = q_add(cur_claim, q_mul(bp, y))
                terms.append(("basis", bp, circle_basis_factors_msb(m, b, idx)))
                bp = q_mul(bp, beta)
            cur_root = next_root
        else:
            assert u_final is not None
            encoded = circle_coeff_encode_qm31(m, b, u_final)
            for idx, y in zip(queried, ys, strict=True):
                if encoded[idx] != y:
                    raise VerifyError("ColumnMismatch")
            dot = Q_ZERO
            for kind, coeff, data in terms:
                if kind == "eq":
                    tbl = eq_table(data)
                    sub = Q_ZERO
                    for a, u in zip(tbl, u_final, strict=True):
                        sub = q_add(sub, q_mul(a, u))
                    dot = q_add(dot, q_mul(coeff, sub))
                else:
                    tbl = fill_basis_table(data)
                    sub = Q_ZERO
                    for b_val, u in zip(tbl, u_final, strict=True):
                        sub = q_add(sub, q_mul_m31(u, b_val))
                    dot = q_add(dot, q_mul(coeff, sub))
            if dot != cur_claim:
                raise VerifyError("ValueMismatch")


def verify_fresh_claims(
    t: Transcript, src: dict, opening_id: int, claims: list[tuple[list[QM31], QM31]], proof: bytes
) -> None:
    ell0, m0, _ = src["levels"][0]
    vars_n = ell0 + m0
    prefix_len = vars_n * 48 + 16
    if len(proof) != prefix_len + expected_proof_size(src):
        raise VerifyError("ProofShape")
    check_header(src, proof[prefix_len:])

    t.absorb(L_FIELD_SOURCES, src["raw"])
    hdr = struct.pack("<QI", opening_id, len(claims))
    for p, v in claims:
        hdr += b"".join(q_to_bytes(c) for c in p) + q_to_bytes(v)
    t.absorb(L_BATCH, hdr)

    lam = t.challenge(L_BATCH_COEFF) if len(claims) > 1 else Q_ONE
    batch_claim = Q_ZERO
    lp = Q_ONE
    for _, v in claims:
        batch_claim = q_add(batch_claim, q_mul(lp, v))
        lp = q_mul(lp, lam)

    t.absorb(L_INSTANCE, struct.pack("<QBBB", opening_id, 0xFF, vars_n, 2) + q_to_bytes(batch_claim))
    cursor = 0
    r_star: list[QM31] = []
    running = batch_claim
    for rnd in range(vars_n):
        chunk = proof[cursor : cursor + 48]
        cursor += 48
        y0, y1, y2 = q_from_bytes(chunk[:16]), q_from_bytes(chunk[16:32]), q_from_bytes(chunk[32:48])
        if q_add(y0, y1) != running:
            raise VerifyError("RoundSumMismatch")
        t.absorb(L_ROUND, struct.pack("<QI", opening_id, rnd) + chunk)
        r = t.challenge(L_SUMCHECK)
        running = interp_deg2(y0, y1, y2, r)
        r_star.append(r)

    v_bytes = proof[cursor : cursor + 16]
    cursor += 16
    v_star = q_from_bytes(v_bytes)
    t.absorb(L_FINAL, v_bytes)

    w_at_r = Q_ZERO
    lp = Q_ONE
    for p, _ in claims:
        w_at_r = q_add(w_at_r, q_mul(lp, eq_eval(p, r_star)))
        lp = q_mul(lp, lam)
    if q_mul(w_at_r, v_star) != running:
        raise VerifyError("RoundSumMismatch")

    verify_fresh_at_point(t, src, opening_id, r_star, v_star, proof[cursor:])


def check_vector(rec: dict) -> None:
    t = Transcript(bytes.fromhex(rec["public_hex"]))
    src = parse_source(bytes.fromhex(rec["source_bytes_hex"]))
    proof = bytes.fromhex(rec["proof_hex"])
    opening_id = int(rec["opening_id"])
    try:
        if rec["kind"] == "at_point":
            p_raw = bytes.fromhex(rec["point_hex"])
            point = [q_from_bytes(p_raw[k : k + 16]) for k in range(0, len(p_raw), 16)]
            value = q_from_bytes(bytes.fromhex(rec["value_hex"]))
            verify_fresh_at_point(t, src, opening_id, point, value, proof)
        elif rec["kind"] == "fresh_claims":
            claims = []
            for c in rec["claims"]:
                p_raw = bytes.fromhex(c["point_hex"])
                pt = [q_from_bytes(p_raw[k : k + 16]) for k in range(0, len(p_raw), 16)]
                val = q_from_bytes(bytes.fromhex(c["value_hex"]))
                claims.append((pt, val))
            verify_fresh_claims(t, src, opening_id, claims, proof)
        else:
            raise AssertionError(f"unknown kind {rec['kind']}")
        decision = "Accept"
        cont = q_to_bytes(t.challenge(L_SUMCHECK)).hex()
    except VerifyError as exc:
        decision = exc.kind
        cont = ""

    if decision != rec["rust_decision"]:
        raise AssertionError(
            f"{rec['name']}: Python decision={decision!r} != Rust decision={rec['rust_decision']!r}"
        )
    if decision == "Accept" and cont != rec["continuation_hex"]:
        raise AssertionError(
            f"{rec['name']}: continuation mismatch py={cont} rust={rec['continuation_hex']}"
        )


def main() -> None:
    if "--stdin" in sys.argv:
        lines = [line.strip() for line in sys.stdin if line.strip()]
    else:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        proc = subprocess.run(
            ["cargo", "run", "-q", "-p", "stele-pcs", "--example", "recursive_oracle", "--", "--vectors"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert lines, "no vectors produced"
    accepted = 0
    rejected = 0
    for line in lines:
        rec = json.loads(line)
        check_vector(rec)
        if rec["rust_decision"] == "Accept":
            accepted += 1
        else:
            rejected += 1
    print(
        f"rfc0029 verify_recursive: OK ({len(lines)} vectors verified: "
        f"{accepted} Accept with bit-exact continuation, {rejected} exact Reject parity)"
    )


if __name__ == "__main__":
    main()
