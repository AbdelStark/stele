"""RFC-0014 A5. Reconcile device work with the independently verified byte-4 PCS schedule."""
import re


def source_work(proof, verified):
    magic = b"stele-dev-zk-v1"
    pos = len(magic) + 64
    if not proof.startswith(magic) or len(proof) < pos + 4:
        raise ValueError("missing byte-4 proof")
    n = int.from_bytes(proof[pos:pos + 4], "little")
    pos += 4
    rows = re.findall(r"^PCS\t(source [0-9]+|shared mask source)\trow exponent (\d+), policy Two, "
                      r"q_c/q_o (\d+)/(\d+), k_t \d+, k_q \d+, ([01]) opening\(s\);", verified, re.M)
    if not rows or len(rows) != n:
        raise ValueError("missing verified hiding source")
    ids = set()
    work = dict(originals=n, visits=0, responses=0, hashes=0, h2d_bytes=0, d2h_bytes=0, host_salt_bytes=0)
    for i, (label, log_rows, cert, opening, used) in enumerate(rows):
        length = int.from_bytes(proof[pos:pos + 4], "little")
        pos += 4
        src = proof[pos:pos + length]
        pos += length
        if (label != (f"source {i}" if i + 1 < n else "shared mask source") or length != 105 or len(src) != length
                or src[:25] != b"stele/v0.1/field-source\x03\x04" or src[34:53] != b"stele/circle-m31/v1"
                or src[33] != int(log_rows) or src[33] > 30 or not 1 <= src[53] <= 28
                or src[54] != 2 or src[71:73] != b"\x00\x02" or src[25:33] in ids):
            raise ValueError("invalid verified hiding-source context")
        ids.add(src[25:33])
        r, c = 1 << src[33], 1 << src[53]
        if int.from_bytes(src[55:63], "little") != r or int.from_bytes(src[63:71], "little") != c:
            raise ValueError("inconsistent hiding-source geometry")
        visits = 1 + int(used)
        queries = int(cert) + int(used) * int(opening)
        leaves = 4 * c
        if min(int(cert), int(opening)) <= 0:
            raise ValueError("missing source queries")
        work["visits"] += visits
        work["responses"] += queries
        work["hashes"] += visits * (2 * leaves - 1)
        # Both twiddle tables, two Merkle prefixes, seed key and salt-domain block per visit.
        work["h2d_bytes"] += visits * (4 * (c - 1 + leaves - 1) + 2 * 43 + 32 + 64)
        work["d2h_bytes"] += 32 * visits + queries * (4 * r + 32 * (src[53] + 2))
        work["host_salt_bytes"] += queries * 32
    return work


def check_source_work(measured, proof, verified, peak_limit):
    expected = source_work(proof, verified)
    if (any(measured.get(key) != value for key, value in expected.items())
            or not 0 < measured.get("observed_peak_bytes", 0) <= peak_limit):
        raise ValueError("CUDA source work differs from the verified PCS schedule")
    return expected
