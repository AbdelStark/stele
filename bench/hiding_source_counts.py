"""RFC-0014 A5. Reconcile device work with the independently verified byte-4 PCS schedule."""
import re


def proof_inventory(proof):
    """Read only authenticated byte-4 round lengths (RFC-0026 A9, QM31 wire width 16)."""
    magic = b"stele-dev-zk-v1"
    if not proof.startswith(magic):
        raise ValueError("wrong proof header")
    cursor = len(magic) + 64  # CQIS id and statement digest

    def take(n):
        nonlocal cursor
        start = cursor
        cursor += n
        if cursor > len(proof):
            raise ValueError("truncated proof inventory")
        return start

    def count():
        start = take(4)
        return int.from_bytes(proof[start:start + 4], "little")

    def sumcheck(dense=False):
        take(16)  # mask sum
        n = count()
        values = 0
        for _ in range(n):
            width = count()
            if dense and width != 3:
                raise ValueError("invalid degree-two batch polynomial")
            take(16 * width)
            values += width
        finals = count()
        if dense and finals != 2:
            raise ValueError("invalid dense batch finals")
        take(16 * finals + 16)  # original finals and mask final
        return n, values, finals

    for _ in range(2):  # original sources and certificates
        for _ in range(count()):
            take(count())
    relations = count()
    rel_rounds = rel_nodes = rel_finals = 0
    for _ in range(relations):
        n, values, finals = sumcheck()
        rel_rounds += n
        rel_nodes += values
        rel_finals += finals
    steps = count()
    rounds = evaluations = 0
    for _ in range(steps):
        n, width, _ = sumcheck()
        rounds += n
        evaluations += width
    batches = count()
    batch_rounds = 0
    for _ in range(batches):
        batch_rounds += sumcheck(dense=True)[0]
        take(count())  # source opening
    source_length = count()
    start = take(source_length)
    standalone = proof[start:start + source_length]
    take(count())  # standalone mask certificate
    n, values, finals = sumcheck(dense=True)
    if n == 0 or values != 3 * n or finals != 2:
        raise ValueError("invalid shared degree-two batch")
    take(count())  # opening of the standalone mask polynomial
    take(count())  # opening of the shared source
    if cursor != len(proof):
        raise ValueError("trailing bytes in verified proof")
    return ((relations, rel_rounds, rel_nodes, rel_finals), (steps, rounds, evaluations),
            (batches + 1, batch_rounds + n), standalone, n)


def source_work(proof, verified, standalone=False):
    magic = b"stele-dev-zk-v1"
    pos = len(magic) + 64
    if not proof.startswith(magic) or len(proof) < pos + 4:
        raise ValueError("missing byte-4 proof")
    n = int.from_bytes(proof[pos:pos + 4], "little")
    pos += 4
    labels = "source [0-9]+|shared mask source" + ("|shared batch mask source" if standalone else "")
    rows = re.findall(rf"^PCS\t({labels})\trow exponent (\d+), policy Two, "
                      r"q_c/q_o (\d+)/(\d+), k_t \d+, k_q \d+, ([01]) opening\(s\);", verified, re.M)
    if not rows or len(rows) != n + int(standalone):
        raise ValueError("missing verified hiding source")
    ids = set()
    work = dict(originals=len(rows), visits=0, responses=0, hashes=0, h2d_bytes=0, d2h_bytes=0, host_salt_bytes=0)
    if standalone:
        relations, gkr, batches, mask_context, shared_rounds = proof_inventory(proof)
        mask_id = n + relations[0] + gkr[0] + batches[0] - 1
        work["original_h2d_bytes"] = 0
    for i, (label, log_rows, cert, opening, used) in enumerate(rows):
        if i == n:
            src, length, expected_label = mask_context, len(mask_context), "shared batch mask source"
            if used != "1" or int(log_rows) != 4:
                raise ValueError("invalid standalone mask use")
        else:
            length = int.from_bytes(proof[pos:pos + 4], "little")
            pos += 4
            src = proof[pos:pos + length]
            pos += length
            expected_label = f"source {i}" if i + 1 < n else "shared mask source"
        if (label != expected_label or length != 105 or len(src) != length
                or src[:25] != b"stele/v0.1/field-source\x03\x04" or src[34:53] != b"stele/circle-m31/v1"
                or src[33] != int(log_rows) or src[33] > 30 or not 1 <= src[53] <= 28
                or src[54] != 2 or src[71:73] != b"\x00\x02" or src[25:33] in ids):
            raise ValueError("invalid verified hiding-source context")
        ids.add(src[25:33])
        r, c = 1 << src[33], 1 << src[53]
        if int.from_bytes(src[55:63], "little") != r or int.from_bytes(src[63:71], "little") != c:
            raise ValueError("inconsistent hiding-source geometry")
        if standalone:
            if int.from_bytes(src[25:33], "little") != (mask_id if i == n else i):
                raise ValueError("wrong proof-local source ID")
            if i == n - 1 and shared_rounds != src[33] + src[53] - 1:
                raise ValueError("shared batch does not match shared source geometry")
            work["original_h2d_bytes"] += 4 * r * c
            if i == n and c != 2 << max(9, (3 * shared_rounds - 1).bit_length()):
                raise ValueError("invalid standalone mask source width")
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


def check_source_work(measured, proof, verified, peak_limit, standalone=False):
    expected = source_work(proof, verified, standalone)
    if (any(measured.get(key) != value for key, value in expected.items())
            or not 0 < measured.get("observed_peak_bytes", 0) <= peak_limit):
        raise ValueError("CUDA source work differs from the verified PCS schedule")
    return expected
