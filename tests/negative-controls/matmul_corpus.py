# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0007 A2: independent complete matmul wires, records, controls and usage.

Reference instrumentation is process-global; run sequentially. No native receipt
or original matrix enters the reference verifier or determines expected results.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
from pathlib import Path
import json
import subprocess
import tempfile
from itertools import zip_longest
import random
import struct
import sys

sys.dont_write_bytecode = True

MATMUL = b"stele/v0.1/matmul/statement"
STRATA = ((0, 0, 0, 0), (0, 1, 0, 2), (1, 0, 0, 1), (0, 2, 1, 0),
          (1, 1, 1, 2), (2, 1, 0, 0), (0, 0, 2, 1), (1, 2, 2, 1))
RATES = ((1, 1), (1, 2), (2, 1), (2, 2))
pcs = stage = sc = raw_hash = base_transcript = None
_created = None


def configure(repo):
    """Load the actual research engines, preserving one shared field module."""
    global pcs, stage, sc, raw_hash, base_transcript
    repo = Path(repo).resolve()
    sys.dont_write_bytecode = True
    for name in ("merkle-oracle", "stacked-gkr"):
        sys.path.insert(0, str(repo / "research" / name))
    pcs = importlib.import_module("field_wire")
    stage = importlib.import_module("stage")
    raw_hash = importlib.import_module("blake3").blake3
    sc = pcs.sc
    assert sc is stage.sc
    paths = ((pcs, "merkle-oracle/field_wire.py"),
             (stage, "stacked-gkr/stage.py"), (sc, "sumcheck/check_sumcheck.py"))
    for module, suffix in paths:
        assert Path(module.__file__).resolve() == repo / "research" / suffix
    base_transcript = pcs.Transcript
    return {suffix: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module, suffix in paths}


def hashes():
    return dict(hash_evaluations=0, xof_requests=0, xof_bytes=0, state_updates=0,
                candidate_words=0, column_attempts=0)


class Transcript:
    """Exact reference transcript with actual call counts and high-level replay log."""
    def __init__(self, public, degree):
        pcs.require(public and degree in (4, 8), "InvalidTranscript")
        self.degree, self.public = degree, public
        self.state = raw_hash(pcs.frame(raw_hash(pcs.INITIAL).digest(), 0, pcs.PUBLIC, public)).digest()
        self.usage = hashes() | dict(hash_evaluations=2, state_updates=1)
        self.events, self.a1_draws, self.in_column = [], [], False
        if _created is not None:
            _created.append(self)

    def absorb(self, label, payload):
        pcs.require(label in (*pcs.ABSORBS, MATMUL, stage.STACK), "InvalidAbsorbLabel")
        self.events.append(("absorb", label, payload))
        self.state = raw_hash(pcs.frame(self.state, 0, label, payload)).digest()
        self.usage["hash_evaluations"] += 1
        self.usage["state_updates"] += 1

    def challenge(self, label=None):
        label = pcs.CHALLENGE if label is None else label
        pcs.require(label in pcs.CHALLENGES, "InvalidChallengeLabel")
        if not self.in_column:
            self.events.append(("challenge", label))
        old = self.state
        raw = raw_hash(pcs.frame(old, 1, label, bytes([self.degree]))).digest(length=256)
        self.usage["xof_requests"] += 1
        self.usage["xof_bytes"] += 256
        try:
            value, consumed = pcs.sample(raw, self.degree)
        except ValueError as error:
            assert str(error) == "SamplingExhausted"
            self.usage["candidate_words"] += 64
            raise
        self.usage["candidate_words"] += consumed
        payload = bytes([self.degree]) + struct.pack("<I", consumed) + value
        self.state = raw_hash(pcs.frame(old, 2, label, payload)).digest()
        self.usage["hash_evaluations"] += 1
        self.usage["state_updates"] += 1
        if label == pcs.CHALLENGE:
            self.a1_draws.append(struct.unpack("<" + "I" * self.degree, value))
        return value, consumed

    def field(self, label):
        if self.in_column:
            self.usage["column_attempts"] += 1
        return base_transcript.field(self, label)

    def column(self, label, size):
        # Log a whole sampler, not its realized attempts: an omitted-history
        # replay must itself perform rejection sampling under its altered state.
        self.events.append(("column", label, size))
        self.in_column = True
        try:
            return base_transcript.column(self, label, size)
        finally:
            self.in_column = False


@contextmanager
def observed_references():
    global _created
    old, previous = pcs.Transcript, _created
    pcs.Transcript, _created = Transcript, []
    try:
        yield
    finally:
        pcs.Transcript, _created = old, previous


@contextmanager
def local_hashes(counter):
    def counted(*args, **kwargs):
        counter["hash_evaluations"] += 1
        return raw_hash(*args, **kwargs)
    old = pcs.blake3, pcs.merkle.blake3
    pcs.blake3 = pcs.merkle.blake3 = counted
    try:
        yield
    finally:
        pcs.blake3, pcs.merkle.blake3 = old


def make_case(degree, dims, seed, zero=None, rates=(1, 2), control_side=None):
    """Independent logical X*W claim, followed by the explicit physical layout."""
    h, a, b, c = dims
    layers, n, inner, m = (1 << v for v in dims)
    rng = random.Random(seed)
    point = [[tuple(rng.randrange(sc.P) for _ in range(degree)) for _ in range(bits)]
             for bits in (h, a, c)]
    x = [[[rng.randrange(sc.P) for _ in range(inner)] for _ in range(n)] for _ in range(layers)]
    w = [[[rng.randrange(sc.P) for _ in range(m)] for _ in range(inner)] for _ in range(layers)]
    if zero in ("X", "both"):
        x = [[[0] * inner for _ in range(n)] for _ in range(layers)]
    if zero in ("W", "both"):
        w = [[[0] * m for _ in range(inner)] for _ in range(layers)]
    if control_side is not None:
        assert h == b == 0 and a > 0 and c > 0
        x = [[[i if control_side == 0 else 0] for i in range(n)]]
        w = [[[j if control_side == 1 else 0 for j in range(m)]]]
    value = sc.scalar(0, degree)
    el, ei, ej = (pcs.eq(p, degree) for p in point)
    for l in range(layers):
        for i in range(n):
            for j in range(m):
                cell = sum(x[l][i][k] * w[l][k][j] for k in range(inner)) % sc.P
                value = sc.add(value, sc.mul(sc.scalar(cell, degree), sc.mul(el[l], sc.mul(ei[i], ej[j]))))
    mx = [[x[l][i][k] for l in range(layers) for k in range(inner)] for i in range(n)]
    mw = [[w[l][k][j] for l in range(layers) for k in range(inner)] for j in range(m)]
    base = 1000 + seed * 8
    return dict(degree=degree, dims=list(dims), seed=seed, zero=zero, rates=list(rates),
                point=point, value=value, ids=[base+j for j in range(1, 6)], matrices=[mx, mw],
                public_hex=(b"stele/native-matmul-corpus/v1/"+struct.pack("<Q", seed)).hex())


def seeded_cases():
    """Exactly 8 strata * 125 distinct seeds in EACH field; no execution here."""
    for degree in (4, 8):
        for stratum, dims in enumerate(STRATA):
            for repetition in range(125):
                seed = 0x4D41544D + degree * 10000 + stratum * 125 + repetition
                # Different counters avoid correlating a zero mode with one rate.
                zero = (None, "X", "W", "both")[repetition % 4]
                rates = RATES[(repetition // 4 + stratum) % 4]
                yield make_case(degree, dims, seed, zero, rates)


def register(case):
    h, a, b, c = case["dims"]
    handles, witnesses, originals, setup = [], [], [], []
    for matrix, ell, identity, rate in zip(case["matrices"], (a, c), case["ids"][:2], case["rates"]):
        preparation = hashes()
        with local_hashes(preparation):
            source, witness = pcs.commit(matrix, ell, h+b, rate, case["degree"], identity)
        before = len(_created)
        proof = pcs.certify(source, witness)
        assert len(_created) == before+1
        production = _created[-1].usage.copy()
        local = hashes()
        with local_hashes(local):
            handle = pcs.verify_certificate(source, proof)
        assert len(_created) == before+2
        imports = dict(transcript=_created[-1].usage.copy(), non_transcript=local)
        handles.append(handle); witnesses.append(witness)
        originals.append(dict(id=identity, ell=ell, m=h+b, blowup=rate, root_hex=source.root.hex(),
                              source_hex=source.bytes().hex(), certificate_hex=proof.hex()))
        setup.append(dict(preparation=preparation, production=production, verification=imports))
    return handles, witnesses, originals, setup


def context(case, certs):
    h, a, b, c = case["dims"]
    rl, ri, rj = case["point"]
    x, w, output, coefficient, identity = case["ids"]
    pcs.require(len(set((x, w, output, coefficient))) == 4 and h+a+c <= 63, "InvalidMatmul")
    pcs.require([len(p) for p in case["point"]] == [h, a, c], "InvalidMatmul")
    pcs.require(len(certs) == 2, "SourceRoster")
    for cert, oid, ell in zip(certs, (x, w), (a, c)):
        s = cert.source
        pcs.require((s.identity, s.degree, s.ell, s.m) == (oid, case["degree"], ell, h+b), "SourceRoster")
    s = dict(field=case["degree"], id=identity, layout=[(h, 1 << h), (b, 1 << b)], order=0,
             output=dict(id=output, layout=[(h, 1 << h), (a, 1 << a), (c, 1 << c)],
                         point=rl+ri+rj, value=case["value"]),
             coefficient_id=coefficient, inputs=[x, w],
             terms=[(sc.scalar(1, case["degree"]), [0, 1])],
             coefficient=dict(kind=0, selectors=[rl, None], axes=[], source_id=None, values=[], width=None))
    stage.encode(s); sc.validate(stage.instance(s), case["degree"])
    assert sc.degree(stage.instance(s)) == 3
    raw = (struct.pack("<BBQQQBBBB", 1, case["degree"], identity, output, coefficient, h, a, b, c)
           + pcs.field_bytes(rl+ri+rj+[case["value"]])
           + b"".join(cert.source.bytes()+cert.identity for cert in certs))
    assert len(raw) == 304 + 4*case["degree"]*(h+a+c+1)
    return s, raw


def opening_size(cert):
    s, tree = cert.source, cert.source.tree()
    return 1+4*s.degree*(1 << s.m)+pcs.counts(s.m, s.blowup)[1]*(tree.width+32*tree.height())


def parse(case, certs, wire):
    rounds, width = case["dims"][0]+case["dims"][2], 4*case["degree"]
    sizes = [opening_size(c) for c in certs]
    end = 1+width*(4*rounds+3)
    pcs.require(len(wire) == end+sum(sizes) and wire[:1] == b"\1", "ProofShape")
    values = pcs.fields(wire[1:end], case["degree"])
    proof = dict(rounds=[values[4*r:4*r+4] for r in range(rounds)], final=values[-3:])
    openings = [wire[end:end+sizes[0]], wire[end+sizes[0]:]]
    for cert, opening in zip(certs, openings):
        pcs.parse(cert.source, opening, pcs.counts(cert.source.m, cert.source.blowup)[1])
    return proof, openings


def finish(case, certs, witnesses, rows, t, proof, point):
    """Untrusted reference/attack serializer, NEVER a native retained-row API."""
    b, openings = pcs.eq(point, case["degree"]), []
    for cert, witness, outer, value, row in zip(certs, witnesses, case["point"][1:], proof["final"][:2], rows):
        s = cert.source
        pcs.opening_instance(t, s.identity, cert, pcs.eq(outer, s.degree), b, value)
        t.absorb(pcs.OPEN_ROW, pcs.field_bytes(row))
        block = pcs.responses(t, s, witness, pcs.OPEN_COLUMN, pcs.counts(s.m, s.blowup)[1])
        t.absorb(pcs.OPEN_COLUMNS, block)
        openings.append(b"\1"+pcs.field_bytes(row)+block)
    return b"\1"+pcs.field_bytes(sum(proof["rounds"], [])+proof["final"])+b"".join(openings)


def produce(case, certs, witnesses, rows, opening_rows=None):
    s, frame = context(case, certs)
    t = Transcript(bytes.fromhex(case["public_hex"]), case["degree"])
    t.absorb(MATMUL, frame)
    proof = stage.prove(t, s, rows)
    point = list(t.a1_draws)  # Actual producer draws; no verification replay.
    wire = finish(case, certs, witnesses, rows if opening_rows is None else opening_rows, t, proof, point)
    return wire, t, proof


def opening_record(handle):
    s = handle.source
    length = 1 << (s.m+s.blowup)
    distance = length if s.m == 0 else length-(1 << s.m)
    qc, qo = pcs.counts(s.m, s.blowup)
    return dict(id=s.identity, queries=qo, kind="Opening", certificate=dict(id=handle.identity.hex(),
        source=s.bytes().hex(), ell=s.ell, degree=s.degree, kind="Certificate", length=length,
        distance=distance, radius=(distance-1)//3, certificate_queries=qc, opening_queries=qo))


def verify_wire(case, certs, wire):
    """No witness matrices, rows, native receipts or callback enter the consumers."""
    assert "matrices" not in case
    t = Transcript(bytes.fromhex(case["public_hex"]), case["degree"])
    local, phase = hashes(), "preflight"
    out = dict(decision=None, record=None, restored_points=None, consumed_claims=[])
    try:
        s, frame = context(case, certs)
        proof, openings = parse(case, certs, wire)
        t.absorb(MATMUL, frame)
        phase = "A4"
        reduced = stage.verify_reduction(t, s, proof)
        b = pcs.eq(reduced["point"], case["degree"])
        records, points = [], []
        with local_hashes(local):
            for j, (cert, outer, (oid, value), opening) in enumerate(zip(
                    certs, case["point"][1:], reduced["claims"], openings)):
                phase = ("X", "W")[j]
                assert oid == cert.source.identity
                pcs.verify_opening(t, oid, cert, pcs.eq(outer, case["degree"]), b, value, opening)
                points.append(outer+reduced["point"])
                records.append(opening_record(cert))
                out["consumed_claims"].append([oid, sc.encode(value).hex()])
        out.update(decision="accept", record=dict(sc=reduced["sc"], openings=records),
                   restored_points=points)
        phase = "complete"
    except ValueError as error:
        out["decision"] = str(error)  # Exact engine cause; no catch-all remapping.
    out.update(phase=phase, usage=dict(transcript=t.usage.copy(), non_transcript=local), state=t.state.hex())
    return out, t


def following(t):
    i = dict(id=901, m=1, ids=[902], terms=[(sc.scalar(1, t.degree), [0])], sum=sc.scalar(7, t.degree))
    tables = [[sc.scalar(2, t.degree), sc.scalar(5, t.degree)]]
    proof, _ = sc.prove(t, i, tables)
    return i, tables, proof


def proof_hex(proof):
    return pcs.field_bytes(sum(proof["rounds"], [])+proof["final"]).hex()


def public_case(case):
    return {k: deepcopy(case[k]) for k in ("degree", "dims", "ids", "point", "value", "public_hex")}


def request(case, originals, wire):
    # Explicit verifier input: no original matrices or caller A/B rows.
    return public_case(case) | dict(originals=deepcopy(originals), proof_hex=wire.hex())


def reference(case):
    with observed_references():
        certs, witnesses, originals, setup = register(case)
        rows = [pcs.row(matrix, pcs.eq(p, case["degree"]), case["degree"])
                for matrix, p in zip(case["matrices"], case["point"][1:])]
        wire, prover, _ = produce(case, certs, witnesses, rows)
        expected, verifier = verify_wire(public_case(case), certs, wire)
        assert expected["decision"] == "accept" and prover.state == verifier.state
        assert prover.usage == verifier.usage
        repeat, _, _ = produce(case, certs, witnesses, rows)
        assert repeat == wire
        i, tables, next_proof = following(prover)
        next_record = sc.verify_public(verifier, i, next_proof, tables)
        assert prover.state == verifier.state and prover.usage == verifier.usage
        inputs = request(case, originals, wire)
        inputs["following_hex"] = proof_hex(next_proof)
        expected.update(imports=[v["verification"] for v in setup],
            statement_hex=context(case, certs)[1].hex(),
            continuation=dict(decision="accept", sc=next_record["sc"],
                point=[sc.encode(v).hex() for v in next_record["point"]],
                state=verifier.state.hex(), usage=verifier.usage.copy()))
        expected["continuation"]["probe"] = sc.encode(verifier.field(pcs.CHALLENGE)).hex()
        return dict(seed=case["seed"], inputs=inputs, expected=expected, setup=setup)


def row_control(degree, side, control, stacked=False):
    """Complete genuine registration, honest baseline, then ONE declared deviation."""
    assert side in (0, 1) and control in (306, 307, 611)
    assert not stacked or control == 307
    case = make_case(degree, (1, 1, 1, 2) if stacked else (0, 1, 0, 2),
                     30000+degree*100+side, zero=("W", "X")[side],
                     control_side=None if stacked else side)
    with observed_references():
        certs, witnesses, originals, setup = register(case)
        rows = [pcs.row(matrix, pcs.eq(p, degree), degree)
                for matrix, p in zip(case["matrices"], case["point"][1:])]
        honest, producer, original = produce(case, certs, witnesses, rows)
        accepted, _ = verify_wire(public_case(case), certs, honest)
        assert accepted["decision"] == "accept"
        if stacked:
            point = list(producer.a1_draws)
            assert len(point) == 2 and all(any(v[1:]) for v in point)
            wrong = [point[1], point[0]]
            flat = [sc.scalar(x, degree) for row in case["matrices"][side] for x in row]
            changed = deepcopy(original)
            changed["final"][side] = stage.evaluation(flat, case["point"][side+1]+wrong, degree)
            assert changed["final"][side] != original["final"][side]
            t = Transcript(bytes.fromhex(case["public_hex"]), degree)
            s, frame = context(case, certs); t.absorb(MATMUL, frame)
            reduced = stage.verify_reduction(t, s, changed)
            assert reduced["point"] == point
            wire = finish(case, certs, witnesses, rows, t, changed, point)
        else:
            false = deepcopy(rows)
            if control == 306:
                outer = list(case["point"][side+1])
                outer[0] = sc.add(outer[0], sc.scalar(1, degree))
                false[side] = pcs.row(case["matrices"][side], pcs.eq(outer, degree), degree)
            else:
                false[side][0] = sc.add(false[side][0], sc.scalar(1, degree))
            assert len(false[side]) == 1 and false[side] != rows[side]
            wire, _, changed = produce(case, certs, witnesses, false, rows if control == 307 else false)
            if control != 307:
                true_word = pcs.extension_encode(rows[side], certs[side].source.blowup)
                false_word = pcs.extension_encode(false[side], certs[side].source.blowup)
                assert all(x != y for x, y in zip(true_word, false_word))
        s, frame = context(case, certs)
        prefix = Transcript(bytes.fromhex(case["public_hex"]), degree); prefix.absorb(MATMUL, frame)
        a4 = stage.verify_reduction(prefix, s, changed)  # Real A1/A7 acceptance before A9 failure.
        assert changed["rounds"] == original["rounds"]
        assert all(changed["final"][i] == original["final"][i] for i in range(3) if i != side)
        expected, _ = verify_wire(public_case(case), certs, wire)
        assert expected["decision"] == ("ValueMismatch" if control == 307 else "ColumnMismatch")
        assert expected["phase"] == ("X", "W")[side]
        assert len(expected["consumed_claims"]) == side
        return dict(control=control, stacked=stacked, affected=("X", "W")[side],
                    honest=request(case, originals, honest), honest_expected=accepted, inputs=request(case, originals, wire),
                    expected=expected, a4_prefix=a4, rounds_unchanged=True,
                    imports=[v["verification"] for v in setup])


def nc0306(degree, side): return row_control(degree, side, 306)
def nc0307(degree, side): return row_control(degree, side, 307)
def nc0307_stacked(degree, side): return row_control(degree, side, 307, stacked=True)
def nc0611(degree, side): return row_control(degree, side, 611)


def nc0802(degree, omitted):
    """Keep the accepted closed artifact; change one following-A1 final only."""
    omissions = {"MatmulStatement": (MATMUL, 1), "XOpeningColumns": (pcs.OPEN_COLUMNS, 1),
                 "WOpeningColumns": (pcs.OPEN_COLUMNS, 2)}
    target, occurrence = omissions[omitted]
    case = make_case(degree, (1, 1, 1, 2), 80020+degree)
    with observed_references():
        certs, witnesses, originals, setup = register(case)
        rows = [pcs.row(matrix, pcs.eq(p, degree), degree)
                for matrix, p in zip(case["matrices"], case["point"][1:])]
        wire, prover, _ = produce(case, certs, witnesses, rows)
        expected, verifier = verify_wire(public_case(case), certs, wire)
        assert expected["decision"] == "accept" and prover.state == verifier.state
        events = list(prover.events)
        i, tables, honest = following(prover)
        next_record = sc.verify_public(verifier, i, honest, tables)
        assert prover.state == verifier.state
        honest_continuation = dict(decision="accept", sc=next_record["sc"],
            point=[sc.encode(v).hex() for v in next_record["point"]], usage=verifier.usage.copy())
        honest_continuation["probe"] = sc.encode(verifier.field(pcs.CHALLENGE)).hex()
        stale = Transcript(bytes.fromhex(case["public_hex"]), degree)
        seen = skipped = 0
        for event in events:
            if event[0] == "absorb":
                if event[1] == target:
                    seen += 1
                    if seen == occurrence:
                        skipped += 1
                        continue
                stale.absorb(event[1], event[2])
            elif event[0] == "column":
                stale.column(event[1], event[2])
            else:
                assert event[0] == "challenge"
                stale.challenge(event[1])
        assert skipped == 1
        _, _, stale_next = following(stale)
        assert stale_next["rounds"] == honest["rounds"]
        bad = deepcopy(honest); bad["final"][0] = stale_next["final"][0]
        assert bad["final"][0] != honest["final"][0]
        closed, verifier = verify_wire(public_case(case), certs, wire)
        assert closed["decision"] == "accept"
        try:
            sc.verify_public(verifier, i, bad, tables)
        except ValueError as error:
            assert str(error) == "FinalEvaluationMismatch"
        else:
            raise AssertionError("omitted-history following final accepted")
        inputs = request(case, originals, wire)
        inputs["following_hex"] = proof_hex(bad)
        return dict(control=802, omitted=omitted, inputs=inputs,
            honest=inputs | dict(following_hex=proof_hex(honest)),
            honest_expected=closed | dict(continuation=honest_continuation),
            honest_following_hex=proof_hex(honest), closed=closed,
            expected_continuation=dict(decision="FinalEvaluationMismatch", state=verifier.state.hex(),
                                       usage=verifier.usage.copy()),
            imports=[v["verification"] for v in setup])


def nc0802_matmul_statement(degree): return nc0802(degree, "MatmulStatement")
def nc0802_x_columns(degree): return nc0802(degree, "XOpeningColumns")
def nc0802_w_columns(degree): return nc0802(degree, "WOpeningColumns")


def malformed_cases(degree):
    """Actual malformed-wire decisions; no synthetic capacity or field failures."""
    case = make_case(degree, (1, 1, 1, 2), 90000+degree)
    with observed_references():
        certs, witnesses, originals, setup = register(case)
        rows = [pcs.row(matrix, pcs.eq(p, degree), degree)
                for matrix, p in zip(case["matrices"], case["point"][1:])]
        wire, _, _ = produce(case, certs, witnesses, rows)
        accepted, _ = verify_wire(public_case(case), certs, wire)
        assert accepted["decision"] == "accept"
        end = 1+4*degree*(4*(case["dims"][0]+case["dims"][2])+3)
        w_start = end+opening_size(certs[0])
        x_response = end+1+4*degree*(1 << certs[0].source.m)
        def replace(offset, payload):
            return wire[:offset]+payload+wire[offset+len(payload):]
        variants = (("short", wire[:-1], "ProofShape"),
                    ("trailing", wire+b"\0", "ProofShape"),
                    ("version", replace(0, b"\2"), "ProofShape"),
                    ("a1-noncanonical", replace(1, struct.pack("<I", sc.P)), "NoncanonicalField"),
                    ("late-W-row-noncanonical", replace(w_start+1, struct.pack("<I", sc.P)), "NoncanonicalField"),
                    ("X-unauthenticated-noncanonical-column", replace(x_response, struct.pack("<I", sc.P)), "RootMismatch"))
        out = []
        for name, bad, reason in variants:
            expected, _ = verify_wire(public_case(case), certs, bad)
            assert expected["decision"] == reason
            if reason in ("ProofShape", "NoncanonicalField"):
                assert expected["usage"]["transcript"] == hashes() | dict(hash_evaluations=2, state_updates=1)
                assert expected["usage"]["non_transcript"] == hashes()
            out.append(dict(name=name, honest=request(case, originals, wire), honest_expected=accepted,
                            inputs=request(case, originals, bad), expected=expected,
                            imports=[v["verification"] for v in setup]))
        return out


ROOT = Path(__file__).resolve().parents[2]
EXPECTED = "808a85fc4d0eb81ad193aa2361ec55e0d4c14845d8b15d1b1694884c13603456"


def projection(expected, imports):
    """Exact native-observable fields; private reference state stays diagnostic."""
    decision, phase = expected["decision"], expected["phase"]
    out = dict(phase="outer", decision=decision, imports=imports,
               usage=expected["usage"], record=expected["record"],
               restored_points=expected["restored_points"],
               consumed_claims=expected["consumed_claims"], continuation=None)
    if decision == "accept":
        if "continuation" in expected:
            out["continuation"] = {k: v for k, v in expected["continuation"].items() if k != "state"}
        return out
    # Only explicitly exercised engine causes are mapped. An unknown phase or
    # rejection fails the checker rather than normalizing it into an expected error.
    causes = {
        ("preflight", "ProofShape"): ("ProofShape", "matmul"),
        ("preflight", "NoncanonicalField"): ("NoncanonicalField", "matmul"),
        **{(side, cause): (f"Pcs({cause})", "pcs")
           for side in ("X", "W") for cause in ("ValueMismatch", "ColumnMismatch")},
        **{(side, "RootMismatch"): ("Pcs(Merkle(RootMismatch))", "pcs") for side in ("X", "W")},
    }
    out["decision"], out["component"] = causes[phase, decision]
    out.update(record=None, restored_points=None, consumed_claims=None,
               same_transcript_counters_as_entry=expected["usage"]["transcript"] ==
               hashes() | dict(hash_evaluations=2, state_updates=1))
    return out


def campaign():
    for case in seeded_cases():
        r = reference(case)
        yield "seeded", r["inputs"], projection(r["expected"], r["expected"]["imports"])
    for degree in (4, 8):
        controls = [fn(degree, side) for side in (0, 1)
                    for fn in (nc0306, nc0307, nc0307_stacked, nc0611)]
        for r in controls:
            yield "control-baseline", r["honest"], projection(r["honest_expected"], r["imports"])
            yield "row-control", r["inputs"], projection(r["expected"], r["imports"])
        for fn in (nc0802_matmul_statement, nc0802_x_columns, nc0802_w_columns):
            r = fn(degree)
            yield "control-baseline", r["honest"], projection(r["honest_expected"], r["imports"])
            expected = r["closed"] | dict(continuation=r["expected_continuation"])
            yield "continuation-control", r["inputs"], projection(expected, r["imports"])
        for r in malformed_cases(degree):
            yield "control-baseline", r["honest"], projection(r["honest_expected"], r["imports"])
            yield "malformed", r["inputs"], projection(r["expected"], r["imports"])


def freeze(path):
    sources = configure(ROOT)
    digest, counts = hashlib.sha256(), {}
    with path.open("w") as output:
        for kind, inputs, expected in campaign():
            raw = json.dumps(dict(kind=kind, inputs=inputs, expected=expected),
                             sort_keys=True, separators=(",", ":")) + "\n"
            output.write(raw)
            digest.update(raw.encode())
            key = f"{kind}/{inputs['degree']}"
            counts[key] = counts.get(key, 0) + 1
    assert counts == {f"{kind}/{degree}": count for degree in (4, 8)
                     for kind, count in (("seeded", 1000), ("control-baseline", 17),
                                         ("row-control", 8), ("continuation-control", 3), ("malformed", 6))}
    return dict(sha256=digest.hexdigest(), counts=counts, sources=sources)


def compare(path, directory):
    requests, responses = directory / "requests.jsonl", directory / "native.jsonl"
    with path.open() as fixtures, requests.open("w") as output:
        for line in fixtures:
            output.write(json.dumps(json.loads(line)["inputs"], separators=(",", ":")) + "\n")
    with requests.open() as inputs, responses.open("w") as output:
        subprocess.run(["cargo", "run", "--quiet", "--profile", "test", "-p", "stele-negative-controls", "--example",
                        "matmul_corpus", "--locked", "--offline"], cwd=ROOT,
                       stdin=inputs, stdout=output, check=True)
    with path.open() as fixtures, responses.open() as actual:
        for index, (line, response) in enumerate(zip_longest(fixtures, actual)):
            assert line is not None and response is not None, (index, "native response count")
            expected, observed = json.loads(line), json.loads(response)
            if expected["expected"] != observed:
                keys = sorted(k for k in expected["expected"].keys() | observed.keys()
                              if expected["expected"].get(k) != observed.get(k))
                raise AssertionError((index, expected["kind"], keys,
                                      {k: observed.get(k) for k in keys}))
        assert index + 1 == 2068


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--reference-only":
        # Root freezes independent evidence before the first native comparison.
        path = Path(sys.argv[2])
        receipt = freeze(path)
        path.with_suffix(".receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, sort_keys=True))
    else:
        assert len(sys.argv) == 1, "unsupported corpus arguments"
        with tempfile.TemporaryDirectory(prefix="stele-matmul-corpus-") as temporary:
            directory = Path(temporary)
            path = directory / "reference.jsonl"
            receipt = freeze(path)
            assert receipt["sha256"] == EXPECTED, receipt
            compare(path, directory)
        print("matmul closed corpus: 2000 seeded cases (1000 per field), 34 honest controls and 34 rejects; "
              "complete wires, actual records, imports, usage and continuation; SHA256 " + EXPECTED)
