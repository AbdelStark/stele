# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "numpy==1.26.4", "torch==2.5.1"]
# ///
"""E5-05: torch CQIS executor parity against the research reference executor.

Random complete small models of both families (check_model_execution.fixture: int4/int8,
static/dynamic rows, all exp modes, every RoPE family/layout, exact/blocked accumulation)
run through both executors. Accepted cases must agree on every residual cut, logit and
K/V cache byte, and incremental steps must reproduce the single pass; rejected cases
must reject in both. Usage: uv run --locked --script harness/eval/check_cqis_torch.py [N]
"""
from fractions import Fraction
import json
from math import gcd
from random import Random
import sys
from types import SimpleNamespace

from blake3 import blake3
import torch

import cqis_torch as ct
sys.path.insert(0, str(ct.ROOT/'research/cqis-model-contract'))
from check_model_execution import fixture  # noqa: E402

c = ct.ref


def rows(r):
    return tuple(tuple(x) for x in r.tolist())


def as_cache(cache):
    return tuple(tuple(((tuple(k.codes[t].tolist()), int(k.scale[t]), k.fraction),
                        (tuple(v.codes[t].tolist()), int(v.scale[t]), v.fraction))
                       for t in range(k.codes.shape[0])) for k, v in cache)


def reference_cache(cache):
    return tuple(tuple(((k.codes, k.scale, k.fraction), (v.codes, v.scale, v.fraction)) for k, v in layer)
                 for layer in cache.layers)


def main(n):
    rng = Random(0xE505)
    counts = dict(accepted=[0, 0, 0, 0], rejected=0, reason_mismatch=0, steps=0)
    corpus = blake3()
    for i in range(n):
        seed = rng.getrandbits(64)
        m, mp, sr, raw, _ = fixture(Random(seed), i % 2)
        tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(rng.randint(1, m.shape.context)))
        # Llama fixtures also run as their RFC-0004 A14 wide twin (same draws, own Artifact identity).
        for version in (1, 2) if i % 2 else (1,):
            variant, mp, sr, raw, _ = fixture(Random(seed), i % 2, version=version)
            data = c.load(variant, mp, sr, raw, blake3(raw).digest())
            ex = ct.Executor(data)
            try:
                expected = c.full(data, tokens)
            except ValueError as error:
                try:
                    ex.full(tokens)
                except ValueError as mine:
                    counts['rejected'] += 1
                    counts["reason_mismatch"] += str(mine) != str(error)
                    if str(mine) != str(error): print("MISMATCH", i, str(error), str(mine))
                    corpus.update(json.dumps([i, str(error), str(mine)]).encode())
                    continue
                raise AssertionError(('torch accepted a rejected case', i, str(error)))
            cuts, logits, cache = ex.full(tokens)
            assert tuple(rows(r) for r in cuts) == expected.cuts, ('cuts', i)
            assert rows(logits) == expected.logits, ('logits', i)
            assert as_cache(cache) == reference_cache(expected.cache), ('cache', i)
            state, step_logits = None, []
            for t in tokens:
                _, lg, state = ex.step([t], state)
                step_logits.append(tuple(lg[0].tolist()))
            assert tuple(step_logits) == expected.logits and as_cache(state) == as_cache(cache), ('step', i)
            counts['steps'] += len(tokens)
            counts['accepted'][i % 2 + 2*(version == 2)] += 1
            if not any(b.accumulation for b in m.blocks):
                prompts = [tokens[:rng.randint(1, len(tokens))] for _ in range(3)]
                budget = m.shape.context - max(map(len, prompts))
                eos = {m.shape.vocabulary - 1}
                got = ex.generate([list(p) for p in prompts], budget, eos, batch=3)
                for p, (generated, reason) in zip(prompts, got):
                    sequence, expected_reason = p, None
                    try:
                        while len(sequence) - len(p) < budget:
                            logits = c.full(data, sequence).logits[-1]
                            sequence += (logits.index(max(logits)),)
                            if sequence[-1] in eos:
                                break
                    except ValueError as error:
                        expected_reason = str(error)
                    assert list(sequence[len(p):]) == generated and (reason is None) == (expected_reason is None), ('generate', i)
                    counts['generated'] = counts.get('generated', 0) + len(generated)
            corpus.update(json.dumps([i, expected.logits]).encode())
    assert counts['reason_mismatch'] == 0, counts
    # The Python-integer normalizer equals the certified one wherever the latter is defined.
    for _ in range(3000):
        d, F, en, ed = rng.choice((1, 7, 768, 4096, 16384)), rng.randint(0, 30), rng.choice((1, 3, 7, 9, 11, 13, 99)), 100000
        v = rng.randint(0, d << 30)
        try:
            w = c.rms.normalize(c.rms.Parameters(d, F, 6, 6, en, ed), v)
            expected = (w['a'], w['M'])
        except ValueError as error:
            expected = str(error)
        try:
            got = ct.normalize(d, F, en, ed, v)
        except ValueError as error:
            got = str(error)
        assert got == expected, ('normalize', d, F, v)
    # Blocked accumulation needs more than 1024 keys: accepted long single-layer cases.
    long = 0
    while long < 3:
        m, mp, sr, raw, _ = fixture(rng, long % 2, layers=1, context=1100, heads=1, width=2)
        if not m.blocks[0].accumulation:
            continue
        tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(1100))
        data = c.load(m, mp, sr, raw, blake3(raw).digest())
        try:
            expected = c.full(data, tokens)
        except ValueError:
            continue
        cuts, logits, cache = ct.Executor(data).full(tokens)
        assert tuple(rows(r) for r in cuts) == expected.cuts and rows(logits) == expected.logits, 'long'
        long += 1
    counts['wide'] = wide_checks(rng)
    print(json.dumps(dict(configurations=n, **counts, blocked_long_cases=long, corpus_blake3=corpus.hexdigest())))


def oracle_norm(d, F, G, E, en, ed, X, H, a_max):
    """RFC-0021 §2.3 from its definition with exact rationals, for int16 or int24 inputs."""
    q = Fraction(ed*sum(x*x for x in X) + en*d*4**F, ed*d*4**F)
    a = next((a for a in range(-23, a_max + 1) if 16384 <= q/Fraction(4)**a < 65536), None)
    if a is None:
        raise ValueError('Normalization')
    M = int(q/Fraction(4)**a)
    J = next(j for j in range(8192, 16385) if M*(2*j - 1)**2 <= 1 << 44 < M*(2*j + 1)**2)
    e = F + G + 21 + a - E
    out = []
    for x, h in zip(X, H):
        T = x*h*J
        y = T << -e if e < 0 else (1 if T >= 0 else -1)*((abs(T) + (1 << e >> 1)) >> e)
        if not -32768 <= y <= 32767:
            raise ValueError('Range')
        out.append(y)
    return out


def wide_checks(rng):
    """Signed range endpoints at both widths, and the norm against oracle_norm on wide inputs."""
    n = 0
    seed = rng.getrandbits(64)
    for bits in (16, 24):
        model, mp, sr, raw, _ = fixture(Random(seed), 1, version=bits//8 - 1)
        ex = ct.Executor(c.load(model, mp, sr, raw, blake3(raw).digest()))
        assert ex.wide == (1 << bits - 1) - 1
        low, high = -(1 << bits - 1), (1 << bits - 1) - 1
        for v, ok in ((low, True), (high, True), (low - 1, False), (high + 1, False)):
            try:
                assert ex.residual(torch.tensor([v]), 0, torch.tensor([0]), 0, 0).tolist() == [v] and ok, (bits, v)
            except ValueError as error:
                assert not ok and str(error) == 'Range', (bits, v)
            n += 1
        for _ in range(400 if bits == 24 else 100):
            d = rng.choice((1, 2, 3, 8))
            spec = SimpleNamespace(version=bits//8 - 1, d=d, F=rng.choice((0, 1, 7, 10, 30)), G=rng.randint(0, 30), E=rng.randint(0, 14),
                                   en=rng.choice((1, 3, 7)), ed=rng.choice((1, 100000, (1 << 32) - 1)))
            if gcd(spec.en, spec.ed) != 1:
                continue
            X = [rng.choice((low, high, 0, rng.randint(low, high), rng.randint(-99, 99))) for _ in range(d)]
            H = [rng.randint(-32768, 32767) for _ in range(d)]
            ex.vectors['t.gain', -1] = torch.tensor(H)
            try:
                expected = oracle_norm(d, spec.F, spec.G, spec.E, spec.en, spec.ed, X, H, 16 if bits == 24 else 9)
            except ValueError as error:
                expected = str(error)
            try:
                got = ex.norm(spec, torch.tensor([X]), 't')[0].tolist()
            except ValueError as error:
                got = str(error)
            if got == 'Shift':  # outside the derived shift interval; the oracle has no such bound
                continue
            assert got == expected, ('wide norm', bits, spec, X, H, got, expected)
            n += 1
    return n


if __name__ == '__main__':
    torch.set_num_threads(1)
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
