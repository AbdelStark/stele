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
import json
from random import Random
import sys

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
    counts = dict(accepted=[0, 0], rejected=0, reason_mismatch=0, steps=0)
    corpus = blake3()
    for i in range(n):
        m, mp, sr, raw, _ = fixture(rng, i % 2)
        tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(rng.randint(1, m.shape.context)))
        data = c.load(m, mp, sr, raw, blake3(raw).digest())
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
        counts['accepted'][i % 2] += 1
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
    print(json.dumps(dict(configurations=n, **counts, blocked_long_cases=long, corpus_blake3=corpus.hexdigest())))


if __name__ == '__main__':
    torch.set_num_threads(1)
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
