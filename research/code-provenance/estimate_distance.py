# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A1 / task E4-01: one-sided distance estimates for the v2 expander code.

Any nonzero codeword's weight is an UPPER bound on the minimum distance. This script
searches low-weight messages, including a cancellation attack, and reports the least
weight found next to the certified LOWER bound of the accepted evidence. A search can
only falsify the certificate (found < bound); it never certifies a distance.
Usage: uv run --locked --script research/code-provenance/estimate_distance.py
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from identity import parameters
from recursive import encode_row, sc
from sampler import manifest, materialize

P = sc.P


def weight(word):
    return sum(any(x) for x in word)


def search(j, samples, rng):
    raw = manifest(bytes(range(32)), j)
    info = parameters(raw, 1)
    k, bound = info['message_len'], info['distance']
    setup, _ = materialize(raw)
    encode = lambda message: encode_row(setup, [(x % P,) for x in message])[0]
    unit = []
    found, witness = None, None

    def observe(message, word, how):
        nonlocal found, witness
        w = weight(word)
        assert w > 0 and (any(message)), 'nonzero message encoded to zero: not injective'
        if found is None or w < found:
            found, witness = w, how

    for i in range(k):                                   # every weight-1 direction
        e = [0] * k
        e[i] = 1
        word = encode(e)
        unit.append(word)
        observe(e, word, f'e_{i}')
    for _ in range(samples):                             # random sparse messages
        w = rng.randint(2, 6)
        m = [0] * k
        for i in rng.sample(range(k), w):
            m[i] = rng.randrange(1, P)
        observe(m, encode(m), f'random weight {w}')
    for _ in range(samples):                             # cancel one shared parity symbol
        i, l = rng.sample(range(k), 2)
        shared = [t for t in range(k, 2 * k) if unit[i][t][0] and unit[l][t][0]]
        if not shared:
            continue
        t = rng.choice(shared)
        c = (-unit[i][t][0] * pow(unit[l][t][0], P - 2, P)) % P
        m = [0] * k
        m[i], m[l] = 1, c
        word = [((a[0] + c * b[0]) % P,) for a, b in zip(unit[i], unit[l])]
        assert word == encode(m), 'linearity'
        observe(m, word, f'cancel e_{i} + c e_{l} at {t}')
    return k, bound, found, witness


def main():
    rng = random.Random(0xE401)
    print('| J | k | N | certified lower bound | least weight found (upper bound) | witness |')
    print('|---|---|---|---|---|---|')
    for j, samples in ((3, 200), (4, 200), (5, 30)):
        k, bound, found, witness = search(j, samples, rng)
        print(f'| {j} | {k} | {2 * k} | {bound} | {found} | {witness} |')
        assert found >= bound, f'certificate falsified at J={j}: weight {found} < {bound}'
    print('One-sided: found weights bound the distance from above; no distance is certified here.')


if __name__ == '__main__':
    main()
