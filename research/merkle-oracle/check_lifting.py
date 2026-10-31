# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q27 frozen-oracle controls; no production verifier or NC credit."""
from pathlib import Path
from dataclasses import replace
from random import Random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'merkle'))
from check_merkle import Tree, build, path
from lifting import RecordedHash, complete, field_column, frames, verify


def rejects(reason, function):
    try:
        function()
    except ValueError as error:
        assert str(error) == reason, (reason, str(error))
    else:
        raise AssertionError('accepted ' + reason)


def accepts_complete_tree():
    spec = Tree(0, 19, 2, 8)
    columns = [(2, 3), (5, 7)]
    payloads = [b''.join(x.to_bytes(4, 'little') for x in c) for c in columns]
    h = RecordedHash()
    leaves = [h(frames(spec, 0, i, p)) for i, p in enumerate(payloads)]
    root = h(frames(spec, 1, 0, b''.join(leaves)))
    frozen = dict(h.log)
    matrix, frontier = complete(spec, root, frozen)
    assert matrix == tuple(columns) and not frontier
    for i, p in enumerate(payloads):
        assert verify(spec, root, i, p, [leaves[1-i]], h) == columns[i]
    assert dict(h.log) == frozen


def rejects_missing_and_malformed_columns():
    spec = Tree(0, 19, 2, 4)
    h = RecordedHash()
    payload = (7).to_bytes(4, 'little')
    left = h(frames(spec, 0, 0, payload))
    absent = bytes([91])*32
    assert absent not in h.log.values()
    root = h(frames(spec, 1, 0, left+absent))
    frozen = dict(h.log)
    columns, frontier = complete(spec, root, frozen)
    assert columns == ((7,), (0,)) and frontier == {absent}
    assert verify(spec, root, 0, payload, [absent], h) == (7,)
    rejects('RootMismatch', lambda: verify(spec, root, 1, payload, [left], h))
    assert complete(spec, root, frozen) == (columns, frontier)
    rejects('InvalidPath', lambda: verify(spec, root, 0, payload, [], h))
    rejects('InvalidLeaf', lambda: verify(spec, root, 0, payload[:-1], [absent], h))
    rejects('InvalidIndex', lambda: verify(spec, root, 2, payload, [left], h))
    singleton = Tree(0, 20, 1, 4)
    noncanonical = (2**31-1).to_bytes(4, 'little')
    bad_root = h(frames(singleton, 0, 0, noncanonical))
    assert complete(singleton, bad_root, dict(h.log)) == (((0,),), set())
    rejects('NoncanonicalField', lambda: verify(singleton, bad_root, 0, noncanonical, [], h))
    rejects('NoncanonicalField', lambda: field_column((2**32-1).to_bytes(4, 'little')))


def matches_late_preimage_counterexample():
    # This symbolic oracle isolates a bad event, not a BLAKE3 preimage attack.
    target = bytes([37])*32
    h = RecordedHash(lambda _: target)
    spec = Tree(0, 1, 1, 4)
    frozen = dict(h.log)
    columns, frontier = complete(spec, target, frozen)
    assert columns == ((0,),) and frontier == {target}
    assert verify(spec, target, 0, (9).to_bytes(4, 'little'), [], h) == (9,)
    assert len(set(h.log.values())) == len(h.log) == 1  # No collision occurred.
    assert set(h.log.values()) & frontier == {target}
    # Re-freezing after the response would erase the original bad event.
    assert complete(spec, target, frozen)[0] == ((0,),)
    assert complete(spec, target, dict(h.log))[0] == ((9,),)


def matches_collision_counterexample():
    target = bytes([38])*32
    h = RecordedHash(lambda _: target)
    spec = Tree(0, 1, 1, 4)
    root = h(frames(spec, 0, 0, (1).to_bytes(4, 'little')))
    assert complete(spec, root, dict(h.log))[0] == ((1,),)
    assert verify(spec, root, 0, (2).to_bytes(4, 'little'), [], h) == (2,)
    assert len(h.log) == 2 and len(set(h.log.values())) == 1


def matches_reference_framing_and_padding():
    cases = paths = 0
    for count in (1, 2, 3, 5, 8):
        for rows in (1, 2, 4):
            spec = Tree(0, 31, count, 4*rows)
            columns = [tuple((i+1)*(j+1) for j in range(rows)) for i in range(count)]
            payloads = [b''.join(x.to_bytes(4, 'little') for x in c) for c in columns]
            reference = build(spec, payloads)
            h = RecordedHash()
            level = [h(frames(spec, 0, i, payloads[i] if i < count else b''))
                     for i in range(1 << spec.height())]
            for depth in range(1, spec.height()+1):
                level = [h(frames(spec, depth, i//2, level[i]+level[i+1]))
                         for i in range(0, len(level), 2)]
            assert level[0] == reference[-1][0]
            frozen = dict(h.log)
            assert complete(spec, level[0], frozen) == (tuple(columns), set())
            for i, payload in enumerate(payloads):
                siblings = path(reference, i)
                assert verify(spec, level[0], i, payload, siblings, h) == columns[i]
                assert verify(spec, level[0], i, payload, siblings, h) == columns[i]
                paths += 1
            assert h.log == frozen  # Duplicate queries retain one fixed value.
            wrong = replace(spec, id=32)
            assert complete(wrong, level[0], frozen) == (((0,)*rows,)*count, set())
            rejects('RootMismatch', lambda: verify(wrong, level[0], 0, payloads[0], path(reference, 0), h))
            cases += 1
    assert (cases, paths) == (15, 57)
    spec = Tree(0, 31, 2, 4)
    h = RecordedHash()
    wrong_level = h(frames(spec, 2, 0, bytes(64)))
    assert complete(spec, wrong_level, dict(h.log)) == (((0,), (0,)), set())
    rejects('RootMismatch', lambda: verify(spec, wrong_level, 0, bytes(4), [bytes(32)], h))


def matches_tiny_oracle_late_preimages():
    # Eight-bit lazy-oracle outputs in 32-byte transport: not BLAKE3 evidence.
    for count, expected in ((2, 16), (1, 18)):
        rng = Random(23)
        h = RecordedHash(lambda _: bytes([rng.randrange(256)])+bytes(31))
        spec = Tree(0, 19, count, 4)
        target = bytes([255])+bytes(31)
        if count == 2:
            left = h(frames(spec, 0, 0, (3).to_bytes(4, 'little')))
            root = h(frames(spec, 1, 0, left+target))
        else:
            root = target
        frozen = dict(h.log)
        columns, frontier = complete(spec, root, frozen)
        assert frontier == {target} and columns[count-1] == (0,)
        for value in range(1, 251):
            payload = value.to_bytes(4, 'little')
            digest = h(frames(spec, 0, count-1, payload))
            assert len(h.log) == len(set(h.log.values()))
            if digest == target:
                break
        assert value == expected
        assert verify(spec, root, count-1, payload, [left] if count == 2 else [], h) == (value,)
        assert len(h.log) == len(set(h.log.values()))
        assert complete(spec, root, frozen)[0][count-1] == (0,)


if __name__ == '__main__':
    accepts_complete_tree()
    rejects_missing_and_malformed_columns()
    matches_late_preimage_counterexample()
    matches_collision_counterexample()
    matches_reference_framing_and_padding()
    matches_tiny_oracle_late_preimages()
    print('15 reference trees / 57 paths; partial/malformed trees and both bad events passed')
