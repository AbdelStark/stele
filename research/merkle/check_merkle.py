# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0012 A3 candidate; research only, no protocol control credit."""
from dataclasses import dataclass, replace
import json
from pathlib import Path
import struct
import sys
from blake3 import blake3

DOMAIN = b"stele/v0.1/merkle"


def require(condition, error):
    if not condition:
        raise ValueError(error)


@dataclass(frozen=True)
class Tree:
    kind: int
    id: int
    count: int
    width: int

    def header(self):
        require(self.kind in (0, 2), "InvalidTree")
        require(0 <= self.id < 2**64 and 1 <= self.count <= 2**63, "InvalidTree")
        require(1 <= self.width < 2**64, "InvalidTree")
        require(self.kind != 2 or self.width == 32, "InvalidTree")
        return DOMAIN + struct.pack("<BQQQ", self.kind, self.id, self.count, self.width)

    def height(self):
        self.header()
        return (self.count - 1).bit_length()

    def leaf(self, index, payload):
        header = self.header()
        require(0 <= index < 1 << self.height(), "InvalidIndex")
        present = index < self.count
        require(len(payload) == (self.width if present else 0), "InvalidLeaf")
        return blake3(bytes([self.kind]) + header + struct.pack("<QB", index, present) + payload).digest()

    def node(self, level, index, left, right):
        return blake3(b"\x01" + self.header() + struct.pack("<IQ", level, index) + left + right).digest()


def build(tree, leaves):
    require(len(leaves) == tree.count, "InvalidLeaf")
    size = 1 << tree.height()
    levels = [[tree.leaf(i, leaves[i] if i < tree.count else b"") for i in range(size)]]
    for level in range(1, tree.height() + 1):
        old = levels[-1]
        levels.append([tree.node(level, i // 2, old[i], old[i + 1]) for i in range(0, len(old), 2)])
    return levels


def path(levels, index):
    return [level[(index >> depth) ^ 1] for depth, level in enumerate(levels[:-1])]


def verify(tree, root, index, payload, siblings):
    height = tree.height()
    require(0 <= index < tree.count, "InvalidIndex")
    require(len(payload) == tree.width, "InvalidLeaf")
    require(len(root) == 32 and len(siblings) == height and all(len(s) == 32 for s in siblings), "InvalidPath")
    value = tree.leaf(index, payload)
    for depth, sibling in enumerate(siblings):
        current = index >> depth
        left, right = (sibling, value) if current & 1 else (value, sibling)
        value = tree.node(depth + 1, current >> 1, left, right)
    require(value == root, "RootMismatch")


def batch(tree, root, indices, openings):
    tree.header()
    require(0 < len(indices) == len(openings) <= tree.count, "InvalidBatch")
    require(all(a < b for a, b in zip(indices, indices[1:])), "InvalidBatch")
    for index, (payload, siblings) in zip(indices, openings):
        verify(tree, root, index, payload, siblings)


def rejects(error, function):
    try:
        function()
    except ValueError as actual:
        assert str(actual) == error, (error, str(actual))
    else:
        raise AssertionError(f"accepted instead of {error}")


def flip(value):
    return bytes([value[0] ^ 1]) + value[1:]


def exercise():
    vectors = []
    honest = 0
    mutations = 0
    for kind in (0, 2):
        for count in (1, 2, 3, 5, 8):
            tree = Tree(kind, 17, count, 12 if kind == 0 else 32)
            leaves = [bytes((i * 13 + j) % 256 for j in range(tree.width)) for i in range(count)]
            levels = build(tree, leaves)
            root = levels[-1][0]
            openings = [(leaf, path(levels, i)) for i, leaf in enumerate(leaves)]
            batch(tree, root, list(range(count)), openings)
            for index, (leaf, siblings) in enumerate(openings):
                verify(tree, root, index, leaf, siblings)
                honest += 1
                rejects("RootMismatch", lambda: verify(tree, root, index, flip(leaf), siblings))
                rejects("RootMismatch", lambda: verify(tree, flip(root), index, leaf, siblings))
                rejects("RootMismatch", lambda: verify(replace(tree, id=18), root, index, leaf, siblings))
                rejects("InvalidLeaf", lambda: verify(tree, root, index, leaf[:-1], siblings))
                rejects("InvalidPath", lambda: verify(tree, root, index, leaf, siblings + [bytes(32)]))
                rejects("InvalidPath", lambda: verify(tree, root[:-1], index, leaf, siblings))
                mutations += 6
                for at in range(len(siblings)):
                    changed = siblings[:]
                    changed[at] = flip(changed[at])
                    rejects("RootMismatch", lambda: verify(tree, root, index, leaf, changed))
                    mutations += 1
                if count > 1:
                    rejects("InvalidPath", lambda: verify(tree, root, index, leaf, [siblings[0][:-1]] + siblings[1:]))
                    mutations += 1
                    other = (index + 1) % count
                    rejects("RootMismatch", lambda: verify(tree, root, other, leaf, siblings))
                    rejects("InvalidPath", lambda: verify(tree, root, index, leaf, siblings[:-1]))
                    mutations += 2
            rejects("InvalidIndex", lambda: verify(tree, root, count, leaves[0], openings[0][1]))
            rejects("InvalidBatch", lambda: batch(tree, root, [], []))
            rejects("InvalidBatch", lambda: batch(tree, root, [0, 0], [openings[0]] * 2))
            rejects("InvalidBatch", lambda: batch(tree, root, list(range(count)), openings[:-1]))
            rejects("InvalidLeaf", lambda: build(tree, leaves[:-1]))
            mutations += 5
            if count > 1:
                rejects("InvalidBatch", lambda: batch(tree, root, [1, 0], [openings[1], openings[0]]))
                mutations += 1
            vectors.append({"tree": tree.__dict__, "leaves": [x.hex() for x in leaves],
                            "root": root.hex(), "paths": [[x.hex() for x in p] for _, p in openings]})
    # Equal payload bytes still bind their position, kind, width and count.
    t = Tree(0, 17, 3, 32)
    leaves = [bytes(32)] * 3
    levels = build(t, leaves)
    p = path(levels, 0)
    rejects("RootMismatch", lambda: verify(t, levels[-1][0], 1, leaves[0], p))
    rejects("RootMismatch", lambda: verify(replace(t, kind=2), levels[-1][0], 0, leaves[0], p))
    rejects("RootMismatch", lambda: verify(replace(t, count=4), levels[-1][0], 0, leaves[0], p))
    rejects("InvalidLeaf", lambda: verify(replace(t, width=31), levels[-1][0], 0, leaves[0], p))
    assert build(t, leaves)[-1][0] != build(replace(t, count=4), leaves + [bytes(32)])[-1][0]
    for invalid in (replace(t, kind=1), replace(t, count=0), replace(t, count=2**63+1),
                    replace(t, width=0), replace(t, id=2**64), replace(t, kind=2, width=31)):
        rejects("InvalidTree", invalid.header)
    mutations += 10
    return vectors, honest, mutations


if __name__ == "__main__":
    vectors, honest, mutations = exercise()
    fixture = Path(__file__).with_name("vectors.jsonl")
    if sys.argv[1:] == ["--write-vectors"]:
        with fixture.open("x") as output:
            for vector in vectors:
                output.write(json.dumps(vector, separators=(",", ":")) + "\n")
    else:
        require(not sys.argv[1:], "unknown arguments")
        assert [json.loads(line) for line in fixture.read_text().splitlines()] == vectors
    print(f"candidate: {honest} honest paths, {mutations} rejection cases, {len(vectors)} vectors; no protocol coverage")
