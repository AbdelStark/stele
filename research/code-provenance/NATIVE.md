# Native encoder differential coverage (RFC-0010 A4)

Run `uv run --locked --script research/code-provenance/check_native.py` from the
repository. The script invokes the bounded Rust `encoder_corpus` example and
compares complete canonical codeword bytes and ordered query values with the
materialized Python map. It uses neither the native traversal nor Python's
bounded traversal to produce expected words. The independent dense/base evidence
in `check_recursive.py` and `research/circle-code/check_circle.py` remains required.

For each of M31/QM31/OM31 there are 1000 independently seeded inputs: 900 at J=3,
90 at J=4, 10 at J=5. Every ordinary input has independently sampled canonical
limbs. Each size also includes all-zero, 0/1/p-1 boundary and prime-subfield rows.
One full-extension linear combination per size adds two more words, giving 1006
words per field. Queries cover empty lists, both endpoints, the recursive boundary,
a random coordinate and a repeated coordinate, preserving order. J=3 retains the
seed identity but has no sparse graph. This is deterministic map parity, not a
statistical distance estimate or a sampling-failure bound.

The adapter accepts only the three field degrees and bounded research dimensions.
Unknown field degrees, wrong identity widths, malformed rows, invalid columns,
noncanonical field limbs, excessive queries, truncation and trailing bytes reject.
It is an example binary, not a production byte decoder or proof format.

`scripts/gates/digest.sh` now regenerates the nine existing reference digests,
runs native tests (including faults and sealed API doctests), and runs the complete
byte corpus. It requires named test/corpus receipts, so a missing test or an empty
script cannot silently pass. The fixture and output comparisons are exact.
Gate mutation tests alter the digest fixture, remove a reference test/corpus call,
reverse query results, and remove the field seal. These are gate regressions,
not PCS negative controls.

The external field doctests share one complete `Field` implementation. It compiles
as `Field` and fails to implement `CodeField`; removing the private seal makes
the compile-fail test fail. Existing external `Code`, CM31 and KoalaBear checks
also reject. This avoids relying on incomplete trait methods to test sealing.

E4-08 remains in progress. Actual operation/preparation/capacity/stack/process
ledgers through 2^20 inputs on all three fields remain required. No benchmark,
GPU parity, PCS/profile admission, soundness loss or NC credit follows here.
