# E16-40n boundary correction — implementation review

Fixed point `db08e8924bf6e3184ae208cf4f810c2896d5a7de`; candidate
`85bab27af45be515c6a76981916a027a8c0fa8f5` plus the documentation correction
in this commit. Development research, lane V. No core interface, dependency,
challenge, commitment, verifier or hash-compression change.

## Owning GPU / spec axis

Independent reviewer `boundaries_spec_review`: PASS. Canonicalization matches
RFC-0003 and GPU-parity guardrail 4. Duplicate workers own disjoint entries in both
halves; bit-reversal pairs have one writer; transpose reads initialized shared
cells after its existing barrier. Callers and test launches provide the required
extents. Leaf serialization normalizes only encoded field words; descriptor,
index, presence, key, salt and child-digest bytes retain their full byte semantics.
The zero-variable bit reversal avoids an undefined shift. No code findings.

## Lane B / standards axis

Independent reviewer `boundaries_standards_review`: PASS after one accounting
correction. The original document omitted the new reads/writes at bit-reversal
fixed points. The corrected account includes four bytes each way per fixed point
per row, with `2^ceil(log/2)` fixed points, including one for `log = 0`. Both
reviewers checked this correction; it is logical traffic, not measured HBM traffic.
No remaining hard violations or actionable smell findings. The standards reviewer
independently passed the focused actual-expression host test.

## Validation and limits

Tests preceded the runtime changes. At test commit `195aaac9`, the host execution
of actual CUDA bodies found 5,000 raw-input mismatches: 1,000 each for mask copy,
duplicate, transpose, bit reversal and leaf serialization. Canonical counterparts
passed. The corrected final corpus passes all 1,000 seeds in both representations
for eleven operations, including the unchanged equality-table regression.

The full CPU research all-target suite, CUDA all-target Clippy with warnings
denied, formatting and whitespace checks pass. The retained red/green and complete
logs are under `/Users/abdel/dev/stele-validation/e16-40n-*.log`.

Actual H100 boundary and complete source-material qualification remain pending,
as do the mandatory current-main/intended-merge-tree gates. Host emulation does
not establish CUDA scheduling parity. No integrated GPU-proof, performance,
complete-memory or ADR-127 GO credit is claimed.
