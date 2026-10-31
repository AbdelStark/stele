# Reference field arithmetic (Q26/Q31)

Question: can the Python reference evaluate RFC-0003 §2/A1's fixed tower
products with less work while preserving every complete proof and consumer?
The candidate follows the existing native field implementation: scalar
products, fixed nonresidue maps and three lower-field Karatsuba products.
This is an arithmetic implementation change, with no protocol amendment.

The cost at stake is reference c_sc/T_misc work during complete public
research proofs. No native constant, production throughput, profile budget
or weight pass changes. Measure complete wide-range preparation, proving
and actual public verification in both fields. Retain all lookup and
original-source consumers, proof encoding and receipt/state assertions.
Record witness preparation separately, with integer nanoseconds, source
commit, hardware and process RSS in a ledger. Profile a separate complete
operation; its instrumented times cannot support a speed comparison.

Kill the candidate if it disagrees with the independent original recursive
oracle, changes any frozen proof value/state/account or rejection, changes
the tower basis or domain, or fails to improve the measured complete
operation. Preserve every original running proof and its domain. No
backend option, global monkeypatch, new dependency or verification bypass.

Before changing multiplication, test at least 10000 full-extension products
per field plus base-field, zero, unit and nonresidue boundaries. Check ring
identities and canonical outputs. Capture complete wide-range artifacts
with both fields/repetition counts and canonical zero/padded/wide inputs.
Existing A1 and A3 corpora remain the proof/receipt/continuation authority;
run their complete checks and the wide-range controls after the change.
Malformed proof fields must still reject at the public boundary.

The affected function is `research/sumcheck/check_sumcheck.py::mul`.
Direct and transitive callers include batching, zerocheck, lookup/fraction
trees and CQIS consumers. Tests and benchmark code live in research/bench;
core imports remain unchanged. Existing native multiplication already uses
these algebraic identities and is not modified.

Continue Q26/Q31 only after differential tests, frozen artifact parity,
ledger validation and repository gates pass. Native/private full inference,
PCS/ZK/FS, GPU parity, full-size evidence and independent review remain
required. E3-06, E4-01 and E5-03 retain their original status and criteria.

This integration starts from main commit
`ff0f005e87d283d4d2fb8fbce172216b0eda5322`. The measured implementation is
retained in its original worktree. Its benchmark dependencies match main
except for wide-range capacity guards and checker coverage. This fixture
uses three words, inside both guards, and imports only the unchanged
`rejects` helper from that checker. Main keeps its existing capacities.
This branch does not replace any full-size attention obligation or run.

Review units separate tests/CI, original baseline ledgers, and the arithmetic
change with its result ledgers. Retain the original measured commit hashes;
verify the frozen complete artifacts on this base before applying the
multiplier. No native, accepted-RFC, accounting or source-domain change is
part of this integration.

The independent main-based check passed all 40409 products and all four
frozen complete proof artifacts with the original multiplier. Each artifact
includes actual source/lookup consumption, exact receipt/state values and
the wrong-root/noncanonical-field controls. This preserves the original
fixture rather than recapturing it on the new branch.

The required `reference-field` CI group runs both `--vectors` and `--proofs`;
fixture-authoring `--capture` is excluded. Tests first rejected its missing
group. All ten inventory/aggregate tests then passed: 119 commands in 21
groups, preserving every inherited group and the workflow byte for byte.
Inventory SHA-256:
`0969b478719fa0ca99c4e34e8e454f86f901fd363041d297a5d198ddaef6c361`.
Hosted CI remains required; no multiplier change is in this review unit.

The original [QM31 baseline](../../bench/ledger/e5-03-reference-field-before-qm31.json)
and [OM31 baseline](../../bench/ledger/e5-03-reference-field-before-om31.json)
are retained byte for byte from the measured branch. Both identify source
commit `b77e9c9971559e6b8a8647a5a34b394f3ba29267`; use that hash for reproduction.
The original source history is available on `task/E5-03-reference-field`.
These are three-sample complete public research operations under concurrent
validation load, with witness/root preparation separated. They establish no
native constant, full-inference throughput or profile certification.
