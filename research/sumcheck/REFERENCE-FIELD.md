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
