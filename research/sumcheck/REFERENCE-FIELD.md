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

Before the arithmetic change, 40409 products passed against the independent
schoolbook oracle. All four complete wide-range proofs passed, including
the actual source/lookup consumers and exact noncanonical/root rejections.
`field-proof-digests.json` freezes each complete proof, receipt and state
under a lossless tagged JSON encoding. The original A1/A3 fixtures remain
the authority for their byte encodings and continuation challenges.

The first QM31 measurement passed every proof check but failed ledger
validation: micro records reserve top-level proof/verification/control
fields for inference. Research evidence now lives under `model_config`.
Both new scripts pin Python 3.12 for comparable measurements. The rejected
record and its Python 3.15 log are retained outside the repository; they
support no performance claim. The arithmetic remains unchanged.

The candidate now uses scalar coefficient products, the fixed nonresidue
maps and Karatsuba at each tower level. For a quadratic generator z with
z²=n, the result is `(ac+n*bd) + ((a+b)*(c+d)-ac-bd)*z`.
The maps for -1, 2+i and u are the same maps used by native `stele-field`.
Every output coefficient is reduced modulo p. No consumer or transcript
code changed; the scalar branch is data dependent, with no constant-time
claim for this Python reference.

All 40409 differential products and four frozen complete artifacts passed
after the change. A1's 196-case corpus and byte vectors passed. A3's 130
byte vectors and 314-case shared corpus passed, including continuation
challenges and 174 exact rejections. Existing wide-range controls passed.
The independent oracle retains the original recursion and never calls the
candidate. These checks establish finite evidence, not a new theorem.

The following totals cover three complete proofs per field on the recorded
Apple M4 Max/Python 3.12 environment. Each proof retains its three supplied
words padded to four, sixteen source byte cells, thirty-two lookup
source rows and complete 256-row table. Witness/root preparation, proving,
actual public verification and encoding/state/account checks are included.
Warmup, separate rejection controls and the instrumented profile are excluded.

| Field and ledgers | Before wall ns | After wall ns | Before CPU ns | After CPU ns |
|---|---:|---:|---:|---:|
| QM31 ([before](../../bench/ledger/e5-03-reference-field-before-qm31.json), [after](../../bench/ledger/e5-03-reference-field-after-qm31.json)) | 7858656874 | 3804318917 | 2717042000 | 1539570000 |
| OM31 ([before](../../bench/ledger/e5-03-reference-field-before-om31.json), [after](../../bench/ledger/e5-03-reference-field-after-om31.json)) | 36932167043 | 10350275333 | 12822273000 | 4442799000 |

Plans, toolchain, hardware and complete artifact digests match between each
pair. Both field measurements execute 36008 externally invoked multiplications
per instrumented complete operation; total calls including recursion fall from 1116248 to
228860 for QM31 and from 5617248 to 662777 for OM31. All four ledgers passed
schema validation. Other original validation processes kept running, so
these observations support no fitted c_sc constant or production target.
RSS includes imports, warmup, all proofs, controls, profiling and allocator
retention; it is not isolated scratch space.

Reproduce from each ledger's clean source commit:

```sh
uv run --python 3.12 --locked --script research/sumcheck/check_field.py
uv run --python 3.12 --locked --script bench/reference_field.py QM31 /tmp/new-qm31-ledger.json
uv run --python 3.12 --locked --script bench/reference_field.py OM31 /tmp/new-om31-ledger.json
```

All required local gates passed at measured-branch head
`51fb88bb232e511d910b97016d00966d859dba74`: formatting, Clippy, workspace
tests, no_std CQIS, dependency bans, Rust policy, digests, negative controls,
soundness accounting, ledgers, RFC references, documentation/glossary and CI
scope. The original process completed successfully; it was not restarted.

Recommendation: retain this reference arithmetic change after fresh hosted
CI and review. Full-size inference, native/GPU performance and independent
audit remain open.
