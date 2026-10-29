# E3-07a delivery acceptance

The complete conditional fraction-tree/selected-product task is delivered.
The codec, native engines, real controls, shared corpus, benchmark harness and
measurement PRs [#98](https://github.com/AbdelStark/stele/pull/98) through
[#105](https://github.com/AbdelStark/stele/pull/105) are merged. Required hosted
checks were inspected at each exact published head; preview merge trees and
post-merge main trees matched the tested source. The final measurement merge
is c0ada2eaeb6e829f6f9751ef44500daa4f54954a, matching tested head
2596ac5d3f6e8dea9d02b5c1bdbfa1e9773fbf3c exactly.

Every original acceptance criterion has concrete evidence:

| Criterion | Evidence |
|---|---|
| Both-field canonical descriptors/proof codecs, malformed/maximal verifier shapes | [codec review](fraction-codec.md), native codec/leaf_codec tests including maximum verifier shape without domain allocation |
| Tree/selected-product engines and original consumers | [tree](fraction-tree.md) and [selected product](selected-product.md) reviews; both original pairs and all original columns consumed, including beta=0 |
| Real NC-0406..0410 plus challenge/continuation controls | Native ProverHook controls, NC-0411/0802, [transcript review](fraction-transcript.md); actual rejection errors are required |
| Shared exact corpus plus 1000 seeded cases per field | [corpus review](fraction-corpus.md); 162 cases, 28 honest and 134 rejects, with proof/decision/claim/accounting/continuation parity; native tree/selected tests retain their seeded cases |
| Complete primitive cost and memory ledgers | [benchmark](fraction-benchmark.md) and [ledger](fraction-ledgers.md) reviews; QM31/OM31 ledgers linked below |

The [QM31](../../bench/ledger/e3-07a-fraction-qm31.json) and
[OM31](../../bench/ledger/e3-07a-fraction-om31.json) artifacts retain all 120
operations across 40 field/case combinations and three samples. They charge
preparation, internal copies/levels, native proving, encoding/decoding, actual
original consumption, validation/result construction and cleanup. Process RSS
is the complete native process peak, not an attributed prover or host bound.
Measured source 8798d1ac60e67d1a6580339f3951427efd82cc05 has no crates/bench
diff against repaired harness head 203bb687be9e4661c24ee39aec35b6167d35f559.

This completion changes task status only. It introduces no protocol decision,
new loss, fitted constant, weight pass or coverage credit. Historical benchmark
coverage remains the coverage at measurement time; subsequently reserved
controls do not change those artifacts. Same-author reviews are not independent
audit. E3-07 remains blocked on RFC-0008 A2 and retains full lookup, committed
multiplicities, private consumers, NC-0400..0403 and measured c_lu criteria.
No PCS, ZK, GPU, inference or profile admission follows from E3-07a completion.
