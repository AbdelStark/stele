# Development-ZK stage inventory (E16-40a)

`STELE_STAGE_TIMES=1` preserves the existing coarse `stage <name> <ms>`
records and adds the inner laps below. It also emits one `shape` record before
each actual relation or GKR masked sumcheck. Without that environment variable,
or without the `std` feature, neither addition emits output. No transcript,
prover algorithm, certificate, opening or verifier predicate changes.

This measures the CPU work needed to reopen ADR-127. It does not approve a CUDA
backend or establish a speedup. In particular, a rounds-only kernel ratio cannot
be applied to a whole GKR, certificate or opening phase.

## Timing hierarchy

Every inner name has prefix `zk/detail/`. Each row's children are disjoint wall
intervals within the named parent; repeated child names are summed. The parent
already includes its children. Never add parent and child times together.

| Existing parent | Children, in execution order |
|---|---|
| `zk/sources_prepare_certify` | `sources_prepare`, `sources_certify` |
| `zk/logup_trees_and_tops` | Per lookup: `top_prefix`, `top_tree`, `top_values` |
| `zk/top_and_shared_sources` | `top_messages`, `top_prepare`, `top_certify` |
| `zk/relations_masked_sumcheck` | Per instance: `relation_prefix`, `relation_factors`, `relation_setup`, `relation_rounds`, `relation_claims` |
| `zk/logup_gkr` | Per step: `gkr_tree`, `gkr_prefix`, `gkr_factors`, `gkr_setup`, `gkr_rounds`, `gkr_claims` |
| `zk/claim_batches_and_openings` | Per source batch: `batch_prefix`, `batch_weights`, `batch_face`, `batch_rounds`, `batch_opening` |
| `zk/shared_batch_and_opening` | `shared_weights_face`, `shared_prove`, `shared_opening` |

`top_tree` measures the first complete tree construction, including table and
member input preparation. `gkr_tree` measures the actual later rebuild/drop
schedule, including zero-work reuse steps. These are separate source visits.
`gkr_factors` includes compact leaf construction; `gkr_claims` includes final
expansion, routing, rank checks and transcript continuation. The `*_setup` laps
isolate shape reporting from round measurements. Prefix laps include host
transcript work; no challenge is moved into a device measurement.

`sources_prepare` measures the complete production source preparation, with its
retained encoding and Merkle material. Certification includes its verification.
`top_prepare` is the wall time of the existing parallel top/shared preparation,
not the sum of worker durations. `batch_face` includes instance construction and
the source-face gather; `batch_opening` retains point checks and the authenticated
PCS response. `shared_prove` includes the complete A4 mask-source protocol,
including its preparation, certification and opening; it is not a rounds-only
measurement. `shared_weights_face` also includes coefficient draws.

The existing timer rounds each interval down to whole milliseconds. Unlabelled
work, timer/reporting overhead and lost fractional milliseconds remain in
`parent_ms - sum(children_ms)`. Treat that entire remainder as CPU work in any
offload model. The parser refuses child totals above a parent's wall time. Coarse
`zk/source_messages`, witness work and self-verification remain separately
reported CPU work; no self-verification is disabled or removed.

## Public geometry

The fixed record is:

```text
shape <relation|gkr_first|gkr_interior|gkr_leaf> field=<4|8> vars=<n> degree=<d> masks=<indices> terms=<factor indices> compact=<0|1>
```

`field` is the extension degree. `masks` lists each factor's vanishing-variable
index, or `-` for a public factor; these are indices, never mask values.
`terms` lists factor indices separated by dots, with commas between terms and
`-` for an empty product. Coefficients, field values, witness entries, mask
contents, seeds and challenge values are never recorded. `compact` reports the
existing leaf-final expansion shape. The inventory describes the actual CPU
strategy, including its first/interior/leaf variants; it does not prove that a
research CUDA shape implements any of them.

## Parse and validate

```sh
python3 research/gpu-gating/stage_inventory.py prove.err > stages.json
python3 -m unittest scripts.tests.test_stage_inventory
cargo test -p stele-reductions --features std --test zk_lookup matches_reference_stage_instrumentation
```

The parser accepts one complete development-ZK proof log with lookups. It checks
phase order, complete child counts, relation/GKR inventory counts, shape bounds
and timing containment, and rejects extra shape fields. The caller must still
verify the actual proof and record its hash, source, hardware, threads and full
process costs in a validated ledger. Parsing a log does not establish acceptance.

The integration test runs the real prover and verifier in two subprocesses, with
the same synthetic input and seed, and compares a digest of every typed proof
field with instrumentation off/on. The parser fixture retains that test's
topology with every time replaced by zero; it is not benchmark evidence.
