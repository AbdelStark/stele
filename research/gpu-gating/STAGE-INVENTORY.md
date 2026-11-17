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

A leading `inventory` record declares the field and the plan's relation, GKR,
lookup and batch counts. Each lookup has either a first step, zero or more
interior steps and a leaf, or a single step that is both first and leaf. The
latter is reported as `gkr_leaf`. Counts and this sequence are validated together.

## Parse and validate

```sh
python3 research/gpu-gating/stage_inventory.py prove.err > stages.json
python3 -m unittest scripts.tests.test_stage_inventory
cargo test -p stele-reductions --features std --test zk_lookup matches_reference_stage_instrumentation
```

The parser accepts one complete development-ZK proof log with lookups. It checks
phase and per-instance child order, declared counts, GKR topology, positive
dimension/degree, factor/coordinate bounds and timing containment, and rejects
extra shape fields. It does not derive a polynomial's degree bound from this
geometry-only log; the ordinary verifier retains that check. The caller must still
verify the actual proof and record its hash, source, hardware, threads and full
process costs in a validated ledger. Parsing a log does not establish acceptance.

The integration test runs the real prover and verifier in two subprocesses, with
the same synthetic input and seed, and compares a digest of every typed proof
field with instrumentation off/on. The parser fixture retains that test's
topology with every time replaced by zero; it is not benchmark evidence.

## H100 host CPU baseline

Three instrumented `stories42M` development-ZK proofs at `T = 32`, checked
positions `23..32`, ran on Lucid `h100-nvl-1-1-cc` with 16 pinned CPU threads and
`RAYON_NUM_THREADS=16`, at source `a9fd51f8`. This is a CPU calibration below
ladder rung L2a's `T = 64`; no CUDA work occurs in these proofs. All three prove
commands started below load 3. Every proof independently verified against its
expected model, and its wrong-model control rejected. The complete observations,
proof hashes, input/binary/archive hashes and host provenance are in the ledgers:

| Proof index | Prove process (s) | GKR factors (s) | GKR rounds (s) | GKR claim routing (s) | Ledger |
|---|---:|---:|---:|---:|---|
| 0 | 489.78 | 108.547 | 106.657 | 25.123 | [sample 0](../../bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-0.json) |
| 1 | 487.36 | 109.590 | 103.692 | 25.221 | [sample 1](../../bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-1.json) |
| 2 | 489.91 | 108.267 | 106.513 | 25.030 | [sample 2](../../bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-2.json) |

Whole-process results also appear in the [scoreboard](../../bench/scoreboard.md),
in the three `e16-40a-dev-zk-stories42m-t32-h100-{0,1,2}` rows.

The same public inventory appears in every sample: 876 relations, 385 GKR steps
(21 first, 343 interior, 21 leaf), 21 lookups and three source batches, represented
by 64 distinct shapes. Factor construction and final routing are substantial
costs separate from rounds. A device-round ratio alone does not measure them.
The ledger retains every coarse lap and summed detail lap; the timing hierarchy
above applies to these fields too. Self-verification remains enabled and timed.

Job 6605 initially compared an ordinary and instrumented CLI proof at index zero
and stopped at a mistaken equality assertion. Each CLI invocation draws a fresh
OS proof seed, so copying the model state does not produce a matched-seed pair.
Both accepted proofs and the failed assertion are preserved; the ordinary proof
is outside this three-sample series. Job 6608 continued the original instrumented
benchmark state through indices one and two without further copies. The real
fixed-seed library instrumentation test passed on this H100 host for both lookup
topologies. Production randomness was unchanged.

The public evidence archive is identified by SHA-256
`e329c9b68a41e8d9ded4ce86b9148d274131f1a3c238e368bfd532fae699ab56`;
all 75 payload files were hash-checked after download. Private state and seeds
are excluded. These measurements qualify CPU costs for further device research;
they do not lift ADR-127's NO-GO or establish an integrated GPU prover.
