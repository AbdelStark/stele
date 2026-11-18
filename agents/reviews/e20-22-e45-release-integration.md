# Integrating E16-45 occurrence weights with E20-20 original lookup reads

The first release tree that contains both E16-45 `6f0c55eb` and E20-20 `5f80428e` needs the lookup adapter update below. The E16-42 through E16-45 CPU stack is exercised together in validation. E16-45 is the commit that moves the offsets to the plan.

E16-45 records one pair per global column number in `Plan.offsets`. Each pair contains the column's start and its first mask block **within its own source**. The producer populates the pair from `cursors[column.source]` and the PCS message builder reads it by global column number. E20-20 uses the identical interval when it projects a committed owner's quarter into original lookup tuple and multiplicity views.

| Required change | Portable commit | Files |
|---|---|---|
| Read `plan.offsets[index]` after checking that the column belongs to an early source. Preserve the single-limb, extent and physical backing checks. | `27a27592e6306afaa67153aa25aab06924ad43c4` | `crates/stele-reductions/src/zk_lookup_input.rs` |
| Exercise alternating owner IDs, distinct prefixes, tuple and multiplicity columns and doubled-row physical addresses. | `d84eb7e68e662be335574b5cedd093ab3e221be1` | `crates/stele-reductions/src/zk_claims.rs` |
| Retain the reviewed private occurrence-weight module in the exact native inventory and the negative that removes it. E16-45 carries this commit on its shipping branch. | `c0bbcec8b28b21ee36b35e9f00665987178c63e2` | `scripts/gates/check.py`, `scripts/tests/test_field_source_gate.py` |

The two lookup commits apply individually to the release integration branch. The E16-45 guard is present there when its shipping branch has landed. The validation branch carries its equivalent as `eaaa7c25`.

```sh
git cherry-pick 27a27592e6306afaa67153aa25aab06924ad43c4 d84eb7e68e662be335574b5cedd093ab3e221be1
cargo test --frozen -p stele-reductions --lib matches_reference_interleaved_lookup_source_offsets
python3 -B -m unittest scripts.tests.test_field_source_gate.FieldSourcesLayoutTests
```

The positive test passed. In an isolated checkout, replacing `index` by the number of preceding columns that share `c.source` made this same test fail at descriptor construction with `Statement`. For that mutation the global offsets vector receives a source-local ordinal. The field gate passed its positive and removal controls.

Lucid job 6961 runs the normal H100 parity gate and conventional T32 proof on candidate `27a27592`, tree `ce4a363a93543a68df111f7613938eb050f211e4`. The validation composition includes exact A7 `92bfae2b` and CPU sources `02afacd9`. The release integration takes the reviewed changes through the ordinary selected PR gates.

## Integration checks

All commands below exited zero. Both Rust workspace suites and Clippy ran on the frozen production source `27a27592`. The native check also included the E16-45 inventory entry. The CI tool tests used the equivalent committed admission and its removal control. The focused interleaving test runs separately on `d84eb7e6`.

| Command | Result | SHA-256 of the operator log |
|---|---|---|
| `cargo test --workspace --locked --offline` | 912 passing cases | `d5a1618221975c5b3c55f8d59701df48682ba65fdcaba1a806bf6ee72554adc1` |
| `cargo test --workspace --all-features --locked --offline` | 978 passing cases | `951cc4e9387605b3cde9cb74dbaad38e2765b4fcbeac4b38a5306014ca843532` |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed | `909d2a8a334fa9375149b97164088872409512d3df8e6f001f3c64b0a6fe2d7f` |
| `scripts/gates/native.sh` | Executed coverage reached 78 of 120 catalog bindings and 150 of 246 catalog controls | `dea8d8867b7081f2e052ab62fd626e0c8493e4e5b8861945ce5564ad6b218663` |
| `python3 scripts/ci_tests.py` | 119 passing cases | `6db7cecc356d689a39a1e798ed8ca802532686faebad16f3ac44171624c48933` |

The H100 parity gate compared 50 distinct complete proof and public bundle pairs with the original independent manifest. The gate also verified the replay, changed-model pins and backend rejection controls. [Complete corpus ledger](../../bench/ledger/e20-22-e45-h100-complete-shared-proof-parity.json)
