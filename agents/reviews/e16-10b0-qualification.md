# NC-1306 rejection-precedence qualification

This is a public-artifact experiment, not a registered negative control or a
performance result. The verifier source is
`9e215b19ffe3e87300144d47fe2a579f8e759969` (PR #389), unchanged by PR #390.
Both fixtures use source profile 5, with one layer / T=16 (L0) and eight layers /
T=64 (L1), respectively. Honest proofs accept. Replacing exactly the stacked root
with the first multiplicity root rejects with exit 1 and the exact CLI verdict
`NO: Engine(Pcs(Transcript(GrindMismatch)))` in both cases.

| Fixture | Honest proof SHA-256 | Changed proof SHA-256 |
|---|---|---|
| L0 | `b87cf7a35ea8c1f5879fe15cc400a32884841e6627a64e911b04eb401e21f70a` | `ac4db9d4abf8598b5e2818f40355b6164bda557b0a17f7ef10d460586330958d` |
| L1 | `899e5745baedfb8a296112f6a61adde966d3f371c5845d94b0a2654ff561d9c1` | `2690ad0231bea907771219aae1684a37190b83a208744392b5f9bdd0b67dd03c` |

Reproduce with the repository's `development::prove_window_development` on the
`one-layer` / `eight-layer` fixtures from
`tests/negative-controls/src/development.rs::span_of`: initial statement
`tokens=[1], start=0, end=1, next=None`, window length 16 / 64, profile
`GRIND_PROFILE`. Decode the proof with the production container decoder. First
verify the honest proof against its returned public input and statement. Clone
the container; copy `multiplicities[0][..32]` into `groups[0][..32]`; assert the
roots differ. Restore that field in another clone and assert complete container
equality with the original. Verify the changed container's encoding against the
same public input and statement and require the exact nested error above. The
changed field starts at absolute byte 90 and has length 32 for both recorded
proofs. No input or reference artifact is changed.

The original CLI experiment uses `stele verify-dev --public public.bin --proof
proof.bin` with the honest and changed proof files separately. A future harness
must compare typed errors before formatting. This experiment does not qualify
Policy 1 or source profile 3, does not count as NC-1306 execution in the catalog,
and does not demonstrate a Merkle-path rejection. Those are explicit E16-10b
obligations. There is no verifier bypass or dependent nonce regeneration.
