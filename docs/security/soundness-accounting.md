# Soundness accounting (generated per proof config by `stele-verifier::accounting`; this file is the human-readable spec)

Total error ε = Σ SC + Σ RLC + Σ LU + Σ PCS + Σ MASK + FS + H (RFC-0012 §4). Profile bound: standard 2⁻¹⁰⁰, treaty 2⁻¹²⁸.

| Line | Instance count driver | Formula | Proven? |
|---|---|---|---|
| SC | stacked reductions per stage (≈ 10²/proof) | `m·δ/|K|` | yes (Schwartz–Zippel) |
| RLC | RLC batch reductions | `t/|K|` | yes |
| LU | one per (table, challenge pair) | `(N+|T|)/|K|`, squared with double challenge | yes (Haböck 2022) |
| PCS | one per opening (R_stack, 7–9 weight types, multiplicities, aux) | `ε_gap(ρ,δ)+(1−δ)^q+ε_Merkle` | treaty: proven only (BCIKS20, DP23/24, Khatam) |
| MASK | per masked instance | `≤ 1/|K|` | yes |
| FS | adaptive queries `Q` + grinding | ROM bound | assumption A2 |
| H | hash collisions | `Q²/2²⁵⁶` | assumption A1 |

Illustrative treaty budget for W4 appears in RFC-0012 §5; the generator must reproduce it. The gate
`scripts/gates/soundness-accounting.sh` diffs the generator's instance enumeration against the transcript labels actually
used by the prover (every `challenge(label)` call must map to a ledger line).

## Transcript label mapping (RFC-0012 A1)

The initial challenge label `stele/v0.1/sumcheck/challenge` maps to SC, once per
round in each consuming sumcheck; absorption labels introduce no random challenge.
QM31/OM31 denominators are exactly p^4/p^8. A1's conditional uniformity argument
adds no sampling-error line; exhaustion aborts and cannot certify a statement.
FS/H still cover all adversary queries and grinding. The gate compares the validated
`stele-hash` registry producer with [the canonical inventory](transcript-labels.json)
and runs the registry and transcript primitive unit tests. NC-0801 rejects a duplicated label at that same
production validator. Remaining protocol crates retain their scaffold guards.
This validates registry mapping, not per-instance accounting or a profile budget;
challenge generation follows A1, while real schedule consumers are still pending.
Q12 (RFC-0019) tracks the missing concrete FS theorem/query convention and the
incompatible illustrative H budget. No profile can be certified from placeholders.
