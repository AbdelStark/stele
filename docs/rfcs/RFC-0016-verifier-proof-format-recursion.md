# RFC-0016 — Verifier, proof format, recursion wrapper

Status: Accepted · Version: 0.1.0

## 1. Proof container (`stele-proof-v1`)
Self-describing, versioned, little-endian: header (`magic`, `version`, `profile`, `cqis_id`, `passport_root`,
`io_digest`, `policy`, ledger hash), then stage sections in transcript order, each with its reduction id, round
polynomials, final claims, lookup roots, PCS openings. Size bounds are derived from `plan.json`; the verifier refuses
any proof whose size deviates from the plan (no variable-length prover control).

## 2. Verifier algorithm
1. Parse header; derive `plan.json` from `cqis_id` + passport (never from the proof).
2. Recompute bound certificates (RFC-0004 §6) and the error ledger (RFC-0012 §4); reject if out of profile.
3. Replay the claim graph: initialise transcript with `π`, draw `ρ`, walk stages; for each reduction verify sumcheck
   rounds, evaluate public MLEs (`eq`, masks, RoPE tables, one-hot from opened indices) at the final points, check
   emitted-claim consistency; for lookups verify fraction-tree roots and the table-side sum; for PCS openings verify
   `u·b`, column spot checks, Merkle paths.
4. Accept iff all checks pass. Cost: `O(Σ rounds·δ)` K-ops + `O(q·R)` per opening + `O(2¹⁶)` per table ⇒ seconds on 8 cores.

## 3. Implementation constraints
`stele-verifier` is `no_std` + `alloc`, < 15k LoC, zero dependencies beyond `stele-field`/`stele-hash`, every check
annotated with the RFC section, panics forbidden (all errors typed). An independent Python verifier in `harness/verifier`
is kept in lockstep by CI (RFC-0002 S10).

## 4. Table MLEs
Natively: evaluate `T̃(r)` over the 2¹⁶ entries. Wrapper mode: open the passport-committed table matrix (RFC-0011 §1.3).

## 5. Recursion wrapper
Purpose: compact certificates (≤ 500 KB, ≤ 200 ms) for registries and on-chain use. The wrapper proves "the Stele
verifier accepted" — a layered computation dominated by Blake3/Merkle checks and K-arithmetic — in an M31-native STARK
(Stwo/stwo-cairo verifier infrastructure, StarkWare-maintained) with Ligerito-mode openings to keep column openings
small. The wrapper is **optional** and **outside the soundness-critical path of native verification**; its own
accounting is a separate ledger. Hash: Blake3 for the inner proof; the wrapper's transcript may use Poseidon2-M31.

## 6. One-time wrapper jobs
Checkpoint-binding proof (RFC-0011 §1.5): hash `digest_cqis` over the committed plaintext in-circuit; batched over the
column leaves so that the Merkle structure is reused.

## 7. Negative controls
NC-1200 proof section reordered; NC-1201 plan derived from proof header instead of passport; NC-1202 panic path in verifier
(fuzz target); NC-1203 wrapper accepting a rejected inner proof.
