# RFC-0012 — Transcript, Fiat–Shamir, soundness accounting

Status: Accepted · Version: 0.1.0

## 1. Transcript
Duplex sponge over Blake3 (`stele-hash::Transcript`): state = 32-byte chaining value; `absorb(label, bytes)` hashes
`(state ∥ label_len ∥ label ∥ len ∥ bytes)`; `challenge(label) → K` draws 16 bytes, rejection-samples each M31 limb
into `[0,p)`. Labels are ASCII constants registered in `labels.rs` (unique, versioned). Order of absorption is the
proof order (RFC-0016 §2). The first absorb is `("stele/v0.1/public", π)` with the full public input `π` (RFC-0001 §3)
including `cqis_id`, `passport_root`, `profile`, and the accounting hash (§5).

## 2. Rules
- Every prover message (round polynomial, claimed value, commitment root, opened leaf) is absorbed before any challenge that may depend on it.
- Claimed final values of sumchecks are absorbed explicitly (weak-FS guard).
- Column indices for PCS openings are drawn *after* `u` (or its commitment) is absorbed.
- Per-instance challenges are never shared across independent instances except through explicit batching (γ drawn from the transcript).
- Grinding: optional proof-of-work nonce absorbed before the PCS query challenges; counted in the ledger.

## 3. Hash choices
Blake3-256 for transcript and Merkle; leaves prefixed `0x00`, internal nodes `0x01`, roots-of-roots `0x02`. Poseidon2-M31
appears only in the recursion wrapper's own transcript. Treaty: 256-bit everywhere; standard may truncate Merkle to 192 bits.

## 4. Error ledger (generated per proof config by `stele-verifier::accounting`)
| Line | Term | Formula |
|---|---|---|
| SC | each sumcheck instance | `m·δ/|K|` |
| RLC | each batching of `t` claims | `t/|K|` |
| LU | each LogUp instance | `(N+|T|)/|K|` (standard) or squared (treaty) |
| PCS | each opening | `ε_gap + (1−δ)^q + ε_Merkle` (RFC-0010 §6) |
| MASK | ZK masks (RFC-0013) | `≤ 1/|K|` per masked instance |
| FS | Fiat–Shamir | `(Q_hash + grind) · ε_round-max` style bound in ROM with `Q ≤ 2^{80|100}` |
| H | collisions | `Q²/2²⁵⁶` |
Total = sum; the verifier rejects any proof whose config yields total above the profile bound (RFC-0002 §8).

## 5. Illustrative budget (405B, n = 4608, treaty)
Sumcheck rounds ≈ 10⁵ instances × ≤ 40 rounds × δ ≤ 4 ⇒ 1.6·10⁷/2¹²⁴ ≈ 2⁻¹⁰⁰ ✗ — **too large for 2⁻¹²⁸**. Mitigation:
(a) batch instances so the count is ≈ 10² stacked instances (the design does this: all per-layer instances are stacked),
giving ≈ 10²·40·4/2¹²⁴ ≈ 2⁻¹¹⁰; (b) treaty profile draws each sumcheck challenge from `OM31` (2²⁴⁸) — the prover's cost
difference is small because round polynomials are few — or doubles the sumcheck (R-OCTIC). Lookups: `N ≈ 2³⁷ ⇒ 2⁻⁸⁷`
single, `2⁻¹⁷⁴` double. PCS: proven gaps with `q` ≈ 300 (rate 1/4). The ledger must show ≤ 2⁻¹²⁸ or the config is invalid.
**Decision D10:** treaty profile uses `OM31` challenges for *all* sumchecks (round polynomials in OM31, witness folds in
QM31 are *not* allowed — folds must be in the challenge field), accepting ≈ 2× extension cost on the K-arithmetic share
(≈ 30% of prover time) — or the alternative of splitting each phase into two independent transcripts; to be fixed by bench (task E12-03).

## 6. Negative controls
NC-0800 challenge drawn before a message is absorbed; NC-0801 label collision; NC-0802 final value not absorbed;
NC-0803 query indices from stale state; NC-0804 ledger total tampered; NC-0805 profile downgrade in public input.
