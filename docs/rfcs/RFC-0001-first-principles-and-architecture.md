# RFC-0001 — First principles, the statement, and the architecture

Status: Accepted · Version: 0.1.0 · Depends on: none · Governs: all protocol RFCs

## 1. First principles

### 1.1 Where the work is in inference
A transformer layer on `n` positions does `≈ 2·n·P_layer` multiply-accumulates but touches only
`P_layer + n·(7d + 4h_kv d_h + 4d_ff)` values. The ratio is the inner dimension `d` ≈ 10³–10⁴. Attention adds
`n²·h` exp evaluations and `2n²·h·d_h` MACs — again a `d_h` ratio.

### 1.2 Where the work is in a commit-the-trace STARK
Every computed value (and every MAC, unless a Freivalds/sumcheck gadget removes it) becomes a trace cell. A cell
costs interpolation + low-degree extension + Merkle hashing + quotient + FRI ≈ 10³–10⁴ field-op-equivalents
(measured: SASH's proof system sustains 1.3·10⁹ cells/s on an H100). The cost is **per cell**, and the cell count
is proportional to the *computation*, not to its *data*.

### 1.3 Where the work is in a sumcheck/GKR proof
Thaler's matmul protocol reduces a claim about `C = X·W` to claims about `X` and `W` at random points with prover
work `O(n·d + d·m)` — the cost of *reading* the operands once, in the field, with no hashing. GKR composes such
reductions through a layered computation without committing any intermediate value. LogUp-GKR proves a lookup
with O(1) field ops per lookup and commits only a table-sized multiplicity vector. The cost is **per byte**.

### 1.4 Consequences (the design, derived)
1. **Never commit activations.** Commit only what breaks sequential dependency: the residual stream at layer
   boundaries (int16, `n·d·L` elements). Everything else is virtual. (RFC-0007 §3)
2. **Never pay a MAC.** All matmuls (weight, QKᵀ, P̂V, embedding, LM head) are sumcheck reductions. (RFC-0007, 0009)
3. **Pay for each weight byte once per proof.** Stack all layers of a weight type into one polynomial; batch all
   its output claims to one point; one sumcheck over `(ℓ, k)`; its partial-evaluation pass is also the commitment
   opening (fused opening). Four sequential phases per proof: DOWN, UP/GATE, O, QKV. (RFC-0007 §5, RFC-0010 §5)
4. **Pay for each nonlinear value once.** Every nonlinearity is a lookup into a table defined by CQIS; the table
   domain performs the range check for free; tables are decomposable where they must be large. (RFC-0008)
5. **Attention touches n² only through the exp lookup.** Scores and probabilities are virtual. (RFC-0009)
6. **The field is chosen by the accumulator, not by the FFT.** M31 holds int8×int8 inner products up to inner
   dimension 2¹⁶ exactly; QM31 gives 124-bit challenges; no FFT exists on the per-proof path. The circle group is
   used once, at registration, to RS-encode weights. (RFC-0003, 0010)
7. **The semantics is designed for the proof, then validated for the model**, not the other way round. (RFC-0004)
8. **Soundness is a budget, not a vibe.** Every challenge has a line in the accounting; treaty profile uses only
   proven bounds and is nearly free because prover cost does not depend on query counts. (RFC-0012)

## 2. The gap we target
Field cost (Stone → Stwo): ≈10×. Cell-count × cell-cost (commit-the-trace → Stele): ≈10× fewer elements per position
× ≈50–100× fewer ops per element ⇒ **≈10³×** on the same hardware (`docs/cost-model.md` §3). The proof becomes
cheaper than serving for decode-heavy requests.

## 3. The statement

**Public inputs** `π = (cqis_id, passport_root, io_digest, policy, profile)`
- `cqis_id`: hash of the CQIS specification version + model configuration (shapes, scales format, table ids).
- `passport_root`: root binding all weight commitments, table commitments and bound certificates (RFC-0011).
- `io_digest = H(prompt_ids ∥ generated_ids ∥ sequence boundaries)`; optionally commitments instead of plaintext.
- `policy ∈ {greedy, sampled(seed_commitment, temperature, top_p)}`, stop rule, max tokens.
- `profile ∈ {standard, treaty}`.

**Witness**: weights (opened via passport), all activations, scales, multiplicities, selection indices.

**Statement**: there exist weights `W` consistent with `passport_root` such that the CQIS forward pass over the
full token sequence `T = prompt ∥ generated` with the causal (or configured) mask produces, for every generated
position `t`, logits at position `t−1` whose decoding under `policy` equals `T[t]`, and the first `|prompt|`
positions are exactly `prompt`. (Decode-by-decode with a KV cache is mathematically this single pass; RFC-0004 §9.)

What is **not** stated: that the tokens came from any particular traffic (RFC-0011 §5 provides the digest hooks),
that the fp32 model would agree (RFC-0011 fidelity report), that the architecture is secret (RFC-0017 §8).

## 4. Architecture in one picture

```
registration (once per model)        proof (once per request / batch / epoch)
──────────────────────────────       ─────────────────────────────────────────────────────────
HF checkpoint ──CQIS quantiser──►     tokens ──CQIS forward (int8/int16)──► residual cuts R_0..R_L
weights(int4/8) + tables + bounds     commit R-stack, multiplicities, aux  (RFC-0010)
──interleaved-code commit (circle RS)─►      │  verifier samples ρ; claims R̃_{ℓ+1}(ρ) ∀ℓ
passport: roots + proximity cert +    DOWN phase ──► SiLU/gate ──► UP/GATE phase ──► norm2
checkpoint-binding proof +                ──► O phase ──► attention ──► QKV phase ──► norm1 ──► embedding/LM head
fidelity report (RFC-0011)            each phase = one stacked sumcheck over (ℓ,k) + one fused weight opening
                                      PCS openings: R-stack (1), weights (7, fused), multiplicities, aux
                                      optional: ZK masks (RFC-0013), recursion wrapper (RFC-0016)
```

### 4.1 Claim flow (dense Llama-style layer; RFC-0007 §4 has the full table)
`R_{ℓ+1}(ρ) → [split] → R_mid(ρ) + ffn_out(ρ)`;
`ffn_out → requant+lookups → C_down → [DOWN sumcheck] → H`; `H → silu·gate zerocheck+lookups → U, G → requant → C_up, C_gate → [UP/GATE sumchecks] → X_norm2`;
`X_norm2 → RMSNorm → R_mid`(batched with the split claim)` → R_ℓ ⊕ attn_proj_out`; `attn_proj_out → requant → C_O → [O sumcheck] → A_out`;
`A_out → attention (exp lookups, attained max, P̂V, QKᵀ, RoPE) → Q,K,V → requant → C_Q,C_K,C_V → [QKV sumchecks] → X_norm1 → RMSNorm → R_ℓ`.
All claims on committed `R_·` go to one batched opening; all weight claims are opened in the phase that created them.

### 4.2 Sequential depth
Fifteen global stages, each a stacked sumcheck across all layers (and heads). Within a stage the per-layer work is
embarrassingly parallel; the only cross-layer communication is a reduction of one round polynomial per sumcheck
round (RFC-0015).

## 5. Decisions (ADR summary; see `agents/context/decision-log.md`)

| # | Decision | Alternatives rejected | Why |
|---|---|---|---|
| D1 | Sumcheck/GKR core, no trace | AIR/Circle STARK core (Stwo fork), zkVM | per-byte cost, no intermediate commitments |
| D2 | M31 base, QM31 challenges | KoalaBear/BabyBear (2-adic), Goldilocks, binary towers | fastest 32-bit arithmetic, M31 exactly fits int8 accumulators, no FFT needed on hot path |
| D3 | Residual-only cuts | cut every matmul input; no cuts (per-layer weight passes) | 1 pass/proof with the fewest committed bytes |
| D4 | Interleaved-code PCS with fused opening | WHIR/BaseFold (FFT per opening), curve PCS | opening = one streaming pass over raw packed weights |
| D5 | int8 matmul inputs, int16 elsewhere, exact int32 accumulate | bf16 lookups (SASH), 12-bit ints (DeepProve) | field-native, same table sizes as bf16, simpler gadgets |
| D6 | LogUp-GKR for all lookups | Shout (needs sparse-friendly PCS), Lasso | nothing committed but multiplicities |
| D7 | Blake3 transcript/Merkle; Poseidon2-M31 only in the wrapper | Poseidon everywhere | GPU throughput; recursion is optional |
| D8 | Treaty profile = proven bounds only, ZK on, double-α LogUp | conjectural 100-bit everywhere | auditors; query count is free for the prover |
| D9 | Stwo as optional outer wrapper, never as core | | M31-native verifier for compact certificates; StarkWare-maintained |

## 6. Negative controls
NC-0001 (tamper one generated token), NC-0002 (tamper one residual cut element), NC-0003 (swap two layers' weights),
NC-0004 (use a different passport), NC-0005 (prompt prefix mismatch). Full catalogue: `tests/negative-controls/catalog.md`.

## 7. Open questions
Q1 Is residual-only cutting optimal for MoE routers (RFC-0017 §4)? Q2 Octic extension vs double-α for treaty lookups (RFC-0019 R-OCTIC).
