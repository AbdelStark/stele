# Architecture — one page

**Statement (RFC-0001 §3):** a passport-registered model, under CQIS (RFC-0004), mapped the published prompt to the
published continuation under the stated decoding policy.

**Shape of a proof (RFC-0007 §4):**
```
commit R_stack (residual cuts), multiplicities, aux        → RFC-0010
ρ ← transcript; claims R̃_{ℓ+1}(ρ) for all ℓ                 → RFC-0012
15 stacked stages (each: one sumcheck across all layers/heads):
  DOWN ─ silu·gate ─ UP/GATE ─ norm2 ─ O ─ attention ─ QKV ─ norm1 ─ embed/LM-head
  weight phases (DOWN, UP, GATE, O, Q, K, V, LM, EMB): one pass over that weight type, fused opening → RFC-0007 §5, RFC-0010 §5
  everything else: lookups (LogUp-GKR, RFC-0008), zerochecks, activation matmuls (RFC-0009)
PCS openings: R_stack (1 batched functional), weights (fused), multiplicities, aux
```
**What is committed:** residual stream at layer boundaries (int16), multiplicities, selection indices, scales;
RFC-0023 §2 additionally names the byte-plane advice cut for its standalone scalar Requant reduction.
That cut does not authorize other auxiliary commitments or the full inference-plan join.
**What is never computed by the prover:** any multiply-accumulate of the inference inside the proof.
**Field:** M31 base, QM31 (standard) / OM31 (treaty) challenges. **Hash:** Blake3. **Codes:** circle RS (weights), RAA (cuts).
**Memory:** one layer's recompute window + stacked sumcheck state (RFC-0014 §4).
**Verifier:** replays the claim graph from `cqis_id` + passport; never trusts proof-supplied shapes (RFC-0016).
**Crates:** see RFC-0020 §1. **Cost model:** `docs/cost-model.md`.
