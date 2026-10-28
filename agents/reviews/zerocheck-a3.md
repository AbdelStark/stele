# RFC-0006 A3 / RFC-0012 A5 review

Reviewer: codex-root, also the author. These soundness-auditor, RFC-author,
sumcheck-prover-engineer and PCS-engineer/hash-owner passes are not independent
audit. Scope is the protocol contract and research oracle, not E3-03 delivery.

Soundness-auditor: fix tensors before alpha; account for j weight-collapse loss,
D skip loss and j*δ tail loss, each over p^d. A nonzero discrepancy survives
weighted endpoints even at alpha=0/1. No inverse of a random value is needed.
Hybrid evaluations close through every original slice claim, including unused
ones. Reusing an ordinary MLE final would be wrong: the recorded rank condition
fails at s=4,u=4. The formal argument is conditional interactive soundness, not
FS, PCS, composition, ZK or a profile certificate. Sign-off: approve the contract.

I tried to break it by changing one skip evaluation, and the control
RoundSumMismatch rejected it. With no tail, FinalEvaluationMismatch rejected it.
An unused slice change instead reaches ClaimMismatch; an early weight changes
one skip value and rejects. These are research controls only. The chained A1
research check detects omission of ZeroFinal through one changed final value.

RFC-author: original Accepted prefixes are preserved byte-for-byte. A3 defines
a separate zerocheck relation; A1/A2 consumers keep their bytes. Degree follows
ordered factors; k is fixed by the verifier's plan. All proof lengths, domains,
labels, final points, records and errors are explicit. Sign-off: approve; retain
both strategies, 10^3 reference cases per degree and the improvement ledger.

Sumcheck-prover-engineer: exhaustive residual sums and independent eq-dot public
consumption agree on 130 honest cases in both fields, plus empty relations.
Eight vectors bind descriptors, proofs, all claims/SC records and final state.
Direct integer-node interpolation is valid through D=60; no FFT cost is assumed.
The cost includes retained originals, slice finals and downstream consumption;
no speedup is established. Sign-off: approve; production parity remains required.

PCS-engineer/hash owner: original MLE slice claims can use existing claim-graph
consumers; no hybrid PCS functional API or new commitment is assumed. Virtual
claims must be merged through A2 before their producing reduction; committed
claims retain the RFC-0010 route. A5 adds four closed labels, changes no sampling
rule and leaves production registry/consumer changes atomic. Sign-off: approve.

Workflow 03 checklist:
- Public items: no new core API; A3/A5 govern the pending implementation.
- Challenges: complete Zero then j weights; ZeroSkip then u; each Round then r.
- Claims/consumers: all original inputs at (Boolean prefix,r), public eq-dot or
  actual reduction/PCS consumers; ZeroFinal precedes continuation.
- Bindings: NC-0207/0208/0209 are planned, NC-0802 needs a production extension.
- Ledger: three phased SC records with j,D,j*δ; current production gates retain
  their existing consumer inventory. New records are research evidence only.
- Certificates: field-only identities; integer/range certificates remain external.
- Padding/masks: plan-owned, degree counted in C; no change to cuts or ZK.
- Determinism: ordered vectors and indices; no timing-dependent selection of k.
- Parity: eight Python vectors, no Rust/CUDA zerocheck parity claim.
- Costs: c_sc/T_misc symbolic only; final payload grows by s, no benchmark result.
- Verifier: no_std implementation must preflight canonical lengths and allocation;
  the oracle is an exact-arithmetic study, not an inference-proof parser.
- Glossary: checked; successful reduction results retain all consumer obligations.
