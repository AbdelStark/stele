---
name: gkr-reduction-author
description: Author a reduction (claim-consuming/claim-emitting sub-protocol) in stele-reductions following the RFC op definition — matmul, requant, rmsnorm, rope, silu_gate, attention steps, embedding, lm-head, moe, mla.
---
# GKR reduction author
Read first: RFC-0006 §6, the op's RFC (0007/0008/0009/0017), RFC-0004 for the exact integer semantics.
Every reduction implements `trait Reduction { fn consume(&[Claim]) ; fn prove(&mut Transcript, witness) -> Vec<Claim>; fn verify(&mut Transcript, proof, claims) -> Vec<Claim>; fn ledger_lines(&self) -> Vec<LedgerLine>; fn certificate(&self) -> BoundCertificate; }`.
Public MLEs (`A` kinds) come from `stele-gkr::public_mle`; add a kind only with its verifier evaluation and agreement test.
Stacking: the reduction is written once for the stacked tensor; never loop over layers.
Checklist: selectors exclude padding; each emitted claim has exactly one consumer in the plan; the control for a
one-value tamper exists; the certificate is static; cost formula documented in the module header.
