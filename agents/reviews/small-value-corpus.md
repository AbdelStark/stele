# E3-04 independent decision corpus review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes, not independent audit. Production library unchanged.

I tried to break it by changing one unused original final, and the control
NC-0204 rejected it with ClaimMismatch. The shared corpus additionally reproduces
unused-final and truncated-original rejections through both actual Rust and
independent Python A1 public consumers; no extra catalog credit is claimed.

Workflow 03 checklist:
- Public items: no library API; RFC-0006 A5 fixture adapter selects Small for
  typed metadata and existing Dense for the continuation. Serde checks i16/u16
  narrowing; unknown representation and invalid widths reject in tests.
- Challenges: same A1 Instance, Round before Sumcheck, then every Final. Each
  accepted case has a following proof produced from the continued transcript.
- Claims/consumers: real verify_public is unconditional, independent of expected
  outcome or strategy metadata. Rust/Python outputs compare all original claim
  values/identities, derived points and SC records; gate checks descriptor counts.
- Bindings: existing NC-0204 remains mandatory; corpus covers changed round,
  missing round, changed unused final and original value, with exact rejections.
- Ledger: unchanged m*delta/p^d; no new labels or challenges. Both gates regenerate
  fixtures and require actual Small proof parity plus adapter boundary tests.
- Certificates: static typed eligibility only; no authenticated range proof.
- Padding/masks: no changed selectors, masks, intermediate commitment or ZK claim.
- Determinism: fixed seed, ordered terms and canonical bytes. 76 accepted chains,
  226 exact rejections, both fields and all supported small dimensions/prefixes.
- Parity: actual Rust Small versus independent dense Python A1 bytes; no GPU change.
- Cost: no runtime/peak-memory number or fitted constant. Required evidence pending.
- Verifier: unchanged no_std library; JSON parsing and assertions are example-only.
- Glossary: unchanged claim/consumer and typed eligibility meanings.

Sign-off: approve this evidence slice conditional on gates, including mutations
of corpus expectation, Small adapter prefix and returned claims. E3-04 remains
in progress for measured complete costs/memory. Finite checks do not resolve Q12.
