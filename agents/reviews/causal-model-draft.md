# Causal model — same-author skill review

Scope: Q26 / Draft RFC-0004 A9. Author/reviewer codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence: [study](../../research/cqis-checkpoint/CAUSAL-MODEL.md).

- Public items: research model composition, boundaries and greedy replay only.
  Accepted text is preserved; no Draft behavior enters core crates.
- Challenges/claims/ledger: none. Full numerical replay supplies no private PCS,
  range/lookup/sumcheck, FS or joint-ZK claim; no ledger or NC credit changes.
- Bindings: whole-model local cache scope and exact checkpoint hashes are checked.
  Cache values, source roles and canonical outer identity still need real consumers.
- Static arithmetic: existing bounded exact operations; unit compatibility is
  explicit. Numerical success is not a static field-faithfulness certificate.
- Masks/determinism: contiguous real positions, causal masks, ordered layers and
  lowest-index ties. No padded-proof layout or sampling policy is admitted.
- Parity: independent arithmetic and complete cuts/head records, full/cache and
  greedy comparisons; shared nonlinear primitives disclosed. No GPU code changes.
- Costs: vocabulary projection/selection, retained payload limits and cache copies
  are explicit; no benchmark number, proof weight pass or new cut.
- Verifier/format: native no_std code unchanged; canonical outer bytes and complete
  source/plan/parameter authentication are still open. Original criteria preserved.

I tried to break it by changing the model's logit units behind an existing cache,
and the CacheScope control rejected it. The Generation control rejected a changed
continuation, a non-lowest tie, an extra token after EOS and a wrong stop reason.
