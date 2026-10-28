# RFC-0010 A1 draft review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author and
soundness-auditor passes on research/escalation only, not an independent audit.
Decision: publish the study and Draft requirements. Do not accept A1, implement
an arbitrary encoder, or create a usable profile entry from this research.

- Public API: unchanged. `stele-code` remains a scaffold; existing gate scopes are unchanged.
  Draft requirements cover encode/eval_row/parameters and their missing contract.
- Challenges: none introduced; existing transcript and label inventory unchanged.
  Setup randomness and its distribution/failure/grinding are open obligations.
- Claims/consumers: no PCS claim produced. Encoding, distance, proximity and
  authentication are explicitly separate; a future original consumer is mandatory.
- Bindings/controls: no NC credit. Research rejects malformed permutation lists
  and exposes a nonzero low-weight message despite misleading random samples.
  Production parameter/code identity substitution controls remain required.
- Ledger: no changed certified term. Missing distance or setup evidence is not
  treated as zero error. Exact proximity and query instantiation remain open.
- Certificates: exact small-code distance uses full-rank generator hyperplanes;
  exhaustive F2/F3/F5 comparisons check that method. This is unrelated to CQIS
  integer bound certificates, and does not supply a scalable production code.
- Padding/masks: unsupported production sizes and padding still need specification.
  No inference selector, mask or padded commitment is introduced.
- Determinism: fixed seed and ordered permutation/basis enumeration. Random
  sampling is diagnostic and cannot turn a distance estimate into a lower bound.
- Parity: 24 fixed maps have checked M31 linearity and operation counts. The
  extension-distance statement is an algebraic support argument, not GPU evidence
  or actual Rust/QM31/OM31 implementation parity. Those remain delivery gates.
- Costs: exact addition counts only; no runtime/throughput benchmark. Construction
  and graph storage must be included in the eventual c_c and memory ledgers.
- Verifier: unchanged. No no_std or parsing change; the future verifier must select
  approved parameters, not trust a prover's boolean or theorem string.
- Glossary: existing meanings preserved; no new commitment or cut introduced.

Adversarial finding: for the tested identity-permutation map, 1,000 random
nonzero words have weight 64 while `[1,-2,1,0,...]` encodes to weight four. This
invalidates a claimed distance lower bound above four for that map. It is not a
false acceptance by a production verifier and supplies no production-review
approval sentence. Full construction and evidence review must precede acceptance.
