# Q23 v2 all-seed setup review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author, soundness-auditor.
Not an independent audit. Decision: continue Draft A1/A7 with v2; E4-01 remains
blocked on the complete production contract and profile composition.

- Public items/RFC: research map/sampler and formal/seeded-setup.md supersede v1.
  The raw map, manifest and block domains change together; old bytes reject.
- Challenges/absorbs: no proof challenge/label change. The ideal-oracle event covers
  every seed of one exact version, independent of adversarial quantum selection.
- Claims/consumers: outside the global bad event every regenerated supported map
  has the required distance. Actual identity/registry/source consumers remain due.
- Bindings/controls: v1 descriptor, changed coefficient/seed/J and cap exhaustion
  checks reject through actual research entrypoints. No production NC credit.
- Ledger: proposed fixed setup event <=200431782/2^160; no implemented loss-family
  change. All events are unioned, not treated as independent probabilities. Q12
  must justify the remaining protocol event outside bad setup in its oracle model.
- Certificates: every small support is checked exactly; rational intervals cover
  larger supports. All twelve degrees are re-derived under the 416-bit event cap.
  Old 288-bit budget and enlarged 272-bit seed universe fail the target checks.
- Padding/masks: same exact powers of four and fixed circle base; no padding rule.
- Determinism: fixed v2 domain/order, sorted distinct neighbors, zero coefficients,
  cap rejection and full regeneration. No caller query/seed-length options.
- Parity: new digest vectors and independent row/dense-map checks pass. Exact toy
  all-seed probabilities and retained quantum counterexample check the boundaries;
  they are not a numerical proof for the full seed universe. No Rust/GPU parity.
- Cost model: n=256 grows from 7424 to 9728 sparse edges; exact operation counts,
  not a performance claim. O(n) work/storage and caps remain; no weight-pass change.
- Verifier: production unchanged; resource policy and authenticated admission still
  required. Legal zero-edge raw maps remain an explicit counterexample to parsing
  as certification and are outside the regenerated-source premise.
- Glossary: setup distance, proximity, codeword validity and FS/H remain separate.
  Ideal-oracle probability is not a proven property of concrete BLAKE3.

I tried to break it by substituting a v1 setup identity, and the control check_setup
rejected it with InvalidSetup. Changing the event budget back to 288 bits also
fails the exact all-seed target inequality. The stronger parameters address the
setup-selection gap under the stated model; they do not certify a treaty profile.
