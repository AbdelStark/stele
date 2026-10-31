# Hash-work observation review

Codex-root applied pcs-engineer. A separate read-only soundness-auditor reviewed
the local work counters and their controls. This is internal agent review;
complete repository gates and PCS consumers remain pending.

- Public API: HashUsage, Transcript::usage and Merkle *_with_usage implement
  RFC-0012 A10 and native-field-pcs §9. Observations cannot authorize a proof.
- Challenges: no label, framing byte, absorb order or sampling rule changes.
  The existing both-field transcript vectors retain every state and challenge.
- Claims: this slice emits no proof claim or verified-certificate handle.
- Bindings: no new protocol edge or NC credit. Controls reject counter overflow,
  exhausted sampling, bad roots and failed batches; repeated queries count again.
- Ledger: counters report evaluations rather than distinct oracle queries. No
  adversarial cap or evaluated FS/H term follows. The full accounting gate is queued.
- Bound certificates: none added; existing Merkle shapes determine path work.
- Padding/masks: absent Merkle padding and every internal node count toward
  construction. Byte-column meaning and all ten fixture roots remain unchanged.
- Determinism: operation order and bytes remain deterministic. There is no
  timing, map iteration or external random source in the accounting.
- Parity: targeted transcript/Merkle fixtures pass. GPU code is unchanged;
  complete proof/backend parity is outside this slice.
- Cost: checked arithmetic adds to T_misc. No measured constant or weight-pass
  improvement is claimed; full E4-03a resource measurements remain required.
- Verifier: no_std, no unsafe code, no new transcript allocation. Every counter
  reservation is atomic and precedes its work. Structural errors hash nothing;
  authentication errors retain completed path hashes.
- Glossary: no conflicting terminology was found.

Review caught constructor length checks occurring after initialization hashing.
They now run before any hash, so constructor errors cannot lose work observations.
Both fields exercise overflow and all transcript KATs. The five usage tests also
check forced 64-word exhaustion and exact last-representable Merkle counts.
The gate tests reject missing or failed producers. Targeted Clippy and workspace
compilation pass; final full local gates remain queued on the committed source.

I tried to break it by overflowing transcript and Merkle counters and omitting
required test producers, and the controls
rejects_usage_overflow_before_unrecorded_work, rejects_merkle_overflow_with_usage
and the two gate omission regressions rejected it.
