# Q26 ordered artifact research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. E5-03 remains blocked.

Workflow 03 checklist:
- Public items: research preparation identity, ordered composition/parser and
  content hash, scoped to Draft RFC-0004 A3 / RFC-0011. No native artifact admitted.
- Challenges: none; BLAKE3 here is deterministic research content/metadata hashing,
  not a transcript challenge. Production hash accounting remains required.
- Claims/consumers: none; independently expected Specs are a prototype input,
  not authenticated plan/passport authority. No proof acceptance is manufactured.
- Bindings/controls: local framing and set checks only, no catalog credit. Source,
  tied roles, PCS packing, certificate and wrapper consumers remain required.
- Ledger: unchanged labels/challenges/losses/profiles; accounting gate retained.
- Bounds: u32 count and record config lengths, checked u64 record/artifact sizes;
  native allocations/streaming and static field certificates remain separate.
- Padding/masks: inner record rules retained; outer frame has no padding, mask,
  PCS matrix or new commitment. Equal-size duplicates still mismatch expected names.
- Determinism: exact name sorting, immutable record snapshot, fixed algorithm
  version and framed BLAKE3; no map iteration order or implementation callback.
- Parity: independent outer codec checks 10,000 mixed artifacts; prior record
  evidence checks inner arithmetic. No new native/GPU/fidelity or hash-theorem claim.
- Cost: metadata and preparation/hash work identified, no fitted constant or
  benchmark. Chunk emission does not establish native streaming or fewer proof reads.
- Verifier: unchanged no_std code/dependencies; complete expected-source/config
  authority must be supplied by the future admitted contract.
- Glossary: quantiser preparation identity, content digest and complete CQIS/plan
  identity are distinct; actual safetensors digest_hf is not fabricated from a map.

I tried to break it by duplicating an equally sized record and changing its expected
channel axis, and check_artifact.py rejected them for Config and Quantiser. Missing,
extra, reordered and truncated records also reject. A legal value mutation remains
parseable and changes only the content digest, correctly preserving the separate
source regeneration/proof obligation. These tests are not production NC controls.
