# Q26 actual source-file research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. E5-03 remains blocked.

Workflow 03 checklist:
- Public items: research single-file source reader, explicit selection descriptor
  and preparation against an expected raw-file hash; Draft RFC-0004 A3/RFC-0011.
- Challenges: none. SHA-256/BLAKE3 are deterministic research identity checks;
  production hash-query accounting remains required with actual consumers.
- Claims/consumers: none. Caller-supplied expected hash/config is not authenticated
  publisher or passport authority. Source reproduction does not prove commitment.
- Bindings/controls: local metadata/selection/hash/finite-source checks only; no
  catalog credit. Full source/plan/PCS/wrapper/certificate consumers remain required.
- Ledger: no transcript label, loss or profile changes; accounting gate retained.
- Bounds: exact u64 products and bit lengths, byte-aligned spans, header limit,
  full coverage before exposing payloads. No static field certificate is supplied.
- Padding/masks: source header bytes are hashed exactly, not normalized; inner
  quantised record padding is retained. No proof mask or commitment added.
- Determinism: explicit source names/dtypes/shapes and ignored set, no alias guess,
  clipping or fallback. Upstream multi-key annotation iteration initially changed
  corpus bytes; fixed single-key fixtures plus explicit alternate-order tests
  separate reproducibility from exact original-file hashing.
- Parity: 10,000 files match pinned upstream raw tensor extraction and artifacts
  derived from retained arrays; all nineteen structural dtypes checked separately.
  No model inference, native/GPU or fidelity claim follows from parsing.
- Cost: preparation/source hashing identified; whole-file/array research storage
  retained, no native streaming/performance or inference weight-pass claim.
- Verifier: no core/no_std/dependency changes. Complete expected configuration
  authority and sharded-source digest semantics remain required.
- Glossary: structural container validation, finite quantisation, published source
  identity and actual commitment binding remain separate obligations.

I tried to break it by overlapping source offsets, substituting BF16 for expected
F16 and changing header padding under the original digest, and check_source.py
rejected those cases for Offsets, SourceMetadata and SourceDigest. Nonfinite data
can pass container parsing but selected preparation rejects it for Nonfinite.
These research checks are not production negative controls or independent audit.

Additional integration: a pinned public tiny-random-gpt2 checkpoint matches its
published raw-file SHA-256 and fixed expected shapes. All 64 tensors are prepared
and compared with independent upstream extraction, with no ignored parameters.
Precision/axis choices are fixture data; full GPT-2 forward semantics/fidelity and
proofs remain open. The external fixture is hash-checked in CI, not model code.
