# Q23 code identity and registry review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author, soundness-auditor.
Not an independent audit. Decision: continue Draft A1 with the checked identity
boundary. E4-01 remains blocked on the complete native/PCS contract.

- Public items/RFC: formal/code-identity.md proposes a closed factory, sealed Code
  API and separate PCS parameters. Research resolution accepts exact identities,
  not raw setups, arbitrary implementations or caller-selected bounds.
- Challenges/absorbs: no challenge/label change. Future public containers must bind
  complete identity plus field; this study does not implement their transcript use.
- Claims/consumers: actual encoding derives the map from the ID. Metadata snapshots
  are not inputs. This supplies no polynomial opening or committed-source consumer.
- Bindings/controls: research rejects every changed catalog field, wrong types,
  missing/extra/reordered entries, old/unknown IDs, raw graphs and malformed rows.
  Invalid/empty requests reach no setup/FFT. No production NC credit is claimed.
- Ledger: no new error line. Circle distance is deterministic; v2 carries the
  existing ideal-oracle setup event. No proximity/query/profile error is fabricated.
- Certificates: dimensions, distance and setup bytes derive statically from IDs.
  No integer CQIS identity is introduced. Both PCS proven flags remain false.
- Padding/masks: exact supported dimensions, canonical field tuples, no padding,
  normalization of equivalent identities or fallback code.
- Determinism: fixed formats and explicit field, deterministic map selection and
  ordered duplicate queries. TOML whitespace/key order does not alter authority.
- Parity: thirty field/map cases; expander checked against independent dense/base
  oracle, circle against existing transform with its separate A2 evidence. All
  72 sizes resolve without generation. No Rust/GPU or maximum-size encoding run.
- Cost model: bounded registry/descriptor work in T_misc; full setup, encoding,
  raw copies and storage remain charged. No benchmark/weight-pass change.
- Verifier: production unchanged. The proposed sealed interface prevents arbitrary
  implementations from supplying trusted parameters. Native checked allocation
  and authenticated registry/plan/passport consumers are still required.
- Glossary: code identity, parameter metadata, distance, proximity and profile
  admission remain distinct. A false proven flag cannot be enabled by TOML input.

I tried to break it by flipping a catalog proven flag, and the control
validate_catalog rejected it with InvalidRegistry. A canonical raw graph also
rejects as InvalidCodeId. These are research interface checks, not PCS admission.
