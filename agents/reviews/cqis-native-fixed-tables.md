# Native fixed table generation review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2.2-2.3,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: immutable Table with range and rsqrt constructors, complete signed
  row access, canonical encoding and full expected-definition validation. No
  untrusted rows can construct a Table; descriptors alone still admit no data.
- Challenges: none; existing ordinary descriptor BLAKE3 is unchanged.
- Claims/consumers: generated integer data only. Validation against an immutable
  generated table supplies no model authority, membership, claim or proof receipt.
- Bindings: no claim-graph edge. Entry/id/shape/padding/field-alias tests are native
  primitive checks; NC-0412/0413/0414 remain pending their actual consumers.
- Ledger: no loss, label, profile or H/FS budget change.
- Bounds: range entries fit i32. Rsqrt uses the specified integer isqrt and exact
  midpoint inequality, with checked u64 threshold arithmetic. Every mantissa is
  independently checked by bisection and its final rounding-cell inequalities.
- Padding: all 16,384 padded rsqrt rows contain two zeros. Range tables have one
  column and no padding. This does not establish a valid-row proof selector.
- Determinism/parity: complete canonical data digests match independent Python
  vectors for all four tables; every header field and integer entry is checked.
  Other generators, function/manifest bytes, NumPy and MLE gates remain E5-02.
- Cost: complete generation and validation are linear in stored entries; no
  measurements, fitted constant, extra weight pass or committed intermediate.
- Verifier: no_std, no unsafe/floats. All owned buffers use checked lengths and
  fallible reservation before initialization. Capacity/parameter errors return
  no partial table or encoding. Validation checks expected length before reading
  headers, uses immutable borrowed bytes and performs no allocation. Private
  table state and readonly entry access prevent mutation after generation.
- Glossary: integer bytes and M31 representatives are distinct; a field-congruent
  alias is rejected even though it could yield the same field commitment.

Tests were written first and failed on the missing Table API and data errors.
The full tables, all 49,152 independent rsqrt rounding checks, canonical bytes,
malformed metadata/lengths, one-value entry/padding mutations, integer aliases,
invalid ranges/mantissas and impossible owned capacities pass. Rejection leaves
the generated table and its subsequent encoding unchanged. No allocation-failure
flag, verifier bypass or configuration-control exception was introduced.

I tried to break it by changing one table value, padding cell or authority field,
substituting a field-congruent integer and requesting impossible capacities, and
the control checks in the native table tests rejected those inputs. These tests
earn no catalog coverage. Full native E5-02 and downstream proof delivery remain.
