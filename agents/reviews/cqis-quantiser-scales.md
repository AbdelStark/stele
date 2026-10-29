# Q26 exact scale-policy research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. Research evidence only;
RFC-0003 A2 / RFC-0004 A3 remain Draft and E5-03 stays blocked.

Workflow 03 checklist:
- Public items: research-only weight/dynamic/static candidates and exact oracle.
  No Accepted protocol, core API, scalar Requant or checkpoint bytes are changed.
- Challenges: none. Seeded research inputs are not transcript challenges.
- Claims/consumers: none emitted. Configured modes/formats/scales and attained
  maxima still require their actual plan/passport/proof consumers.
- Bindings/controls: no production edge or catalog credit. NC-0102/0109 remain
  real-consumer obligations; a numerical helper is not a proof verifier.
- Ledger: no loss, transcript label or profile term changes; gate retained.
- Bounds: exact source-format, mantissa, exponent and output bounds are proved
  in the candidate note. Runtime maxima choose dynamic scales, never static
  certificate limits. Narrow symmetric ranges need future explicit enforcement.
- Padding/masks: none introduced. Nonempty rectangular weight channels and
  nonempty int16 input rows are required. Native resource admission remains open.
- Determinism: integer/rational operations, explicit int4/int8/static selection,
  half-away ties, fixed zero policies and no saturation or implicit calibration.
- Parity: independent bisection/neighbor-distance choices match 20,000 weight
  tensors plus 10,000 dynamic and 10,000 static rows. No native/NumPy/GPU or
  model-fidelity credit. The oracle's endpoint search was corrected to include
  s=259 after the explicit int16 boundary exposed its off-by-one bound.
- Cost: preparation and future c_a work identified; no fitted constant,
  benchmark, commitment or additional weight pass.
- Verifier: unchanged no_std implementation and dependencies. Research-owned
  arrays and rational arithmetic do not authorize a native allocation policy.
- Glossary: format bounds, configured scales and static bound certificates are
  distinct; a weight exponent is not the scalar Requant right-shift parameter.

I tried to break it with X=-32768 at static scale 257 and with zero/oversized
configured scales, and the control `rejects` in check_quantiser.py rejected it
with Overflow/Scale. Independent inequalities check every output and scale choice.
These are research controls only. Native conversion, canonical configuration,
residual alignment, full certificate schemas and actual consumers remain open.
