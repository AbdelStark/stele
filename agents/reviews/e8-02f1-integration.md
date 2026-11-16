# E8-02f1 integration and parser review

Reviewer: codex-root, using the soundness-auditor skill. Scope: integration of
#381 with main at `0bdde641`, and the UTF-8 correction below. The original
independent protocol review and its fixes remain recorded in ADR-130. This is
not a new independent derivation of the replay.

## Finding and correction

RFC-0026 A15 §1 defines `str` as length-prefixed UTF-8; §5 uses it for every
relation name. The decoder checked lengths but treated names as arbitrary bytes.
`rejects_non_utf8_relation_names` failed before the correction: a group name
containing `0xff` decoded successfully. It now rejects malformed names in every
named relation list, including all column kinds, with `StatementMismatch`.
The verifier entry point rejects them before reading a proof. A valid non-ASCII
group name still decodes. One shared `name` reader validates all eight call sites.
The native gate requires the regression by name and pins the corrected sources.

I tried to break it by replacing each relation name with non-UTF-8 bytes, and the
control `rejects_non_utf8_relation_names` rejected it.

## Checklist

- Public items: unchanged; the private name reader implements A15 §§1,5.
- Challenges: unchanged. A15 §6.4 fixes the statement and source roots before
  identities, lookups, matmuls and source openings. No new absorb or draw.
- Claims: unchanged; identity, lookup and matmul claims go to source openings or
  the public-column MLE check. The opening consumes the claim batch's point.
- Bindings: no new binding or NC id. Existing forged-table/public windows target
  `TableDenominatorMismatch` and `PublicMismatch`; the new control targets the
  existing canonical string requirement.
- Ledger: no changed line or bound; native includes the accounting gate.
- Bounds: no new instance; `Plan::derive` still validates the relation first.
- Padding: no changes to member selectors, table padding or zerochecks.
- Determinism: UTF-8 validation has no iteration-order or backend dependence.
- Parity: honest proof bytes are unchanged. Lucid H100 validation of the preceding
  integration tree accepted the honest windows and rejected the forged windows;
  final-tree proof replay remains required by native CI.
- Cost model: no constant or performance claim. Name validation reads each name
  once and allocates nothing beyond the existing decoder.
- Verifier: `no_std`; `core::str::from_utf8` returns a typed error, with no panic or
  new allocation. Plan-derived proof lengths are unchanged.
- Glossary: no protocol vocabulary changes.
- Tier: development only. The caller must still supply a trusted relation and
  `cqis_id`; this change does not close E8-02f2.
- Commit rule: unchanged; no column or source added.
- Plain checker: unchanged; the correction is confined to the independent decoder.
- Segments: none added or changed.
- Proof bytes: unchanged; only malformed relation encodings lose acceptance.
- Ladder: L0/L1 dump-and-replay parity is required by the native gate; there is no
  benchmark comparison or performance claim in this change.
