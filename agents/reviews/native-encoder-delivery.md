# Native bounded encoder delivery audit

Task E4-08, RFC-0010 A4/A5; branch task/E4-08-native-evidence. Same-author
pcs-engineer/owner, benchmark-runner and soundness-auditor review by codex-root,
not an independent audit. E4-08 remains in progress pending gated merge.

## Contract coverage

1. Closed Encoder and CodeField/Code factories, exact identity/field/size checks,
   no_std and unchanged Circle behavior: native tests, external implementation
   positive/compile-fail controls and no-default-features build pass.
2. Full canonical words and ordered queries: the real digest gate checks 1006
   words per field at J=3/4/5 against the materialized Python map. Independent
   dense/base studies and the regenerated benchmark base fixture remain separate.
   Zero/boundary/full-extension inputs and linearity are covered.
3. Native rejection: malformed/truncated/suffixed IDs, wrong row/column/field,
   requested capacity overflow, empty requests, cap/last-word boundaries and
   outer/inner/late exhaustion are tested. Zero coefficients are retained, every
   zero row generates its streams, input survives failure and no partial result
   is returned. Gate mutations reject missing corpus/tests, changed digest/query
   order, removed field seals and omitted memory overlap. No new NC credit.
4. [Clean-source ledger and report](../../bench/README.md#bounded-native-encoder-e4-08):
   all J=3..10 sizes, every supported field, three samples each; full preparation,
   generation/encoding/query and independent exhaustive validation. Actual logical
   counters, owned capacity liveness, caller buffers, inline layouts, compiler
   native/hash frames and whole-process peaks have explicit separate scopes.
   The frame inventory is not a whole-process stack bound; RSS covers the complete
   worker including stack/runtime and validation. No setup amortization, skipped
   samples, extrapolated peaks or fitted constants. Native size arithmetic covers
   every supported dimension without huge allocations, independently of counters.
5. Local workspace/tests, Clippy, fmt, no_std, bans and all applicable gates pass.
   Hosted CI is required before merge. GPU code is unchanged; no GPU result is
   inferred. Existing statement coverage remains 3/17 bindings and 14/72 controls,
   with one separate configuration control.

## Soundness, determinism and cost

The encoder adds no proof claim, consumer, transcript challenge, soundness loss,
integer certificate, padding rule or committed tensor. Observations never affect
map selection or admission. All canonical coordinates, caps, fields and output
order stay fixed. E4-01/A1 registry/distance/setup authority, E4-03/A3 openings,
A7 composition, ZK and the complete inference statement remain outstanding.
The ledger supplies c_c/T_misc observations with no fitted constant or weight-pass
change. Native memory figures exclude stated process categories and are never
accepted as resource or profile certificates.

I tried to break it by omitting work, output validation, query copies and live
capacity from actual worker receipts, and the control receipt tests rejected it.
The real digest gate also rejected omitted simultaneous allocation overlap.
No benchmark or arithmetic control is counted as an inference binding control.
