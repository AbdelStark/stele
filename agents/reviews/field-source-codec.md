# Native field-source codec review

Codex-root applied pcs-engineer. A separate read-only soundness-auditor reviewed
the source codec, policy export and fail-closed gate changes. This is internal
agent review; certificate/opening verification and full repository gates remain
outside this scoped approval.

- Public items implement RFC-0010 A9 source context, finite parameters and
  unverified wire shapes. No accepting PCS API or certificate handle exists.
- No challenge is added and no verified claim is emitted. Canonical row parsing
  does not authenticate the responses; that remains their actual consumer's job.
- Parser tests reject wrong lengths/versions and noncanonical row limbs. All
  six complete fixtures match the independent oracle; no new NC credit follows.
- Ledger terms are unchanged. All 59 native N,D,e and query-count entries match
  independent integer calculations, including least-count checks.
- Dimensions are exact, with no implicit padding. A checked shift stores the
  row count, and checked products bound complete wire sizes before execution.
- Fixed bytes and ordered, repeated responses are deterministic. Full PCS or
  GPU parity is not claimed.
- Source construction and parsing allocate no domain or proof. No measured
  performance constant or weight-pass improvement is supplied.
- The codec is no_std with sealed challenge fields and private context fields.
  An unauthenticated response or public parameter tuple is never a receipt.
- The gate rejects extra public methods and trait conversions in the existing
  module, as well as added files/exports/dependencies. This is a reviewed API
  inventory and regression guard, not a semantic Rust sandbox.
- Existing unrelated bootstrap guards remain; glossary wording is unchanged.

Review found and corrected the unsupported-target row shift, incomplete native
geometry comparison and same-file API expansion gap. Four native tests, two
compile-fail checks, expanded native policy checks and the focused gate controls
pass. The scaffold/dependency checks and targeted Clippy pass after corrections.

I tried to break it by adding an accepting associated method and a
From<Source<K>> for bool conversion, and the control
test_rejects_unwired_accepting_api_and_dependencies rejected them.
