# Field preparation review

Codex-root applied pcs-engineer. A separate read-only soundness-auditor approved
the prover preparation slice after checking the shared fixture corpus and gates.
This is internal agent review. Full repository gates remain queued.

- Public items implement RFC-0010 A9 §§1,6,9. Source::code exposes the already
  validated Circle map. Tree::owned_bytes reports actual owned node capacity.
- No challenge or transcript schedule changes. Prepared bytes emit no verified
  claim, certificate handle or profile decision.
- Both-field tests authenticate every generated column against independent
  roots. A changed message element rejects with RootMismatch; no NC credit follows.
- No probability term changes. The caller's hash record counts all constructed
  Merkle nodes and remains observable after failure. The full accounting gate
  is pending with the other required repository gates.
- Dimensions and allocation products are checked; there is no implicit logical
  padding. Circle codeword length remains a power of two.
- Row order, transposition and field serialization are deterministic. The six
  native/Python fixture cases pass; GPU code is unchanged.
- Resource observations include full encoder scratch, column storage, leaf
  references and Merkle nodes with their actual overlap. Borrowed message bytes
  are separate. Later response paths belong to their consuming operation.
- The code remains no_std with unsafe forbidden. Invalid response indices fail
  before path allocation or slicing. Original input is immutably borrowed.
- Registration encoding and hashing affect c_c/T_misc. No measured constant or
  matmul weight-pass change is claimed. Full E4-03a benchmarks remain required.
- No conflicting glossary terminology was found.

Review caught removal of the two inherited compile-fail producer requirements.
The corrected gate matches all three successful compile-fail filenames without
depending on source line numbers. A regression deletes each required producer
from actual test output and requires rejection before the next validator.

I tried to break it by changing a message element, requesting invalid response
indices, overflowing hash usage and deleting required test producers, and the
preparation fixture controls, rejects_preparation_shape_and_hash_overflow and
gate regressions rejected it.
