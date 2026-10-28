# RFC-0006 A6 file source and NC-0210 review

Reviewer: codex-root, also the author; sumcheck-prover-engineer, soundness-auditor
and negative-control-author passes. Not an independent audit.

- Public items/RFC: opt-in std FileSource, prepare and IoCounts implement A6 §1.
  Default sumcheck stays no_std. File handles are opened read-only once; source
  ids borrow the descriptor. Construction/replay validate exact regular-file lengths.
- Challenges/absorbs: no new transcript operation. Files feed the existing bounded
  Streaming/A1 engine; canonical full-extension decoding never reduces malformed limbs.
- Claims/consumers: every original input remains an obligation. Path/handle metadata
  is not authentication; replay is an honest-source contract only. The actual public
  consumer rejects substituted original values at the same derived point.
- Bindings/controls: NC-0210 produces an honest real-file Streaming proof and checks
  acceptance first. One prepared record changes from zero to one; the original file,
  table and Instance stay fixed. A second real proof has equal rounds and exactly one
  unequal final. ProverHook installs that value into the honest artifact, and the
  unchanged original consumer must return ClaimMismatch in QM31 and OM31.
- Ledger: no label/challenge/loss changes. Both gates run the actual file tests and
  NC-0210, and require named successful tests. Catalog credit follows execution;
  independent streaming corpus and complete pipeline ledgers remain open. Q12 unchanged.
- Certificates: no CQIS integer identity. Checked record counts/bytes/offsets and
  counters protect resource arithmetic; canonical limb parsing uses the field decoder.
- Padding/masks: no inference padding. Preparation reads canonical row-major records
  and writes separate bit-reversed offsets; tests compare every prepared byte directly.
- Determinism: exact field bytes, fixed schedule/order and retained file handles.
  Path replacement does not reopen a new source. Owner mutation remains untrusted.
- Parity: real file proofs equal Dense and all original public claims/continuations
  in both fields, across empty, one-window and multiple-window schedules. No GPU change.
- Cost model: c_sc/T_misc and preparation I/O are now measurable. Counters report
  successful record I/O, seeks and EOF probes, not physical traffic or partial failed
  operations. Source reports its full file-vector capacity; borrowed ids, inline state,
  kernel handles, preparation and process memory remain separate. No benchmark claim.
- Preparation failures: create_new preserves existing destinations/originals. Errors
  attempt truncation/unlink of the new output; callers must discard it even if the
  filesystem rejects cleanup. Only successful preparation yields an authorized source.
- Verifier: unchanged no_std path, no bypass. Malformed limbs/lengths/EOF abort with
  Source; row shape errors use PublicShape. Empty input sets require no file access.
- Glossary: no authenticated-source claim, cut, profile or intermediate commitment.

I tried to break it by changing one unused prepared source value, and NC-0210
rejected the resulting real-prover final with ClaimMismatch in both fields.

Sign-off requires all local and exact-head hosted gates. E3-05 remains in progress
until independent streaming corpus and complete preparation/proving/consumer ledgers.
