# Packing contract study review (Q28)

Reviewer: codex-root, also author. Same-author pcs-engineer, soundness-auditor
and rfc-author passes, not independent review or protocol approval. RFC-0010 A6,
RFC-0007 A1 and RFC-0008 A1 remain Draft. Original acceptance criteria remain.

The cardinality contradiction and both concrete M31 collision pairs are exact.
The fused example uses supported source values and a valid tensor point; it
demonstrates different original functionals with the same packed row value,
not two openings of one root. No computational security theorem is assumed.

Workflow 03 checklist:
- Public items: research codec only; no production API or admitted layout.
- Challenges: none; the chosen algebraic point is a counterexample, not FS.
- Claims/consumers: private range/sign/fragment/position/padding and fused source
  consumers remain required. Reversible encoding of revealed values is insufficient.
- Bindings/controls: same-integer invalid-digit and fused-vector counterexamples;
  malformed width/range/shape, 112 tail-bit and 120 padding-word rejections.
  These are research checks and do not earn NC-0603/0605 credit.
- Ledger: no production loss, label or profile changes. Future reduction losses
  must be specified before implementation; the codec does not certify proximity.
- Static bounds: every candidate packed word is at most 2^30-1<p/2; its count
  comes from shape/format. Actual verifier-recomputed certificates remain open.
- Padding: exact expected C is separate from the supplied word count; decoder
  rejects extra zero words, truncation, nonzero tail bits and nonzero code padding.
- Determinism: exact source/bit/row order, fixed shape and no value-dependent size.
- Parity: 87,042 byte-oracle/round-trip cases pass, including all signed int8/int16
  scalars. This is not Rust/extension/GPU or proof-byte parity.
- Cost: derived symbol counts and bounded-accumulator work only; all packing,
  decomposition, code padding, consumer state and weight reads need native ledgers.
- Verifier: no core/no_std change. Shape and budget errors are checked in research;
  native allocation/overflow and trusted descriptor derivation remain requirements.
- Glossary: existing claim, functional opening, bound certificate and source terms.

I tried to break it by accepting extra zero words and nonzero unused high bits,
and the control check_rejections rejected both inputs. Removing each corresponding
check in an isolated mutant caused its targeted rejection case to fail for the
named reason.
Review corrected an earlier prototype that inferred C from supplied data.

Recommendation: retain the explicit A3/A6 and fused-contract task blocks and
continue with the complete authenticated decomposition/one-pass schedule. Do not
promote this codec to a replacement for any missing proof consumer.
