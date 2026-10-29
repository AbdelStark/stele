# Q26 scale alignment and tied-storage research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. Research evidence only; no
Accepted CQIS behavior changes. E5-03 remains blocked on its complete contract.

Workflow 03 checklist:
- Public items: research-only combined-scale and residual arithmetic. No core
  API, scalar Requant limit, weight/plan byte format or existing inference changes.
- Challenges: none. Fixed test seeds never enter a production transcript.
- Claims/consumers: none emitted. The derived shared tensor is an arithmetic
  fixture, not authenticated source/role/tie authority or a checkpoint proof.
- Bindings/controls: no new catalog credit. Zero-scale consistency, exact target
  ranges and metadata reject locally; actual attained/source/scale/certificate
  consumers and NC-0102/0109 remain required.
- Ledger: no challenge, label, loss or profile line changes; accounting retained.
- Bounds: int32 accumulator times two positive 16-bit mantissas has magnitude
  strictly below 2^63. Aligned int16 residual sums have magnitude at most 2^46.
  Right shifts >=64 are exactly zero; nonzero left shifts >15 cannot fit int16.
  NumPy range checks precede left shifting; uint64 quotient/remainder avoids
  biased-sum overflow. These are capacity facts, not field-faithfulness proofs.
- Padding/masks: none introduced. Canonical storage axes, operation layouts and
  source/tie aliases still require explicit authenticated artifact/plan fields.
- Determinism: exact integer/rational arithmetic and one half-away rounding;
  explicit modes/exponents, no clipping or data-dependent fallback.
- Parity: exact and NumPy arithmetic agree on 20,000 scale and 10,000 residual
  decisions. 10,000 tied-role examples reuse the same int4/int8 weight record.
  Boundary products/shifts, signed ties, cancellation and type failures are
  explicit. No native inference, GPU, model-fidelity or source-binding claim.
- Cost: preparation and future c_a scale/range work identified. No extra weight
  tensor/commitment, fitted constant, benchmark or weight-pass change is claimed.
- Verifier: unchanged no_std implementation/dependencies. NumPy is harness-only.
- Glossary: numerical conversion, source authentication and static bound
  certificates are distinct; a weight exponent is not a Requant right shift.

I tried to break it with a nonzero accumulator at dynamic scale zero, scale zero
in static mode and an overflowing positive signed left-shift endpoint, and the
control `rejects` in check_alignment.py rejected it for ZeroScale/InputScale/
Overflow. These are research checks, not production negative controls. The exact
rounding and transpose counterexamples require explicit future RFC choices.
