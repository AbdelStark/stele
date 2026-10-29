# Q26 physical tensor record research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. RFC-0004 A3 remains Draft;
E5-03 remains blocked on the complete quantiser/static-certificate contract.

Workflow 03 checklist:
- Public items: research-only tensor Spec/config, preparation and checked physical
  record codec. No core API, Accepted artifact, PCS packing or operation admitted.
- Challenges: none. The deterministic corpus seed is not a transcript challenge.
- Claims/consumers: none emitted. Parsing checks independently expected metadata,
  not source derivation, shape admission, quantiser identity or authenticated roles.
- Bindings/controls: no catalog credit. Local config/padding/range/truncation checks
  do not replace actual source/plan/PCS/certificate consumers or NC-0102/0109.
- Ledger: no challenge, transcript, loss or profile change. Accounting gate retained.
- Bounds: source significands fit 53 bits; int16 gain conversion is checked before
  returning any record. Shape/source/payload sizes use explicit u64 bounds. These
  are capacity/arithmetic facts, not static field certificates or proof ranges.
- Padding/masks: only the last unused int4 nibble is zero; no row/channel padding,
  PCS message, virtual padding selector, new commitment or ZK mask is introduced.
- Determinism: exact source decoding, canonical row-major axes, explicit scales,
  immutable Spec and fixed field order; no host floats, clipping or silent fallback.
- Parity: 20,000 weight tensors match independent complete encodings; 10,000 wide
  tensor decisions match exact arithmetic and NumPy. Signed limits, precision,
  maximum shape/length, malformed metadata and final nibble cases are explicit.
  There is no native quantiser, GPU, checkpoint-origin or model-fidelity claim.
- Cost: preparation work/storage identified, no measured constant or benchmark.
  Research materializes arrays; native streaming/resources remain required.
  No inference weight-pass or commitment count changes.
- Verifier: core no_std code/dependencies unchanged. Expected config must eventually
  come from the full authenticated contract; the caller cannot self-authorize it.
- Glossary: source bytes, physical quantised bytes, committed field packing and
  bound certificates remain distinct. No complete cqis_id/passport is supplied.

I tried to break it by changing the unused high nibble, source dtype, channel axis,
and mantissa to zero, and the check_records.py controls rejected them for Padding,
Config, Config and Scale. Every strict truncation of the hand vector rejects for
Truncated. A legal payload mutation is intentionally still decodable, but differs
from exact source regeneration; syntax alone is not authenticated checkpoint binding.
These research checks and this same-author review provide no production NC credit.
