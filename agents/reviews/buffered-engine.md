# RFC-0006 A1/A6 caller-buffer engine review

Reviewer: codex-root, also the author; sumcheck-prover-engineer and
soundness-auditor passes. Not an independent audit. Scope: caller-owned A1 proof
and absorb buffers, shared serialization/checks, Dense overrides and gate coverage.

- Public items/RFC: Instance encoded_len/encode_into, message_size/bytes_into,
  prove_into and Summand into methods implement A6's preallocated A1 path.
  Allocating wrappers remain compatible; default strategy methods still allocate.
- Challenges/absorbs: validated Instance prefix, each delta+1 Round prefix before
  its Sumcheck challenge, then all Final values. Only written bytes are absorbed.
  Shared round/final helpers preserve endpoint and final polynomial checks.
- Claims/consumers: verify_public consumes every original Dense input at the same
  challenge point, including unused inputs. Buffer ownership supplies no binding.
- Bindings/controls: no new claim edge. Existing A1 controls stay required; the
  new both-field test changes exactly one unused final after an honest acceptance
  and requires ClaimMismatch. NC-0210 remains todo until the real source strategy.
- Ledger: no new challenge, label or loss; A1 m*delta/p^d is unchanged. Tests
  compare SC numerator/field and continuation. Q12 remains unresolved.
- Certificates: no integer identity or new bound certificate; size arithmetic is
  checked and Instance validation bounds ordinals/degrees before serialization.
- Padding/masks: no inference padding/mask change. Oversized scratch suffixes
  must not enter the transcript; a gate regression mutates this exact boundary.
- Determinism: fixed term/column/node order, exact field arithmetic and no hash
  iteration. Dense recomputes factor folds directly to avoid a temporary vector.
- Parity: 1,000 seeded cases per degree 0..4 and QM31/OM31 compare complete Dense
  and buffered proofs, public decisions and continuations. Independent existing
  Python corpus/digests are required because the engines share codecs/checks.
  There is no CUDA change or new CPU/CUDA performance claim.
- Capacity: caller proof/byte pointers and capacities stay fixed. Engine code
  does not allocate; Dense overrides avoid the default allocating trait methods.
  This is not a total capacity or process-memory certificate. Source/workspace,
  descriptor, transcript, preparation and consumer lifetimes remain to be measured.
- Cost model: removes engine frame/interpolation and Dense endpoint temporaries
  from c_sc/T_misc work. Direct factor recomputation may add arithmetic; no fitted
  constant, throughput or total-memory improvement is claimed without a ledger.
- Verifier: still no_std, same validated proof lengths and original consumers.
  The shared interpolator accepts the same 1..61 nodes with field denominators;
  existing A1/batch/zerocheck/Small tests cover its callers. Short/invalid buffer
  inputs fail before transcript mutation; later failures discard the attempt.
- Glossary: no new cut, authenticated source, profile or committed intermediate.

I tried to break it by changing one unused final value, and the control
rejects_buffered_unused_final_value rejected it with ClaimMismatch in both fields.

Sign-off is conditional on all required local and exact-head hosted gates.
This review does not complete E3-05 or replace independent cryptographic review.
