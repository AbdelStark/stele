# RFC-0011 — Model passport and checkpoint binding

Status: Accepted · Version: 0.1.0 · Depends: RFC-0004, RFC-0010

## 1. Contents (`passport.json` + binary artefacts), `passport_root = H(all fields)`
1. `cqis_id`, model configuration (shapes, formats, table ids, scale exponents), `plan.json` digest.
2. Weight commitments: per type `τ` the Merkle root, layout, code parameters, element format; scale tensors in plaintext.
3. Table commitments (every registered table as an interleaved-code matrix) for wrapper-mode openings.
4. **Proximity certificate** (optional, treaty: required): a transcript proving each committed matrix is within the
   proven proximity radius of an interleaved codeword, with randomness derived from the roots (one-time, RFC-0010 §5).
5. **Checkpoint binding proof**: a proof that the committed plaintext (packed int8 weights + scales, canonical
   serialisation `cqis-weights-v1`) hashes to `digest_cqis`, and that `digest_cqis` was produced from the published
   checkpoint `digest_hf` (SHA-256 of the safetensors) by the public quantiser `quantiser_id`. v0.1: the quantiser step is
   reproducible, not proven (anyone with the HF checkpoint can recompute `digest_cqis`); the hash binding of the commitment
   to `digest_cqis` is proven in the wrapper (SHA-256 or Blake3 in-circuit, one-time, RFC-0016 §6).
6. **Fidelity report** (RFC-0004 §8) with item-level hashes so it can be re-run.
7. Registration metadata: registrant identity, timestamp, signature(s); optional registry transaction reference.

## 2. Lifecycle
`quantise → commit → certify → bind → evaluate → publish`. Any change to weights or CQIS version is a new passport.
Proofs reference `passport_root` in their public input; verifiers cache passports.

## 3. Cost (one-time, per model)
Encode + Merkle 4·10¹¹ elements with circle RS: ≈ 2^39 · 39 butterflies ≈ 10 GPU-minutes; hashing ≈ 1 GPU-minute;
proximity certificate ≈ one weight pass; checkpoint binding ≈ hashing 400 GB in-circuit ≈ 10³–10⁴ GPU-s (Blake3) or
10× more (SHA-256). Negligible against the model's lifetime.

## 4. Confidentiality
The passport reveals shapes and scales only. Treaty registrations may encrypt scales to the verifier set; the ZK
argument (RFC-0013) keeps weight values hidden through all openings.

## 5. Hooks for traffic binding (out of scope, interface only)
`io_digest` may be replaced by `(input_commitment, output_commitment)` with openings held by a certifier; the proof
statement is unchanged. A `session_id` field allows multi-turn chaining (RFC-0017 §9).

## 6. Negative controls
NC-0700 passport root mismatch; NC-0701 table commitment swapped; NC-0702 certificate for a different root; NC-0703 scale
tensor altered after registration.

## 7. Amendment log

### A1 — Confidentiality across a fixed passport's lifetime

Status: Draft. Question Q29. Companions RFC-0013 A1 and RFC-0010 A7.
Evidence: [mask lifetime and fixed-oracle analysis](../../formal/commitment-privacy.md).
Motivation: a mask row committed in a passport is fixed with its root. Fresh
proof challenges cannot refresh it, and raw coordinate disclosures accumulate.

Proposed addition to §§2,4:

> Specify the complete confidentiality lifetime of each committed weight oracle,
> including its certificate and every later opening. Any query-bounded masking
> argument must count the cumulative disclosures to that same oracle. Fresh
> session identifiers, seeds or challenges do not change its committed mask.
> A mask refresh must bind the unchanged source to the resulting commitment and
> justify certificate reuse or replacement. Its source reads, registration work,
> storage and per-proof costs require explicit accounting. Alternatively specify
> a protocol hiding the queried payload itself. Neither path is selected here.

The original checkpoint/source binding, public statement, privacy goal and
one-weight-pass requirement remain. No new root, seed API, certificate format,
loss or profile is admitted. Costs and possible protocol losses depend on the
complete replacement; no measured constant changes. Affected tasks: E4-05,
E4-06, E10 passport/inference and E12 privacy/certificate consumers.
