# Native fraction codec review (E3-07a)

Reviewer: codex-root, also author. Same-author GKR, sumcheck, soundness-auditor
and RFC-author passes, not independent audit. Governing RFC-0008 A3 / RFC-0020 A4.
This delivery implements canonical descriptor and tree-proof types/codecs only;
E3-07a stays in progress with its engines, consumers, controls, corpus and ledgers.

Workflow 03 checklist:
- Public items: immutable Descriptor, unverified Proof, typed Error, exact codecs.
- Challenges/absorbs: none; production registry is unchanged. A9 requires the
  actual engine and accounting producer before adding its labels.
- Claims/consumers: none emitted or accepted. Parsing does not verify arithmetic,
  source identity, leaf values, poles, membership, privacy or a profile.
- Bindings/controls: native codec malformed-input tests, no NC-0406..0410 credit.
  They check all truncations/limb positions, trailing bytes and wrong dimensions.
- Ledger/certificates: no new random loss or integer identity; sizes derive from
  immutable validated m<=63 and sealed QM31/OM31, not proof counts.
- Padding/masks: field-order preservation only; engine consumers remain required.
- Determinism/parity: twelve genuine Python proofs compare complete decoded
  native fields, descriptor bytes and payloads in both fields, not just round trips.
- Cost: O(m^2) payload parsing/output and vector metadata, independent of 2^m;
  all constructor/codec allocations use checked fallible reservation. No runtime,
  process-peak, c_lu or weight-pass claim. Primitive ledgers remain required.
- Verifier: no_std; maximum depth decodes without source-domain allocation.
  Compile-fail checks exclude M31 targets and an unimplemented verification API.
- Glossary: existing descriptor, fraction, proof, source and claim terminology.

The actual native/Python producers replace only the lookup scaffold's codec
boundary in both gates. Unknown modules, changed public entrypoints/dependencies,
fixture drift and omitted OM31 tests fail; PCS/verifier and all other guards remain.
Bootstrap hashes are not updated to bless changed code. Downward dependency
permissions are exact; lookup-to-PCS/verifier edges are rejected through Cargo bans.

I tried to break it by corrupting each encoded field-limb position and adding
trailing bytes, and rejects_fraction_codec_boundaries rejected them with
NoncanonicalField and ProofShape. Native-field and Python-reference drift are
separate gate regressions. Full exact-head CI remains required before merge.
