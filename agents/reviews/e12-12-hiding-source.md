# E12-12 hiding Circle source review (RFC-0013 A2 item 1, RFC-0010 A15)

Reviewer: claude-code, also the author. Same-author pcs-engineer and
soundness-auditor passes; an independent review is still needed.

## What changed

- `stele-hash::mask`: the keyed BLAKE3 mask stream of A2 (contexts
  `zk/source-mask`, `zk/source-salt`, `zk/sumcheck-mask`). Prover-only.
- `stele-pcs`:
  - `Source::hiding` adds version-3 bytes and the A15 admission
    (`R ≥ 2D`, `q_c + q_o ≤ C − 1`).
  - The leaf width is `32 + 4·2R`, and the verifiers decode after the salt.
  - `hiding_message` builds the A2 layout.
  - `PreparedSource::hiding` writes salted leaves.
  - The certificate and opening producers run the A2 rank check and abort with
    `MaskRank`.
- The A9 arithmetic, the query policy and the version-1/2 bytes are unchanged.
  The existing fixtures and corpora still pass.

## Pass 1 — soundness-auditor

- Challenges: none added. The certificate public input contains the version-3
  bytes, so the hiding layout is bound before `CertificateWeight`.
- The salt is authenticated with the payload and never decoded. NC-0902 flips
  one salt byte of an honest certificate, and the actual verifier rejects it
  with `RootMismatch`.
- Admission: NC-0903 lowers `ell` (so `R < 2D`) or `m` (budget above `C − 1`)
  in the expected bytes. `Source::from_bytes` rejects both with
  `UnsupportedSource` before any transcript work.
- The verifier decodes `payload[salt_len..]`. `parse` fixes the payload width
  from the expected source, so a short payload is `ProofShape` and the slice
  cannot panic.
- The rank check sits only in the producers. Skipping it cannot make the
  verifier accept anything new.
- Independent review finding (fixed): the first version checked rank only on
  the certificate and the current opening, and kept no opening count, so a
  source could be opened twice. Three revealed row combinations give `3D` rows
  over `2D` dimensions, `S0` cancels, and functionals of `X` leak; the query
  budget is exceeded too. `PreparedSource` now counts openings of a hiding
  source through every path (point, functional, retained row) and refuses a
  second with `MaskBudget`, before any transcript work. Tests cover both paths;
  NC-0906 records the refusal (a producer control, not a verifier binding).
- NC-0902 now also flips a salt byte of an opening response; the actual
  opening verifier rejects it with `RootMismatch`.

I tried to break it by flipping a salt byte and by offering a context outside
admission, and the controls NC-0902 and NC-0903 rejected them. I also tried to
open at `W = 0`. The producer refused with `MaskRank`
(`accepts_hiding_certificate_and_opening`).

## Pass 2 — privacy evidence

- `accepts_masked_opened_values_and_rejects_unmasked` takes, for 96 seeds, one
  opened column symbol and the first limb of the certificate row, for the zero
  secret and for the all-one secret.
  - Masked, every top-3-bit histogram passes a χ² test (7 degrees of freedom,
    bound 30).
  - With the masks zeroed, the zero secret shows only zeros and the one secret
    does not, so the test detects the leak.
- This is statistical evidence for Lemmas 1–2, not a proof.
- The exact rank evidence is `crates/stele-code/tests/hiding.rs`.
- Not covered: weight lifetimes, repeated openings, seed reuse (NC-0901), and
  every composition item R1–R13.

## Checklist

- RFC: RFC-0013 A2 item 1, RFC-0010 A15 items 1–4.
- Challenges: unchanged.
- Claims: an opened value is a functional of `M'`; it has no consumer.
- Controls: NC-0902 (certificate and opening salts), NC-0903 and NC-0906 are done.
- Ledger: unchanged (the A9 terms at `(m + 1, b)`).
- Determinism: masks and salts are fixed functions of the seed and id.
- Parity: no GPU.
- Cost: no constant moves.
- Verifier: still `no_std`. There is no new dependency (`blake3` was already a
  `stele-hash` dependency).
- Gate: `scripts/gates/check.py` admits the new reviewed PCS API items and the
  `zk.rs` control module.
- Glossary: A2 terms only.
