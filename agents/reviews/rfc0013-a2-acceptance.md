# RFC-0013 A2 acceptance review (with RFC-0010 A14 and RFC-0012 A17)

Decision: accept A2, A14 and A17 at their conditional scope, under the owner's
authorisation for autonomous amendment acceptance after Workflow 02 review.
Reviewer: claude-code, also the author. Two same-author passes follow
(soundness-auditor, then rfc-author acting as the hostile privacy reader). This
is not an independent review; an independent pass is still needed before any
consumer relies on these components. RFC-0013 A1 and RFC-0010 A7 stay Draft.

## Why a new amendment and not A1

A1 requires the complete construction (Circle and expander paths, the 5% target,
native evidence). The design note proves four component lemmas and shows that
the composition is open (R1–R13). Accepting A1 would claim more than is proved.
A2 admits the two components that are completely specified and proved alone,
and A1 keeps the full contract.

## Pass 1 — soundness-auditor

Challenges and absorbs, in order:

- Hiding source: no new challenge. The certificate's `CertificateWeight`
  follows the certificate public input, which contains the version-3 source
  bytes and the root. The root covers the salts. Opening challenges are A9's.
- Masked sumcheck: `Instance` (A1 bytes, original `H`), then `zk/mask-sum` with
  `G`, then `zk/mask-weight` (`α`), then A1 rounds with running claim
  `H + α·G`, then `Final` over `finals ‖ μ` at message index `k + 1`. The index
  differs from A1's `k`, so a masked final cannot be read as an unmasked one.

Attempts:

1. *Choose `μ` after `ρ`.* Nothing in A2 binds `g` before `G`. A prover
   picking `μ = (running − P(finals))/α` passes every final check. A2 therefore
   states that the SC and MASK lines hold only for a bound `g`, returns `(ρ, μ)`
   as an undischarged obligation, and forbids consumers. Planned control:
   NC-0905 changes `μ` under the actual verifier and expects
   `FinalEvaluationMismatch`. It catches a tampered `μ`; it is not a binding.
2. *Shift `G` to absorb a false `H`.* `G` is absorbed before `α`, so
   `H + αG = H_true + αG_true` holds for at most one `α` when `H ≠ H_true`: the
   MASK line `1/|K|`. NC-0904 changes `G` and regenerates the rounds honestly.
   The first round check fails (`RoundSumMismatch`), because the running claim
   moved by `α·ΔG`.
3. *Salt bytes.* Salts are not field elements and are not decoded. A prover may
   choose any salt; the Merkle tree authenticates the whole payload, so a salt
   changed after the root fails (NC-0902, `RootMismatch`). The column equation
   decodes only the `2R` elements after the salt, with A9's canonical checks.
4. *Open the data directly.* A consumer asking for a point whose `W` coordinate
   is 0 would receive `X̃` in the clear. The prover's rank check sees zero
   mask-row coefficients and aborts with `MaskRank`. The check is prover-side
   and cannot weaken soundness. A malicious prover that skips it only harms its
   own privacy.
5. *Query budget.* The verifier rejects a version-3 context with
   `q_c + q_o > C − 1` or `R < 2D` before any transcript work (NC-0903). The
   tables are indexed by the encoded message length `m + 1`, as the code
   identity states.
6. *Degenerate instances.* `n = 0` or `δ = 0` is rejected: with no round,
   `G = μ` would reveal `g` and add no masking. At `i = n` the formula's last
   term is an empty sum, so its coefficient `2^{−1}` never matters.

I tried to break it by choosing `μ` late, by shifting `G`, by editing a salt and
by opening at `W = 0`. The text rejects or confines each: the reserved controls
NC-0905, NC-0904 and NC-0902 name the rejections, and the `MaskRank` abort
covers the last. Attempt 1 is a real gap, recorded as R2 and as the reason no
consumer is admitted.

Ledger: one MASK draw per masked instance, `1/|K|`. SC unchanged. The PCS terms
of a version-3 source are A9's at `(m + 1, b)` and `2R`. No other line.

## Pass 2 — rfc-author as the hostile privacy reader

1. *Reused seed.* With one seed for two sources, `Rm` and `S` repeat and
   commitment privacy §4 recovers data. A2 makes "fresh, never reused" normative
   but cannot enforce it from the verifier. NC-0901 (reuse) stays `todo`, as in
   FlashProve, where a lost mask can still verify.
2. *Derived masks are not uniform.* The lemmas assume uniform masks. A2 states
   the computational form under the PRF assumption on the keyed BLAKE3 stream.
   It does not hide that this is an assumption.
3. *Final values.* Lemma 4 simulates the rounds given the final values; the
   final values themselves reveal linear functionals of the columns. A2 says
   so in item 2 and leaves claim masking to R1. A reader cannot take A2 as
   hiding a sumcheck's inputs.
4. *Conflict with Accepted §3.* §3.2's single random row is not implemented or
   replaced by A2. A2 adds a component beside it and claims none of §3's
   properties for any profile. A1's Draft replacement text still governs the
   eventual §3.
5. *Words.* "hiding source", "mask half", "mask rows" and "masked sumcheck" are
   added to the glossary. No forbidden synonym (glossary lint).
6. *Cost.* A2 states the factor four and the two extra `K` values as layout
   counts. It moves no cost-model constant and quotes no measurement.

## Checklist (Workflow 03)

- RFC sections: RFC-0013 A2 items 1–3, RFC-0010 A14 items 1–4, RFC-0012 A17.
- Challenges: `zk/mask-weight` after `Instance` and `zk/mask-sum`; PCS
  challenges unchanged.
- Claims and consumers: the masked reduction's finals and `(ρ, μ)` have no
  admitted consumer; opened values of a hiding source are functionals of `M'`.
- Bindings and controls: salt payload (NC-0902), admission (NC-0903), mask sum
  (NC-0904), mask final (NC-0905), all reserved `todo` for E12-12 and E12-13.
- Ledger: MASK `1/|K|` per masked instance, conditional.
- Bound certificates: none.
- Padding and masks: data occupy the `W = 0, Y = 0` face; consumer padding rules
  are R1.
- Determinism: masks and salts are fixed functions of the seed and source id;
  equal seeds give equal bytes (INV-8), which is not evidence of fresh masks.
- Parity: no GPU path.
- Cost model: no term moves.
- Verifier: version-3 parsing and a 32-byte payload offset; no new arithmetic,
  still `no_std`.
- Glossary: four terms added; lint passes.
