# Masked claims research note review (R1, task E12-16)

Reviewer: claude-code, also the author. This is a same-author soundness-auditor
pass on [the note](../../formal/zk-claims.md). It is not an independent review.
The note is research only: no RFC, label, ledger line, wire format, control or
code change.

Attempts:

- **Mask variable fixed instead of summed.** The note forbids it. The one case
  it would arise is matmul `out`, and the broadcast form `Ȯ` handles that.
- **Base-field mask on a `K` claim.** Lemma 6 charges `D` M31 dimensions per
  claim. It proves the rank condition with an explicit non-degeneracy witness
  and a Schwartz–Zippel bound.
- **Shared mask between certificate and claims.** Claim masks are separate
  columns. The source mask rows serve only the certificate, the opening and
  `σ_S`. Lemma 7 states the resulting rank condition but does not prove it.
- **False batch sum hidden behind `σ_S`.** `σ_S` is fixed before `β`, so this
  is an RLC event.
- **Correlated claim points through `vars` maps.** Lemma 6 does not cover them.
  The note lists this as item 9.

Open, as the note says:
- Lemma 7 and the executable small-field check (the gate before any code);
- committed-fraction LogUp;
- degree counts;
- weight lifetime;
- abort bounds;
- correlated points;
- the normative amendment.
