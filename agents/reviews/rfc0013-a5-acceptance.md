# RFC-0013 A5 acceptance review (with RFC-0026 A9 and RFC-0008 A7)

Decision: accept at conditional scope. The dev-zk profile is defined but not
admitted until E12-18, E12-19 and E12-14 deliver with their controls, privacy
tests and an independent review. Reviewer: claude-code, also the author. Two
same-author passes follow; an independent review is requested.

## Pass 1 — soundness-auditor

- **Relation forms.** On the cube every `V̇` equals its column, so every cube-sum
  identity, every zero-sum and every A7 identity is the same polynomial
  statement as before.
  - The matmul zero-sum at `ρ` is the MLE identity of RFC-0026 §3.5, because
    the summand equals `lhs·rhs − 2^{−s}out` for every Boolean `y`. The SZ line
    is unchanged.
  - The degree bound rises by one per masked factor in its vanishing variable
    only, and A5 item 3 charges it.
  - I tried a matmul whose `out` is masked on a free variable instead of a summed
    one. The zero-sum then fails for the honest prover. That is why item 2 makes
    `v_a` a summed variable.
- **RFC-0008 A7 against A5.**
  - The order is sources, units, multiplicities, `β`, `α`, then the fractions,
    so A5's `e` applies unchanged.
  - The zero-denominator event is a separate line, `(N + |T|)/|K|`, with a
    producer abort and a verifier check on the public table side.
  - I tried an `h_w` entry free at a zero denominator. It needs
    `α = z_β(x_i)`, which is that line.
- **Padding.** Multiplicities scale by `2^pad`. `B·2^pad < p` is a plan check.
- **Batching.** The weight `(1 − w)·W` makes the claimed sum public (Lemma 7). A
  prover that puts weight on `w = 1` changes the final (NC-0915).
- **Profile byte.** It is in the public input, so it is bound before every
  challenge (NC-0912).

I tried to break it with a free-variable mask on `out`, a zero-denominator
fraction and nonzero batch weight on the mask rows. The relation identity, A7's
abort with its ledger line, and NC-0915 cover each.

## Pass 2 — privacy (rfc-author as the hostile reader)

- Every revealed value is one of:
  - a masked claim (Lemma 6′, own block);
  - an A4-masked round, `G` or `μ` (Lemmas 4–5);
  - an A2 row or column (Lemmas 1–2);
  - the batch's public sum and opened value (Lemma 7).
- The exact checks model one and two relations sharing a column and find no leak.
  A shared mask block leaks, and that is why item 1 gives each occurrence its own
  block.
- Every rank condition is a producer abort on public data.
- Weight sources need a fresh block set per proof. Item 7 makes this a lifetime
  budget the prover enforces.
- The cost projection is labelled as one, from census counts. It moves no
  ledger constant.
- Open, and not claimed:
  - Fiat–Shamir ZK beyond the programmable random-oracle sketch (Q12);
  - expander sources;
  - the standard and treaty profiles, and the 5% target (A1);
  - a stories42M census.

## Checklist (Workflow 03)

- RFC: RFC-0013 A5 items 1–10, RFC-0026 A9, RFC-0008 A7 items 1–10.
- Challenges: existing labels only (`ZeroWeight`, A1, A5, `relation/roots`,
  `BatchCoefficient`, A18). Their order is A5 item 6.
- Claims: every claim is consumed by its source's batch and one opening.
- Bindings and controls: NC-0909..0915 reserved `todo`.
- Ledger: SC degrees, A7's lines, MASK and PCS per instance and per source.
- Determinism: masks, blocks and seeds are fixed functions of the seed and the
  plan.
- Parity: no GPU path.
- Cost: projection only. No constant moves.
- Verifier: no code yet.
- Glossary: "claim mask" and "dev-zk" are added.

## Revision: ZK-GKR in place of committed fractions

The coordinator asked for a design comparison before E12-19. formal/zk-gkr.md
gives the construction, its soundness and privacy (Lemmas 4, 6′ and 7), and the
census cost. On the eight-layer window, masking A5's trees costs about `4.2·10^5`
M31 entries with hiding, against `3.3·10^8` for committed fractions.
`check_gkr.py` finds the masked two-layer view private. Removing the masks,
removing the mask rows, sharing the `t` blocks, or a `2D` block each leaks.

A7 is rewritten to ZK-GKR before merge. A5 gains item 5a: one shared mask
source per proof, with batched `μ` openings, in place of one A4 source per
instance. Soundness pass:
- A5's order and `e` are unchanged.
- Each masked step is a GKR step whose extra `s = 1` half is a claim on a block
  committed before the step.
- The committed top replaces the revealed root and carries its own
  zero-denominator abort.

Privacy pass:
- The block rank `3D` is a producer abort.
- The top and the leaves are A5 masked claims.
