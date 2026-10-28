# Small-value prefix strategy (Q21)

Question: can E3-04 retain bounded input storage through several A1 rounds without
folding a QM31/OM31 challenge in M31 or changing the ordinary sumcheck relation?
Cost terms: c_sc and T_misc; measure caller inputs, prover scratch/transition,
proof and complete claim-consumer memory separately. Kill criterion: any changed
round value, original final claim or transcript continuation versus dense A1.

Method: the direct prototype evaluates a prefix grid from original integer tables.
A second builder extends each monomial's Boolean prefix tables one axis at a time
in M31, accumulates its suffix sum, then applies the original K coefficient.
It retains only one monomial accumulator rather than one grid per term. The
resulting K grid answers ordinary A1 rounds, followed by direct prefix evaluation
of every original table and a dense tail. This is prover-only deferred binding,
not A3's protocol-changing univariate skip.

Primary algorithm reference: [Dao et al., §5.1, Figure 2 and Appendix C.4.1](https://quangvdao.github.io/papers/authored/speeding-up-sum-check-proving.pdf).
The explicit polynomial-prefix view in this extended version of the RFC's
2025/1117 reference motivates the grid. Our checked algorithm uses simple
axis expansion and ordered sums of monomials; it does not claim the paper's
optimized product-evaluation constants or copy another prover into the core.

Reproduce:

```sh
uv run --locked --script research/small-value/check_small_value.py
python3 research/small-value/check_grid.py
```

The first script passes 70 cases across both fields and degrees 0..4, including
full-extension coefficients, zero coefficients, constants, unused inputs,
signed/unsigned 16-bit extrema, maximum prefix and a nonempty tail. Each table's
generated values fit one signed or unsigned representation. Direct and term-grid
construction agree; resulting proofs/points match the dense Python A1 oracle,
all claims pass its actual public-table adapter, and continuations agree.
The second script compares 500 expanded grids with direct integer MLE evaluation
modulo M31; a swapped-axis mutation changes the non-symmetric checked grid.
The algebra suite also includes k=0/1 edge cases beyond the proposed production
constructor domain k=2..4. These are finite algebra checks, not the required
production 1,000 cases per degree/field. Research input assertions inspect values only to establish the
prototype's domain; production eligibility must follow its typed representation.

The truncation reproduction starts with an honest constant-zero A1 assertion
and an unused original table containing 65536. It verifies the honest dense proof,
then uses the candidate small prover on a control-side truncation to zero. Exactly
one final value changes and the unchanged original public consumer rejects with
ClaimMismatch in each field. This supports the NC-0204 design but earns no
production catalog credit. Neither the strategy nor this control proves range.

Recommendation: adopt RFC-0006 A5's complete prover-only contract after the required
reviews, then implement and measure E3-04. The A1 transcript, verifier and SC loss
stay unchanged. Typed optimization eligibility is distinct from authenticated
private-tensor range discipline and CQIS integer field-faithfulness certificates.
No runtime, peak memory, speedup or fitted constant has been measured here.
