# Masked claims and composition for the development path (Q29, R1)

Status: Draft research note, task E12-16. Question Q29. Builds on
[the design note](zk-development.md) (Lemmas 1–5; RFC-0013 A2/A3). Companion:
RFC-0026 §§3–4. Nothing here is normative; implementation waits until this note
survives review.

The goal is the R1 item of the design note. After A2/A3, every masked sumcheck is
simulatable from its **final values**, and every hiding source is simulatable
from the values it opens. What still leaks is the set of final values: column
evaluations at random points, matmul `out~(ρ)`, and lookup layer claims. This
note gives

1. a construction that randomizes every revealed claim (§2);
2. a simulator argument by hybrids (§3);
3. the entropy budget under the M31 limit (§4);
4. costs (§5) and the exact remaining list (§6).

## 1. Requirement, restated

A Stele relation proof ends in claims `x̃(ρ)` on committed columns `x`. The
verifier needs those values to evaluate the relation polynomial `P` at the end of
a sumcheck. Libra's answer (Xie et al. 2019, §4.2) is to run every relation on a
randomized extension `V̇_x` that agrees with `x` on the Boolean cube, so the
relation's cube sums are unchanged while `V̇_x(ρ)` is masked.

The design note's §5 showed two ways this fails in Stele's field setting:
- an M31 mask cannot hide a `K` value;
- a mask shared between the certificate and the claims cancels.

The construction below avoids both by giving each column a dedicated mask column
and charging every revealed `K` value `D` M31 dimensions of it.

## 2. Construction

### 2.1 Masked claims

For every committed column `x` with `n` variables, the prover commits a **claim
mask** `r_x`: a column of `L_x = 2^ℓ_x` uniform M31 values, placed in the same
commitment group as `x` (§4 fixes `ℓ_x`). A claim on `x` inside a sumcheck uses
one variable `X_v` of `x` that the sumcheck **sums** (binds as a sumcheck round):

```
V̇_x(X) = x̃(X) + κ(X_v) · r̃_x(π(X)),   κ(t) = t(1 − t),
```

Here `π` is a fixed public map from `x`'s variables other than `X_v` onto
`ℓ_x` variables (a sub-tuple, padded with fixed zeros if `ℓ_x` is larger). On
the Boolean cube `κ = 0`, so `V̇_x = x`, and every cube sum the relation needs is
unchanged. The value revealed at the end is

```
c = x̃(ρ) + λ · r̃_x(π(ρ)),   λ = κ(ρ_v),
```

a masked **linear claim** on the pair `(x, r_x)` with public coefficient `λ`.

### 2.2 Which variable carries the mask

The vanishing variable must be summed in that sumcheck. Otherwise the mask term
does not vanish where the relation is checked:

- **Identities (RFC-0026 §3.2).** Run in A1 form, `Σ_x eq(τ,x)·P(x) = 0`
  (design note R3). Every column variable is summed; any one can be `X_v`.
- **Matmul (§3.5).** `out(x) = Σ_y lhs(x,y)·rhs(x,y)` is proven at the free
  point `ρ` by a sumcheck over `y`, plus the shared bits. `lhs` and `rhs` take
  their vanishing variable from `y`. `out` has no `y` variable, so its claim is
  carried by the broadcast extension
  `Ȯ(X, Y) = out~(X) + κ(Y_v)·r̃_out(π(X))`, which equals `out(x)` for every
  Boolean `y`. The matmul sumcheck then becomes the zero-sum
  `Σ_y [V̇_lhs·V̇_rhs − 2^{−s}·Ȯ](ρ, y) = 0`.
  - No claimed `out~(ρ)` is ever sent; the A1 claim is 0.
  - The three final values are masked claims.
  - Soundness is the existing SZ line: on the cube the summand is
    `lhs·rhs − 2^{−s}out`, so the zero sum at `ρ` is the MLE identity of the
    current proof. Degree in `Y_v` rises by one per masked factor.
- **Lookups (§3.3–3.4).** RFC-0008 A5's GKR fraction tree has uncommitted
  layers, whose claims would each need their own randomization. dev-zk replaces
  it by a **committed-fraction LogUp**, for the challenge `β` (and the tuple
  compression):
  - commit `h_w = 1/(β − w)` and `h_T = m/(β − T)` after `β`;
  - prove the identities `h_w·(β − w) = 1` (on the selector) and
    `h_T·(β − T) = m` as zerochecks;
  - prove `Σ h_w − Σ h_T = 0` as a cube sum.

  Every column is committed and every check is a cube sum, so §2.1 applies
  unchanged. The losses are LogUp's usual `(N + |T|)/|K|` and the zerochecks'
  SC terms. RFC-0008 A5's grouped units and repetitions are not needed.
- **Public columns and tables** are not masked. Their MLE values are public.

A product of several masked factors may give each factor a *different* summed
vanishing variable. Each variable's degree then grows by at most one: `δ + 1`
instead of `2δ`. If two factors must share one, that variable's degree adds up.
The A1 instance's single degree bound is the maximum over variables.

### 2.3 Batching masked linear claims per source

A source (commitment group) collects claims `c_a = ⟨w_a, M⟩`. Each is a linear
functional of the source's data message `M` (the `x` columns and the `r_x`
columns), a scaled eq at a known point. The source is a hiding source (A2). Its
opening must put nonzero weight on the mask rows (A2 rank check), so the opened
value involves the mask rows `S`. The batch therefore runs over the full message
`M'` with a weight that is zero on the mask rows:

1. Draw batch coefficients `γ_a` (existing `BatchCoefficient`). Put
   `W = Σ_a γ_a·w_a` on the data positions (`Y = 0` face).
2. Run one bound masked A1 sumcheck (A3) over the source's row bit `w` and its
   other data bits, for `Σ_{w,x} W'(w, x)·M̃'(w, x) = Σ_a γ_a·c_a`, with
   `W'(w, x) = (1 − w)·W(x)`. On the cube the `w = 1` half has weight zero, so the
   claimed sum is public, given the `c_a`. `W'` is multilinear and
   verifier-computable at any point.
3. Its final claim `M̃'(w*, x*)` is opened once with A2's point opening at
   `(w*, x*)`. The verifier multiplies by `W̃'(w*, x*) = (1 − w*)·W̃(x*)`. `w*`
   is nonzero except on a public abort, so A2's rank check holds generically.

Soundness:
- `γ` is A2's RLC line.
- The sumcheck has SC and MASK, and the opening has A9's terms.

No other value is revealed. An earlier draft of this note sent `σ_S = ⟨W, S⟩`
and drew one more challenge. The zero weight on `w = 1` makes both unnecessary.

### 2.4 Order inside one proof (dev-zk)

1. Statement, as RFC-0026 §4 step 1.
2. All witness groups, now including the claim-mask columns `r_x` of their
   columns, as hiding sources. Then the multiplicity sources. Absorb the roots
   and verify the certificates (A2 rank check).
3. The lookup challenges `β`, then the commitment of the fraction columns as
   hiding sources.
4. The identity zerochecks (A1 form), the lookup zerochecks and cube sums, and
   the matmul zero-sums. Each is a bound masked sumcheck (A3) on the `V̇`
   polynomials.
5. Per source: the batch of §2.3, then one opening.
6. Weight sources: §4.3.

## 3. Simulator argument

The simulator gets the public input only. It must produce, for an honest
verifier with uniformly drawn challenges, a view distributed as the real one up
to a stated statistical error. The argument is a hybrid over layers. Each hybrid
replaces one layer's messages by a function of public data and of the next
layer's revealed values.

- **H0.** The real view.
- **H1, PCS layer.** Every hiding source's roots, paths, certificate row, opening
  row and queried columns are replaced, given the source's opened value only,
  using Lemmas 1–3. The A3 mask sources are handled the same way, given their
  Lemma 5 view. Error: the salt term `N·q_H/2^256` per source, plus the
  rank-check abort events, which are public.
- **H2, sumcheck layer.** Every bound masked sumcheck's mask commitment, `G`,
  rounds and `μ` are replaced, given its final values only (Lemmas 4–5). Error:
  `1/|K|` for each `α = 0`, plus the public `ρ_n ∈ {0, 1/2}` aborts.
- **H3, batching layer.** Per source, the batch rounds and the opened
  value are replaced, given the masked claims `c_a`. This is Lemma 7 below.
- **H4, claim layer.** All masked claims `c_a` are replaced by independent
  uniform `K` values, conditioned only on what is public: the relation polynomial
  `P`'s evaluation must be consistent, and public-column values are computed by
  the simulator itself. This is Lemma 6 below.
- **H5.** The view no longer depends on the witness, so it is the simulator's
  output.

**Lemma 6 (claims).** Fix a column `x` with `t_x` masked claims at points whose
mask parts `π(ρ^a)` come from independent uniform sumcheck challenges, with
`λ_a ≠ 0`. Let `Λ_x` be the `D·t_x × L_x` M31 matrix of the coordinates of
`λ_a·eq(π(ρ^a), ·)`. If `rank Λ_x = D·t_x`, then for any two witnesses the claim
values `(c_a)` have the same distribution: uniform on `K^{t_x}`, independent of
`x`. Moreover `Pr[rank Λ_x < D·t_x] ≤ D·t_x·ℓ_x / p` whenever
`ℓ_x ≥ log2(t_x) + c_D`, with `c_2 = 1`, `c_4 = 2`, `c_8 = 3`.

*Proof sketch.* Multiplying by a fixed nonzero `λ_a` is an invertible M31-linear
map on that claim's `D` coordinate rows, so it does not change the rank. The map `r_x ↦ (λ_a r̃_x(π(ρ^a)))_a` is M31-linear with matrix
`Λ_x`. Full row rank makes it onto `K^{t_x}`, so a uniform `r_x` gives uniform,
`x`-independent claim values. That is the translation argument of Lemma 2.

For the probability: the determinant of a fixed `D·t_x` minor is a polynomial
in the M31 coordinates of the points, of total degree at most `D·t_x·ℓ_x`, since
each eq entry is multilinear. It is not the zero polynomial. To see this, give
point `a` non-Boolean coordinates in `c_D` positions, equal to M31-independent
basis elements: for QM31, `i` and `u` with `{1, i, u, iu}` a basis. Give it a
Boolean pattern `b_a` in the remaining positions, distinct for each `a`. The eq
vectors then have disjoint supports, and each block has rank `D`. Schwartz–Zippel
over uniform M31 coordinates gives the bound. ∎

Lemma 6 assumes the points of one column's claims are independent. Two claims
from the same sumcheck on the same column through two different `vars` maps
(RFC-0026 §3.1) share one challenge vector, so they are not independent. The
rank argument must then use their actual coordinate structure. This is item 9
of §6.

Two more cross-checks remain before H4 is complete:

- **Same point across columns.** One sumcheck reveals claims on several columns
  at one point. Their masks are distinct columns, so the per-column argument
  composes: the joint map is block-diagonal.
- **Shared variable choices.** If a claim's `π` drops coordinates, the bound
  uses the remaining `ℓ_x` coordinates only. The `λ_a` are public, and the
  public event `λ_a = 0` (`ρ_v ∈ {0,1}`) aborts.

**Lemma 7 (batching).** Fix the honest verifier's challenges, with `w* ≠ 0`
and `α ≠ 0`, a query set of at most `C − 1` distinct positions, and certificate
and opening coefficients whose mask-row M31 coordinates have rank `2D`. Then for
any two data messages `X, X'` with the same masked claims `c_a`, the batching
view has the same distribution. The view is: the certificate row, the batch
sumcheck (`G`, rounds, `μ`, its A3 mask source), the opened value, the opening
row and every queried column.

*Proof.* The batch sumcheck's claimed sum `Σ γ_a c_a` is the same for `X` and
`X'`. By Lemmas 4–5 its view is a function of public data, its final values and
fresh randomness. Its final values are `W̃'(w*, x*)`, which is public, and
`M̃'(w*, x*) = u·b`, a function of the opening row `u`. So it suffices that
`(t, u, queried columns)` has the same distribution for `X` and `X'`. That is
Lemma 2 with `J = 1`, whose translation needs no condition on `X − X'`. ∎

The earlier draft's `σ_S` would have needed an extra rank condition (one more
`K` functional on `S`, impossible at `R = 2D`). The zero-weight batch avoids it.

**Executable check.** `research/zk-claims/check_view.py` models the whole linear
view at toy size and checks the exact criterion `rank([B A]) = rank(B)`:
- field and code: `F_31 ⊂ F_{31²}` (`D = 2`), a Reed–Solomon toy code;
- one column `x` of 8 entries with a 4-entry claim mask and two masked claims;
- one hiding source, the A2 certificate row, and the zero-weight batch with
  Lemma 4 masking;
- the batch opening row and every queried column.

In 60 random draws per case:
- The honest view is private in every draw without a public abort.
- The tiny field makes rank failures frequent (5 of 60). Every rank failure
  leaks, so Lemma 6's and Lemma 2's rank conditions must be producer aborts,
  not only error terms. The note's ε for Lemma 6 is therefore an abort
  probability, and the producer checks `rank Λ_x` as it already checks A2's
  rank.
- Each control leaks in every draw:
  - claim masks removed;
  - mask rows removed;
  - batch sumcheck mask removed;
  - opening at `w* = 0`;
  - a query set above the budget.

**Fiat–Shamir.** In the random-oracle model the simulator programs the oracle so
its sampled challenges are the transcript's:
- every absorbed message is public or simulated;
- every Merkle root covers salted leaves;
- no secret enters a hash without a salt or a mask.

The FS error adds `q_H` times the number of programmed points over the output
space. The concrete FS line is still Q12's placeholder.

**Privacy claim reached** (Lemmas 1–7, with uniform masks): statistical
honest-verifier ZK with error

`ε_zk = Σ_sources N·q_H/2^256 + Σ_sumchecks 1/|K|`,

where the rank conditions of Lemmas 2 and 6 are producer aborts on public data.
Their probabilities (at most `D·t_x·ℓ_x/p` per column, and A2's) bound
availability, not privacy;

then ZK in the programmable ROM; computational with seed-derived masks.

## 4. Entropy budget under the M31 limit

Every revealed `K` value consumes `D` M31 dimensions (`D = 4` for QM31, 8 for
OM31) of a mask that nothing else uses.

| Mask | Consumed by | Requirement |
|---|---|---|
| `r_x` (claim mask, per column) | `t_x` masked claims | `L_x ≥ D·t_x` with `ℓ_x ≥ log2 t_x + c_D` (Lemma 6) |
| source mask half (per row) | `q_c + q_o` queried positions | `C − 1 ≥ q_c + q_o` (Lemma 1) |
| source mask rows `S` | certificate row, opening row | `R ≥ 2D` and rank `2D` (Lemmas 2, 7) |
| A3 mask source | `G`, rounds, `μ`, its opening row | Lemma 5 |

`t_x` per column in RFC-0026 is small and plan-fixed:
- one claim per zerocheck domain it appears in;
- one per lookup or range it feeds;
- one per matmul role.

The actual per-module maximum is not counted yet (item 5 of §6). If it is at
most 6, then `L_x = 2^{⌈log2 6⌉ + 2} = 32` for QM31 and 64 for OM31. A claim mask is
therefore tiny next to a typical column (`2^n` with `n ≥ 10`). It costs one
small column per witness column, not a doubling. Columns shorter than
`D·t_x` (`n < ℓ_x + 1`) take `π` with zero padding, so `r_x` is still `L_x`
long.

### 4.3 Weight sources

Weights are committed once, so their claim masks `r_W` are committed once too.
Each proof reveals `t_W` masked claims of `r_W`. Over `P` proofs this is
`D·t_W·P` M31 dimensions, and Lemma 6's rank condition must hold for the union.
The lifetime budget becomes

`P ≤ ⌊L_W / (D·t_W)⌋ − 1`

on top of A2's column budget `q_c + P·q_o ≤ C − 1`. With `L_W = 2^16` per
weight column and `t_W = 1`, this allows 16 383 proofs at QM31. `r_W` is then
a 2^16-entry column next to weight columns of `2^20` or more. The binding
budget remains A2's column budget (4699 proofs at `C = 2^20`). A refresh
mechanism (FlashProve's linked re-encodings) is still R8.

## 5. Costs (counts, no measurement)

- **Commitments.** One claim mask of `L_x` M31 per witness column (32–64
  values), inside its group. Plus the fraction columns of each lookup (two
  columns of the lookup's length, committed after `β`), in place of the GKR tree.
- **Sumchecks.** Each relation's sumcheck gains at most one degree in the
  vanishing variables. The matmul zero-sum carries `Ȯ` as one extra factor. Every
  sumcheck carries an A3 mask source: `4D × 2^(m+1)` with `m ≥ 9`. It is
  per-instance, so with tens of instances this is the main new fixed cost.
  Batching the A3 masks of all instances into one mask source is an
  optimization left open.
- **Batching.** One masked batch per source and one opening, in place of the
  current claim batch.

## 6. Exact remaining list for R1

1. **Lemma 7.** Done (§3), after removing `σ_S`.
2. **Executable check.** Done for one column, one source and its batch
   (`research/zk-claims/check_view.py`). Still to extend: two relations sharing a
   column (an identity and a matmul zero-sum with `Ȯ`), and correlated points
   (item 9).
3. **Matmul with shared bits.** RFC-0026 §3.5's `eq(ρ_shared, x_shared)` sum is
   a summed variable too, so it can carry a vanishing factor. Its degree budget
   is to be checked per module.
4. **Committed-fraction LogUp.** Fix its statement, bound and labels, and its
   interaction with RFC-0008 A6 tuples and RFC-0026 §3.4 widths. It is an
   RFC-0008 amendment of its own.
5. **Degree.** Each RFC-0026 module's maximum per-variable degree with distinct
   vanishing variables, and the resulting A1 instance degrees.
6. **Weights.** `r_W`'s lifetime accounting (§4.3), and prover-side state.
7. **Aborts.** The public events `λ_a = 0`, `ρ_n ∈ {0, 1/2}`, `α = 0` and rank
   failures: an availability bound for each.
9. **Correlated claim points.** Lemma 6 for claims on one column that come
   from one sumcheck through different `vars` maps (permuted or broadcast reads).
10. **Normative text.** An RFC-0013 amendment (A4) for §§2–4, with RFC-0026 and
   RFC-0008 companions, NC reservations, and the dev-zk profile flag (INV-1).

The note's position: §2's construction is complete for cube-sum relations and
for matmul through the broadcast form. Lemmas 6 and 7 are proved, and the toy
model finds no leak. The extended check and items 3–9 are the gate before
implementation.
