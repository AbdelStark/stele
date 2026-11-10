# ZK-GKR for the A5 LogUp trees, against committed fractions (Q29)

Status: Draft research note, task E12-16. Question Q29. Compares two zero-knowledge
routes for lookups under RFC-0013 A5:

- RFC-0008 A7 as first accepted in #337: committed fraction columns;
- masking A5's existing GKR fraction trees, in the style of Libra and Virgo.

The recommendation is the second route, recorded as a revision of A7.
Evidence: `research/zk-claims/check_gkr.py` and the census in
`crates/stele-prover/tests/development.rs`.

## 1. Construction (ZK-GKR over A5's trees)

The A5 statement, its units, its multiplicities, `θ, β, α`, and the order and
error `e` of the A5 argument are unchanged. Each tree has layers `V_k = (p_k, q_k)`
over `k` variables, with
`p_k(x) = p_{k+1}(x,0)·q_{k+1}(x,1) + p_{k+1}(x,1)·q_{k+1}(x,0)` and
`q_k(x) = q_{k+1}(x,0)·q_{k+1}(x,1)`.

1. **Committed top.** Layer `k0 = c_D + 1` (3 for QM31, 4 for OM31) is committed
   as witness columns `p_{k0}`, `q_{k0}` and `h_{k0} = p_{k0}/q_{k0}`, in a
   hiding source. Two A5 relations prove the tree's fraction sum without
   revealing a root: the identity `h·q − p = 0` and the cube sum `Σ h = 0`. The
   lookup and table trees are combined into one fraction sum, with the table
   numerators negated. All their claims are A5 masked claims on committed
   columns. No root `(P, Q)` is ever revealed; plain LogUp reveals it.
2. **Masked layers.** Below `k0` every layer polynomial `V ∈ {p_k, q_k}` gets a
   mask block `r_V` of `2^{c_D+2} = 4D` M31 entries, with coordinates
   `(T, u_1..u_{c_D+1})`, in the proof's **shared mask source** (item 4):
   `V̇(X, T) = Ṽ(X, T) + κ(X_v)·r̃_V(T, X_u)`.
   Here `T` is the layer's last variable, `v` a variable of `X` (summed in the
   step below) and `u` `c_D + 1` coordinates of the step point. On the cube
   `κ = 0`, so the layer relation is unchanged.
3. **Masked GKR step.** The claim `c_k = V̇_k(ρ_k, t*)` is reduced by one A1
   sumcheck over a selector bit `s` and the layer variables:

   `Σ_{s,x} [(1 − s)·eq(ρ_k, x)·F_λ(V̇_{k+1}(x,0), V̇_{k+1}(x,1))
            + s·κ_k·eq(u_k, y)·r̃_{V_k}(t*, y)] = c_k`.

   - `F_λ` combines the `p` and `q` relations with a challenge `λ`.
   - The `s = 1` half is padded with zero weight to the same length.
   - The step is masked with the shared source (item 4).

   Its finals are the four masked values `V̇_{k+1}(x*, 0/1)` for `p` and `q`, and
   one claim `f_k = r̃_{V_k}(t*, y*)` on the committed block. A line challenge
   `t*` folds the two `t` values into the next claim.
4. **Shared mask source** (replacing one RFC-0013 A4 source per instance). One
   hiding source per proof holds:
   - every masked sumcheck's mask polynomial `g_j`, a plain sum of univariates,
     whose coefficients are stored as `D` limb rows;
   - every layer mask block.

   It is committed and absorbed before the first masked instance. For each
   instance `j`, `μ_j = g_j(ρ_j)` is a linear claim on it, and so is every `f_k`.
   They are batched with Lemma 7's zero-weight batch and opened once. That batch
   is the only instance with its own RFC-0013 A4 mask source: one per proof.
   This also replaces A5's one A4 source per relation instance.
5. **Leaves.** The last step's finals are claims on the committed sources:
   tuple columns, selectors (public) and multiplicities. They are A5 masked
   claims.

## 2. Soundness and privacy

**Soundness.**
- A5's argument bounds a false identity by `e` and is untouched.
- Each masked step is a GKR step on the same layer polynomials. Its sumcheck
  carries the `s = 1` half, whose final is a claim on a committed block, bound
  before the step.
- The per-layer losses are:
  - SC `(k + 1)·3/|K|`;
  - the RLC line `1/|K|` for `λ`;
  - the line challenge `1/|K|`;
  - MASK `1/|K|`.
- The committed top adds A5's identity and sum terms.
- The shared source binds every `g_j` before its `G_j` is absorbed: this is the
  R2 argument, with RLC batching of the `μ_j` in place of A4's two-block
  opening.

**Privacy.** Every revealed value is one of:
- a masked layer value: Lemma 6′ with three `K` functionals per `4D` block, of
  which two at `t ∈ {0, 1}` and one `f`, needing block rank `3D`;
- a masked round, `G_j` or `μ_j`: Lemma 4 with a uniform sum-of-univariates;
- a claim on the shared source, through the zero-weight batch and one opening
  (Lemma 7);
- an A5 masked claim at the committed top and leaves.

The block rank `3D` is a producer abort, like A5's claim-block check.

`check_gkr.py` checks the exact linear view of two masked layers (`p` and `q`
each), their `f` claims, the shared source's certificate, the batch, the opening
and the queried columns. The true layer values are treated as free secrets,
which is more than the real tree allows. The view is private, and each of these
leaks: removing the masks, removing the mask rows, sharing one block between
`t = 0` and `t = 1`, or a block of `2D` entries.

## 3. Cost on the eight-layer window (census)

The census groups the 4537 ranges and 108 lookups of the eight-layer window
(`T = 64`) into **21 checks**: one per table, and one per range width, as
RFC-0026 A3 already does. Their padded source lengths sum to
`N = 2.01·10^7`, and their tables to `|T| = 3.3·10^5`. The trees have 570
layers in all.

| Route | Committed M31 entries | With A15 hiding (×4) |
|---|---|---|
| A7 as accepted: committed fractions `D·(N + |T|)` | 8.2·10^7 | 3.3·10^8 |
| ZK-GKR: per layer `16(k+1)` mask coefficients and `2·4D` block entries, summed over 570 layers | 1.05·10^5 | 4.2·10^5 |

ZK-GKR is about 780 times smaller, and it keeps the current tree work
unchanged.

The shared mask source also removes A5's projected `1.3·10^7` entries of
per-instance A4 sources. About 800 relation instances plus 570 layers now need
only `16(k+1)` entries each. With both changes, the projected dev-zk
commitment on this window becomes:
- `4 × 1.6·10^7` for the hiding witness and weights;
- plus about `5·10^5` of masks, blocks and the committed tops.

That is about `6.5·10^7` M31 entries, roughly 4 times today's `1.6·10^7`
instead of 20 times. It is a projection from census counts, not a measurement.

**Other options considered.** Batching ranges of one width into one tree is
already in place (21 checks). FlashProve-style randomized range checks would
change the range relation itself. They are not needed now that the lookup side
is small, and they would need their own amendment.

## 4. Decision and remaining work

- **Decision.** Revise RFC-0008 A7 in #337 to ZK-GKR over A5's trees (§1). Revise
  RFC-0013 A5 to use the shared mask source (item 4) in place of one A4 source
  per instance. The committed-fraction route is withdrawn.
- **Remaining for implementation (E12-19):**
  - the exact step layout: selector padding, `λ` and the line challenge reuse
    A5/A3 labels;
  - the top-layer commitment order (after `α`, absorbed with
    `relation/roots`);
  - NC-0913 (one masked layer value changed: `RoundSumMismatch` at the next
    step);
  - NC-0914 (one block entry changed after commitment: `RootMismatch`).
