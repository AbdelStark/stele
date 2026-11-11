# RFC-0026 — Development-profile end-to-end prefill proof

Status: Accepted · Version: 0.1.0 · Depends: RFC-0003, RFC-0004, RFC-0005, RFC-0006, RFC-0008, RFC-0010, RFC-0012, RFC-0021, RFC-0025

Review: [same-author passes and the independent pass](../../agents/reviews/rfc0026-acceptance.md).
Decision: ADR-074. Companions: RFC-0006 A8, RFC-0008 A6, RFC-0012 A16. Tasks: E16-01..E16-11.

## 1. Statement

### 1.1 What is proven

One proof covers one **prefill window** of a CQIS family-1 (Llama-style) model, as
evaluated by the RFC-0025 §2.6 full causal evaluation. The statement follows FlashProve's
small route: the prover shows the window was evaluated correctly and that each
checked token is the greedy choice.

Public inputs, in the order they are absorbed (§4):

1. `cqis_id` and the canonical `Model`, `Scales` and `Preparation` bytes (RFC-0025 §2.7).
   The verifier decodes them itself. Mantissas, exponents, fractions, policies and
   function representations are therefore public data, not witness.
2. The **model commitment**: one PCS root per weight source (§2.2).
3. `T`, a power of two, and the tokens `x_0..x_{T-1}`.
4. The checked range `[r, e)` with `0 <= r < e <= T`, and the next token `y`.
   `y` is required exactly when `e = T`.

Claim: there is an assignment of every witness column (§2.3) for which every relation
of §3, as derived from the plan (§5), holds over the integers. Every weight column then
equals the committed weights. By the encoding obligation (§5.2), the logits are the
logits that `stele_cqis::execution::Executor::full(x)` computes under those weights.
For each checked position `i`, the token `c_i` (that is `x_{i+1}` when `i < T-1`, and
`y` when `i = T-1`) is the least vocabulary id that attains the maximum logit in row
`i` (RFC-0025 §2.6 greedy rule).

### 1.2 Development profile

The **development profile** is the parameter set of this RFC. It is not a profile
under RFC-0002 §8, and it claims no security level.

- **Arithmetic.** The base field is M31 (RFC-0003). Every challenge is a QM31 element
  drawn from `stele_hash::Transcript<QM31>`.
- **Lookups.** LogUp follows RFC-0008 A5 with `r = 1`, the `standard` choice.
- **Fiat–Shamir.** Q12 is open: RFC-0012's FS line is still a placeholder. The ledger
  of §6 therefore reports the interactive error terms only, and labels FS as unproven.
- **PCS.** No PCS parameter set is admitted for any profile (RFC-0012 A15, Q12).
  Development proofs use RFC-0010 A3 Policy 1 v2 sources and print their PCS terms
  as conjectural. They make no admitted proximity claim.
- **No zero-knowledge.** There is no masking (RFC-0013 does not apply). The proof
  reveals claimed evaluations, PCS opening rows and query columns of witness and
  weight sources, as the RFC-0010 openings define them. It reveals no other witness
  value. Even so, opening rows and columns leak linear combinations of witness and
  weights. Treat every proof as disclosing the model and the activations.
- **Not proved.** The proof does not bind a passport or checkpoint (RFC-0011): the
  model commitment is taken as given. It makes no claim about floating-point fidelity
  (RFC-0004 §7). It proves no decoding beyond the checked greedy tokens, and nothing
  about sampling. It makes no cost claim, so INV-7's one-pass weight phases and the
  RFC-0007 four-phase schedule are not used. It does not cover treaty/standard
  admission or GPU parity before E16-11.
- **Cuts (INV-6).** In the development profile every witness column of §2.3 is a
  named committed tensor, that is a cut, and this RFC is the RFC that names them.
  The `standard` and `treaty` plans are unchanged.

### 1.3 Model class

E16 covers the following model class:

- family 1, version-1 residual stream (int16; RFC-0004 A14 wide streams are excluded);
- dynamic row policies, non-grouped or RFC-0004 A15 grouped (group size `g` from
  the `Model`; the §5 row-conversion pattern runs once per group of `g` features,
  and the projection uses `A' = Σ s_k(i)·q_i·w_i` through limbs, `|A'| < 2^51`);
- int4 or int8 weights;
- no GQA, or GQA with the K/V rows committed once per key/value group and read
  through a `Ref` (§3.2);
- any RFC-0021 exponential mode and SiLU representation that the `Model` names.

An unsupported `Model` is rejected before proving, with `UnsupportedModel`. Extending
the class is an amendment to this RFC.

## 2. Commitments and layout

### 2.1 Columns

A **column** is a vector of `2^n` integers with a declared **width**:

- signed `b`: values in `[-2^(b-1), 2^(b-1))`;
- unsigned `b`: values in `[0, 2^b)`;
- in both cases `1 <= b <= 30`.

Tensors are flattened row-major. Each dimension is padded to a power of two, so a
tensor of shape `(a, b)` uses `log a + log b` index bits, with the row index in the
high bits. Padding entries are ordinary data. The plain checker and the proof both
check them, so a module must state what its padding holds, which is usually 0, and
its relations must hold there too. Selectors (§3.3) and public masks are the only way
to exempt a row.

Every module pins the padding entries of its output columns to 0, using an identity
with a public mask. Results therefore never depend on the padded entries of a weight
tensor, which the model commitment fixes but the executor never reads.

A column has one of three kinds (`stele_ir::relation::Kind`):

- **Witness**: committed for this proof, in a commitment group.
- **Weight**: committed once, in the model commitment.
- **Public**: values known to the verifier. It is evaluated by the verifier, never
  committed or opened.

### 2.2 Model commitment

- Each weight tensor of RFC-0025 §2.1, for each layer and role, is one PCS source.
  Its values are the original integer codes (int4/int8) under the RFC-0010 A6 signed
  embedding.
- The model commitment is the ordered list of their roots. The order is plan order:
  embedding, then for each layer ℓ the roles Q, K, V, O, gate, up and down, then the head.
- A tied head reads the embedding source and has no root of its own.
- Every weight column must still pass a range check (§3.6). In the development
  profile that check is run in every proof.
- Each `Kind::Weight` column is exactly one weight source, padded as in §2.1.
  Weight columns are matched to the model-commitment roots in order of first
  declaration, and that order must equal the plan order above. A tied head reuses
  the embedding's `ColumnId`.
- **Plan obligation.** `Relation::validate` does not see roots, so it cannot check
  this order. The E16-10 verifier checks it before step 1 of §4: it compares the
  sequence of `Kind::Weight` columns, by declaration order, with the plan's weight
  list, and rejects any difference in count, order or padded shape with
  `StatementMismatch`.

### 2.3 Commitment groups

- A **commitment group** is a named set of witness columns that all have the same
  `log_len`. It is one RFC-0010 v2 source.
- The source message is the group's columns in `ColumnId` order, padded with zero
  columns to a power-of-two count `2^c`, in the signed embedding.
- **Column claim.** Column `k` of a group with `n`-bit columns and claim point
  `ρ ∈ K^n` maps to the source claim at the MSB-first point `(bits(k) ‖ ρ)`. The
  column-index bits are the high (leading) variables, and `bits(k)` is a Boolean
  vector known to the verifier.
  Converting a column claim into a source claim is therefore exact, with no
  Schwartz–Zippel loss.
- **Group naming.** A module creates its groups with `Relation::add_group`. Names
  follow `L{ℓ}/{module}/{n}`, or `G/{module}/{n}` outside layers, so groups are
  deterministic from the plan.
- **Order.** Groups are committed in `GroupId` order.

### 2.4 Multiplicity sources

Every lookup and every range check (§3.3–3.4) has its RFC-0008 A5 multiplicity
sources. Their roots are absorbed after all group roots (§4, step 3).

## 3. Relations

The types are those of `crates/stele-ir/src/relation.rs`. The integer semantics in
this section are normative: `stele_ir::relation::check` implements them as stated.

### 3.1 Domain and references

- A relation has a **domain** `{0,1}^m`.
- A `Ref { column, vars }` reads the column at index `Σ_j bit(x, vars[j]) · 2^j` for
  a domain point `x`. `vars` must be injective and have length equal to the column's
  `log_len`.
- One mechanism therefore expresses broadcast (a column uses fewer bits than the
  domain), tiling, transposition and head splitting. All of them are permutations or
  subsets of variables.
- In MLE terms, the column's multilinear extension is evaluated at the domain point
  restricted to `vars`. A permuted or broadcast read costs nothing and adds no error term.
- `MAX_VARS = 30` caps every domain. In particular, a single matmul has
  `log(batch) + log(out) + log(d) <= 30`. A larger shape is split into row blocks
  at module level, and the plan fixes the split; the engine never splits a relation.

### 3.2 Identity

`Identity { vars: m, terms }`: for every `x ∈ {0,1}^m`, `Σ_t c_t · Π_f f(x) = 0` over Z.

- Each term has at most 3 factors, so the zerocheck degree with `eq` is at most 4
  (RFC-0006 A3).
- `c_t` is a nonzero i64.
- A factor may be a public column, which gives public coefficient vectors, masks and
  selectors.

### 3.3 Lookup

`Lookup { vars, selector, tuple, table }`: for every `x` where the selector equals 1
(every `x` when there is no selector), `(tuple_1(x), …, tuple_k(x))` is a row of `table`.

- A selector must be a public 0/1 column.
- The tuple has `c ∈ {1, 2}` columns, and a table has at most `2^16` real rows
  (RFC-0008 A2 item 5). A wider tuple is split into several lookups by the module.
- Tables are public, with declared widths for each table column. CQIS tables come
  from `stele_cqis::tables::Table::generate` (RFC-0021 §4) and are converted row for row.

### 3.4 Range

`Range { column, width }`: every entry of the column lies in `width`, where
`width.bits <= 16`.

- Proof: a lookup of `v − width.min()` into a public table of `2^bits` consecutive
  integers.
- A wider value is split into limbs (§3.5).

### 3.5 Matmul (two-factor contraction)

`Matmul { free: a, summed: s, out, lhs, rhs }`: for every `x ∈ {0,1}^a`,

`out(x) = Σ_{y ∈ {0,1}^s} lhs(x,y) · rhs(x,y)`

with `y` on domain bits `a..a+s`.

- `out` reads free bits only.
- `lhs` and `rhs` are columns of any kind: witness × weight is a projection,
  witness × witness is `QKᵀ` or `P̂V`, and public × weight is the embedding gather.
- A free bit read by both `lhs` and `rhs` is a **shared** bit, for example a batch
  or head bit. Without shared bits, `Σ_y lhs~(ρ,y)·rhs~(ρ,y)` is multilinear in `ρ`
  and equals `out~(ρ)`. With shared bits it is not multilinear, so the proof (§4,
  step 6) sums over the shared bits too, under the factor `eq(ρ_shared, x_shared)`.

### 3.5a Compose

`Compose { column, limbs: [(limb, shift)] }`: for every index `i`,
`column[i] = Σ 2^shift · limb[i]` over Z. Every limb has the column's `log_len`.

- In the proof it is one identity in the zerocheck of its domain size, under the
  bound rule: `mag(column) + Σ 2^shift · mag(limb) < p`.
- It disciplines `column` (§3.6 item 3) when every limb is disciplined and the
  composed range `[Σ 2^shift·limb.min, Σ 2^shift·limb.max]` lies within the
  column's width. This is how a column wider than 16 bits, up to 30, is declared:
  a quotient, a scale or a limb-composed value.

**Limb rule.** A value that does not fit the bound rule (§3.6), or is wider than 30
bits, is represented as radix-`2^b` limb columns with explicit carry columns. Each
limb relation is bound-checked on its own, and a value wider than 30 bits never
appears whole in any relation.

- Limbs and carries follow the LIMBS/LIMB-PRODUCT/WIDE-RANGE research consumers
  (`research/cqis-bounds/LIMBS.md`, `LIMB-PRODUCT.md`, `WIDE-RANGE.md`) and RFC-0003 A5.
- Each limb has a range check, and the final carry is pinned to zero.

### 3.6 Static validity, bound rule and range discipline

`Relation::validate` is the bound certificate of INV-5 for this profile. Prover and
verifier both run it on the plan-derived relation, before any proof message is read.
It rejects the following:

1. **Malformed shapes**:
   - a width outside `1..=30`;
   - a public column whose length or values do not fit its declaration;
   - a non-injective, out-of-domain or wrong-arity `Ref`;
   - more than 3 factors in a term, or a zero coefficient;
   - a lookup arity that differs from the table's or is outside `{1, 2}`, a table
     with more than `2^16` rows, or a selector that is not public 0/1;
   - a `Compose` with no limbs, a limb of another length, or a shift above 30;
   - a range wider than 16 bits, or a range on a public column;
   - a witness column whose group is missing or has a different `log_len`.
2. **The bound rule.**
   - For an identity: `B = Σ_t |c_t| · Π_f mag(width_f) < p`, where
     `mag(w) = max(|w.min|, |w.max|)`.
   - For a matmul: `B = mag(out) + 2^s · mag(lhs) · mag(rhs) < p`.
   - Why this is enough: when every column lies within its width, the integer value
     `V` of the relation at any point satisfies `|V| <= B < p`. So `V ≡ 0 (mod p)`
     implies `V = 0`. RFC-0022's column lemma (each side `< p/2`) is the same argument
     with the positive and negative parts kept separate.
   - Lookup tuples need no extra rule. Every width is at most 30 bits, so distinct
     integers have distinct residues, and field membership implies integer membership.
   - In the proof, the integer value of a committed entry is the centered
     representative of its M31 element, in `(−p/2, p/2)`. Range discipline places
     that representative within the declared width.
3. **Range discipline.** Every witness and weight column must be **enforced**: its
   declared width must hold for every entry. Without that, the bound rule could not
   rely on the declared widths. Public columns are enforced by validation. A column
   is enforced by any of the following, applied to a fixed point:
   - a range check whose width lies within the column's width;
   - a lookup with no selector whose table column width lies within it. A lookup
     with a selector does not count, because unselected rows are left unconstrained;
   - a `Compose` (§3.5a) of enforced limbs whose composed range lies within it;
   - being a matmul `out` whose `lhs` and `rhs` are enforced, when the worst case
     `Bp = 2^s·mag(lhs)·mag(rhs)` satisfies `Bp <= width.max` and
     `−Bp >= width.min`. Soundness: the true sum `V` has `|V| <= Bp`, so `V` lies in
     the width. The matmul proof gives `out ≡ V (mod p)`, and both centered values
     lie in `(−p/2, p/2)`, so `out = V` over Z. Identities cannot express this case,
     because they are pointwise and cannot sum over lanes.

### 3.7 Plain checker

`check(relation, values)` runs `validate`, then evaluates every relation over Z in
this order:

1. ranges, which report a column index;
2. lookups, which report a domain point;
3. compositions, which report an index;
4. identities;
5. matmuls.

It returns the first `Violation`. The checker is the specification oracle:

- Every module's honest witness must pass it.
- Every tamper control must fail it, for the same reason the proof rejects.
- The proof engine (E16-02) must accept exactly the `(relation, values)` pairs the
  checker accepts, except with the error of §6.

### 3.8 Module contract

The `Module` trait has two methods:

- `declare(&mut self, &mut Relation)`. It allocates columns, groups, tables and
  relations from plan data only, and keeps the ids it needs. Prover and verifier
  both run it.
- `assign(&self, &Relation, &Capture, &mut Values)`. It fills only the module's own
  witness columns.

How modules connect:

- Modules are wired by passing `ColumnId`s of upstream outputs into downstream
  constructors. A module never reads values another module assigned.
- Each module defines its own `Capture` type. E16-03's capture supplies every
  intermediate the executor computes, and E16-10 maps the capture onto each
  module's type.

## 4. Protocol (transcript order)

Every challenge is drawn from one `Transcript<QM31>` (FS from the transcript object
only).

1. **Statement.** `Transcript::new(public)`, where `public` is the canonical encoding
   of the §1.1 public inputs. Then absorb `relation/statement`: the BLAKE3 digest of
   the canonical relation encoding (E16-02 fixes the codec), which both sides derive
   from the plan. The verifier rejects with `StatementMismatch` if the plan, `T`,
   `[r,e)` or the model class do not match.
2. **Group roots.** For each group in `GroupId` order, absorb `relation/roots` with
   the group's root. Each group's RFC-0010 A9 certificate is verified on its own
   transcript, as A9 specifies. The model-commitment roots were already bound in step 1.
3. **Multiplicity roots.** For each lookup and range check in relation order, the
   prover commits the RFC-0008 A5 multiplicity sources, which do not depend on any
   challenge. Their roots are absorbed and their certificates verified.
4. **Identities.**
   - For each domain size `m`, in increasing order, draw one `relation/identity`
     coefficient per identity of that size (each `Compose` counts as one identity
     over its column's domain). This is the RLC line.
   - Run one RFC-0006 A3 zerocheck on the combined polynomial, using the existing
     zerocheck labels.
   - The final values become claims on columns: one per (column, `vars` map) at the
     zerocheck point restricted to `vars`.
5. **Lookups and ranges.** One RFC-0008 A5 grouped lookup per lookup/range, in
   relation order, with the existing lookup labels.
   - Each emits claims on its tuple columns (through their `vars`) and on its
     multiplicity sources.
   - For public tables and selectors, the verifier evaluates the claims itself.
   - Lookup originals are column claims (§2.3), read through a `Ref` and, for a
     range, shifted by `−width.min()`. RFC-0008 A6 admits these tuples.
   - The Statement is derived as RFC-0008 A2 item 2 requires, from the relation and
     never from the proof: `N = 2^lookup.vars` (for a range, `2^log_len` of its
     column), `m = log N`, `b = min(m, 30)`, `r = 1`, `d = 4` (QM31), and `σ` equal
     to the public selector column or all ones when there is none.
   - Multiplicity sources are opened exactly as RFC-0008 A5 specifies, with its
     rank-one prefix-mask functional openings. They never go through `claim_batch`.
6. **Matmuls**, in relation order, for each one:
   - draw `ρ ∈ K^a` with `relation/point` (SZ line, `a/|K|`);
   - the prover sends `out~(ρ)`;
   - run one RFC-0006 A1 sumcheck over the `s` summed bits and the `k` shared free
     bits (§3.5) of `eq(ρ_shared, x_shared)·lhs~·rhs~`. Its degree is 2 when
     `k = 0` and 3 otherwise. This emits claims on `out`, `lhs` and `rhs`.
   - The existing matmul reduction (RFC-0007 A2) may replace this sumcheck when both
     operands are whole sources. The claim semantics are identical.
7. **Openings.**
   - Public-column and table claims are evaluated by the verifier, with
     `Table::evaluate` for tables.
   - Witness-column claims are mapped to group-source claims (§2.3). Weight claims
     target their weight source.
   - For each group source in `GroupId` order, then each weight source in model
     order, the claims are reduced to one point with RFC-0006 A2 mode 1
     (`claim_batch`), admitted for committed sources by RFC-0006 A8. That point is
     opened once with `verify_point` (RFC-0010 A9).
   - Multiplicity sources were opened in step 5.
8. **Argmax.** No extra step: the greedy check is relations over committed logits
   and public data (§5, row 13).

### 4.1 Proof container

`stele-dev-e2e-v1` is defined in `stele-proof`; E16-10 fixes its exact codec. It is
the following sequence of length-prefixed sections:

- header: magic, version, `cqis_id`;
- statement digest;
- the group certificates, each a root plus a certificate;
- the multiplicity certificates;
- for each domain size, its zerocheck proof;
- for each lookup, its proof;
- for each matmul, `out~(ρ)` and its sumcheck proof;
- for each source, its claim-batch proof and opening.

There is no compression or optional section. The verifier rejects trailing bytes
with `ProofShape`.

## 5. Operation map

Each row names the integer definition it must reproduce, the columns a module commits,
and the relation kinds it uses (I identity, L lookup, R range, M matmul, P public).

Notation: `T` is the number of tokens, `d` the model width, `h` the number of heads,
`dh` the head width, `f` the FFN width and `V` the vocabulary size.

**Shared patterns.** Each module states which of these it uses:

- **sign/abs**: `X = (1−2σ)·A`, with `σ` a 0/1 column and `A ≥ 0` range-checked.
- **round-half-away division** `R(n/d)`, RFC-0025 §2 (applies to a public or committed `d`):
  - `|n| = q·d + ρ`, with `0 <= ρ < d` enforced by range checks on `ρ` and `d−1−ρ`;
  - a 0/1 column `β` that is 1 exactly when `2ρ >= d`, enforced by a range check on
    `(2β−1)(2ρ−d) − (1−β)`;
  - `y = (1−2σ)(q+β)`.
- **attained maximum** (glossary "attained"):
  - `M − v_j >= 0` for every `j` in scope, by a range check on a masked difference;
  - a witness 0/1 one-hot `h` with `Σ h = 1` over the scope (M row sums);
  - `Σ h·(M − v) = 0`.
  - The value of `M` is then unique.
- **limbs**: as in §3.5 and §3.5a.
- **zero-row branch** (RFC-0025 §2.2, `s = 0` when every code is 0):
  - a 0/1 witness `z` per row, with identities `z·M = 0` and `z·q_i = 0` for every `i`;
  - the division by the scale uses `s + z` as its divisor, with a range check
    `s + z − 1 >= 0`, so the divisor is at least 1;
  - when `M > 0`, `z = 0` is forced. When `M = 0`, the ceiling below forces `s = 0`,
    so `z = 1` and every code is 0.
- **row-scale ceiling** `s = ceil(M/127)`: a range check on `127·s − M ∈ [0, 126]`.
  Dynamic int16 scales stay at most 259.
- **gated-scale ceiling**: the same for the gated conversion (RFC-0004 A8). Its scale
  goes up to 8454661 (24 bits), so `s` is a `Compose` of range-checked limbs, and
  `127·s − M` is checked as in the row-scale ceiling, with `M` itself in limbs.

| # | Op | Integer definition | Columns (per layer unless noted) | Kinds | Task |
|---|---|---|---|---|---|
| 1 | embedding gather | RFC-0025 §2.5 (family 1): `R0 = R(e_{t,k}·m_t·2^(ee+f0))` | `G = onehot(x)·E` (T×d, int8); `R0` (T×d, int16) + rounding columns. `m_t` gathered as a public column from `Scales` | M (public onehot × weight), I, R, P | E16-04 |
| 2 | rmsnorm_q (v1) | RFC-0021 §2.3 (sum of squares, exponent `a`, quotient `M`, `J = rsqrt_q[M]`, `Y = R(X·H·J/2^e)`); bounds `full-model-rms-bounds.md`, `research/cqis-bounds/NORM*.md` | `S` as limb row sums (M of limb products); `a` as a one-hot over its public range; `M`, remainder; `(M, J)`; output `Y` (T×d, int16) + rounding when `e >= 0`, or the exact multiply `Y = X·H·J·2^(−e)` when `e < 0`. The branch is selected through the `a` one-hot (`e` is affine in `a` with public `F, G, E`) | M, I, L (`rsqrt_q`), R | E16-04 |
| 3 | row conversion (every projection input) | RFC-0025 §2.2 dynamic/static rows; RFC-0004 A8 gated kind; bounds `full-model-flow-bounds.md` §1, `research/cqis-bounds/ROW*.md`, `DYNAMIC-SCALE.md`, `ATTAINED-MAGNITUDE.md` | row maximum `Mx` (attained), scale `s` by the row-scale (or gated-scale) ceiling, the zero-row branch `z`, codes `q` (int8, from `R(2|x|/(2(s+z)))` with sign/abs) and division columns; grouped rows (RFC-0004 A15) apply this per group of `g` | I, R, M (row sums) | E16-05 |
| 4 | Q/K/V/O/gate/up/down/head projections | RFC-0025 §2.2: `A = Σ q·w`, `Y = R(A·m_j·s·2^(e−f+fo))`, one rounding; bounds `full-model-bounds.md` §3, `SCALED-LINEAR.md`. Not RFC-0023/0024 Requant: the multiplier `m_j·s` exceeds u16 | `A = q·W` (M, witness × weight; `|A| < 2^28`); `A·m_j·s` as limb products with public `m_j`; output `Y` + rounding | M, I, R, P | E16-05 |
| 5 | RoPE | RFC-0025 §2.4 / RFC-0004 A7 coefficients: `x' = R((x·c − y·s)/2^14)`; layout 0/1 pairs; `ROTARY.md`, `ROTARY-CONSUMER.md` | `Q'`, `K'` (int16) + rounding; `c`, `s` as public columns from `model::rotary::Rotation::coefficient` | I, R, P | E16-06 |
| 6 | scores | RFC-0025 §2.4, RFC-0009 A4: `score = R(dot(q_i,k_j)·sq_i·sk_j·m_score·2^(e_score−fq−fk+Fexp))` over whole-row int8 codes; `ATTENTION-SCORE.md` | Q/K row conversion (pattern of row 3); `dot` (M per head, witness × witness, `Ref` head split); scaled product as limbs; `score` + rounding | M, I, R | E16-07 |
| 7 | causal max | RFC-0025 §2.4: maximum over keys `j <= i`; `ATTENTION-MAX.md`, `ATTENTION-MAXIMUM-CONSUMER.md` | `Mx` per (head, i), attained over the causal scope (public causal mask factor) | I, R, M, P | E16-07 |
| 8 | exp | RFC-0021 §2.1 modes 0/1/2: `t = score − Mx ∈ [−2^B, 0]`, direct, product or corrected; `ATTENTION-EXP*.md` | `t` (masked to 0 outside scope); `P̂` (unsigned `E+1` bits) via `exp_q/direct` or `exp_q/hi`, `exp_q/lo` (+ `exp_q/correction`) | L, I, R | E16-07 |
| 9 | normaliser and P̂·V | RFC-0025 §2.4, RFC-0004 A6, RFC-0009 A4: `Z = Σ P̂_j > 0`; `D = sv_j·v_jc`; `T_c = Σ P̂·D` (exact, or block mode with `B_bc = R(Σ_block P̂D/2^c)`); output `R(T_c·2^(fo−fv+c)/Z)`; `ATTENTION-NORMALIZATION.md`, `ATTENTION-BLOCKS.md`, `ATTENTION-VALUES.md`, `ATTENTION-DIVISION.md` | V row conversion; a committed masked `P̂m = causal·P̂` (an identity), because a matmul has only two factors; `Z` (M of `P̂m` with ones); `D`; `T` as limbs (`|T| < 2^50`); quotient, remainder; head assembly before one O-input row conversion | M, I, R, P | E16-07 |
| 10 | SiLU gated product | RFC-0025 §2.5, RFC-0004 A8, RFC-0021 §2.2: `silu_q[t]`, `T = U·silu_q(G)` exact int32 (`|T| <= 2^30`); then gated row conversion; `GATED-PRODUCT.md`, `SILU-CONSUMER.md`, `GATED-CONSUMER.md` | `(G, silu_q(G))` lookup; `T` as limbs (`2^30` > 30-bit signed width); gated conversion → down-projection codes | L, I, R | E16-08 |
| 11 | residual add | RFC-0025 §2.2: `c = max(fx, fy, fo)`, `R((X·2^(c−fx) + Y·2^(c−fy))/2^(c−fo))`, int16 (v1); `RESIDUAL*.md` | `R_mid`, `R_{ℓ+1}` + rounding | I, R | E16-09 |
| 12 | final norm, head | RFC-0025 §2.5: rmsnorm_q, final row conversion, unbiased head with `fl ∈ [0,30]`, int16 logits; tied head reads the embedding source | rows 2–4 instances (global group `G/…`) | as rows 2–4 | E16-09 |
| 13 | greedy argmax | RFC-0025 §2.6: least id attaining the maximum; `research/cqis-bounds/GREEDY.md` | `sel_i = Σ_v O[i,v]·L[i,v]` (M, public one-hot `O` of `c_i` on checked rows); margin `Mg[i,v] = chk[i,v]·(sel_i − L[i,v]) − lt[i,v]`, unsigned 16; public `chk[i,v]` (checked row and real vocabulary id `v < V`) and `lt[i,v] = chk[i,v]·[v < c_i]` | M, I, R, P | E16-09 |

Row 13 is sound for the following reasons:

- Logits are int16, so `sel − L ∈ [−65535, 65535]`.
- `Mg >= 0` for every `v` makes `sel_i` a maximum.
- Every `v < c_i` with `L = sel_i` would give `Mg = −1`, so `c_i` is the least id
  attaining the maximum.
- The one-hot `O` fixes `sel_i = L[i, c_i]`.
- Unchecked rows and padded vocabulary ids have `Mg = 0`, because `chk = 0` and
  `lt = 0` there. A padded logit therefore never competes.

### 5.1 Interfaces between modules

Only the following columns cross module boundaries. Widths are for the version-1
stream.

| Producer → consumer | Column | Width |
|---|---|---|
| E16-04/09 → E16-04 | residual `R_ℓ` (T×d) | int16 |
| E16-04 → E16-05 | norm output `Y` (T×d) | int16 |
| E16-05 → E16-06/07/08 | projection outputs Q, K, V (T×h·dh), gate and up (T×f) | int16 |
| E16-06 → E16-07 | `Q'`, `K'` | int16 |
| E16-07 → E16-05 | attention output (T×h·dh), before the O-input row conversion | int16 |
| E16-08 → E16-05 | gated product `T` limbs with the gated-conversion inputs | as declared by E16-08 |
| E16-05 → E16-09 | O and down outputs | int16 |
| E16-09 → E16-04 | `R_{ℓ+1}`; logits (T×V) | int16 |

### 5.2 Encoding obligation

The plain checker shows completeness: honest values pass. It cannot show soundness.
Each module PR must therefore also provide two things:

1. **An output-uniqueness lemma.** For any input columns within their widths, every
   assignment that satisfies the module's relations gives the same output columns.
   Those outputs are the executor's. Auxiliary columns may be non-unique only where
   the outputs do not depend on them, for example `σ` at `X = 0`.
2. **Near-miss tests.** For each output, take the executor value ±1 and the other
   rounding direction, together with the strongest auxiliary assignment the author
   can construct. The plain checker must reject each of them.

Soundness of the whole statement is these lemmas composed along §5.1, together with
the proof error of §6.

## 6. Soundness

Every term is an existing RFC-0012 line. Nothing new is invented.

| Source | Line | Formula | Status |
|---|---|---|---|
| identity combination (one per domain size) | RLC | `(#identities of that size)/|K|` | proven |
| zerocheck per domain size | SC | RFC-0006 A3 `m·δ/|K|`, `δ <= 4` | proven |
| matmul point `ρ` | SZ | `a/|K|` per matmul (RFC-0012 A14) | proven |
| matmul sumcheck | SC | `(s+k)·δ/|K|` per matmul, with `δ = 2` if `k = 0` and 3 otherwise | proven |
| lookups and ranges | LU | RFC-0012 A8/A11 per lookup, `r = 1`, plus tree/leaf terms | proven |
| claim batching per source | RLC + SC | RFC-0006 A2 mode 1 | proven |
| certificates and openings | PCS | RFC-0012 A15 per source | conjectural; not admitted (Q12) |
| Merkle/hash | H | RFC-0012 A15 | proven under its caps |
| Fiat–Shamir | FS | placeholder | unproven (Q12) |

- **Transcript labels.** Steps 1, 2, 4 and 6 add four labels, through RFC-0012 A16:
  - absorb `stele/v0.1/relation/statement`;
  - absorb `stele/v0.1/relation/roots`;
  - challenge `stele/v0.1/relation/identity` (RLC);
  - challenge `stele/v0.1/relation/point` (SZ).
- **Ledger output.** The verifier computes and prints the full ledger. A development
  proof reports `ε_interactive` (every line except FS) and states "FS unproven, PCS
  conjectural".
- **Fiat–Shamir at r = 1 fails.** QM31 with `r = 1` fails RFC-0012 §4's FS charge
  (Q times the largest round error) at real shapes: the LogUp pair round is near
  `2^-10` (RFC-0008 A2 item 8). The development profile accepts this, because it
  claims no non-interactive security; promotion needs Q12 and, at least, the
  `treaty` lookup parameters.
- **Integer faithfulness** follows from §3.6: the bound rule, plus range discipline
  under the LU line.

## 7. Prover and verifier cost

The development profile claims no cost-model term, and no constant moves.

- **Prover:** one commitment per group, one zerocheck per domain size, one LogUp per
  lookup or range, one sumcheck per matmul, and one opening per source.
- **Verifier:** linear in public columns and tables. It evaluates the MLEs of public
  columns and tables directly.
- **Shape cap.** `MAX_VARS = 30` caps each relation domain (§3.1). Matmuls with
  `log(batch) + log(out) + log(d) > 30` are split into plan-fixed row blocks by
  their module, which adds one matmul relation per block.

E16-11 measures both against FlashProve's small route (8 layers, T = 64, d = 512) and
records them in `bench/ledger/` (RFC-0018 A1); the comparison is in
`docs/development-e2e.md`.

## 8. Verifier algorithm

1. Decode and check the public inputs. Reject an unsupported model class.
2. Run every module's `declare` from the plan, then `Relation::validate`. On any
   `Invalid`, reject with `StatementMismatch`.
3. Replay §4: verify certificates, zerochecks, lookups, matmul sumchecks, claim
   batches and openings, in that order.
4. Evaluate every public-column and table claim. Reject on the first mismatch, with
   the primitive's typed error.
5. Accept, and print the ledger.

Placement: the development verifier sits in `stele_reductions::relation` (the engine)
and `stele_prover::development` (container and orchestration). `stele verify-dev`
calls it. The no_std `stele-verifier` is unchanged, and no new Cargo edge is needed:
`stele-cli` already wraps `stele-prover`, which wraps `stele-reductions`.

## 9. Negative controls

The following controls are reserved as NC-1300..1310. Each must run through the
actual E16-10 verifier.

| NC | Tamper | Expected |
|---|---|---|
| 1300 | change one checked token `x_{i+1}` | `FinalEvaluationMismatch` (margin range/identity) |
| 1301 | change `y` | `FinalEvaluationMismatch` |
| 1302 | +1 on one witness value of a group, recommitted honestly | `FinalEvaluationMismatch` (the identity holding it) |
| 1303 | send one group message element as the noncanonical limb `p` | `NoncanonicalField` |
| 1304 | prove with other weights under the expected model commitment | `RootMismatch` |
| 1305 | change one plan parameter (one rounding exponent) on the prover side | `StatementMismatch` |
| 1306 | swap two group roots | `RootMismatch` |
| 1307 | +1 on one matmul `out~(ρ)` | `RoundSumMismatch` |
| 1308 | route one column claim to the neighbouring column index of its group | `ValueMismatch` |
| 1309 | change `[r,e)` | `StatementMismatch` |
| 1310 | commit one ranged witness value as `2^30`, outside its declared width, with every identity recomputed | LU rejection (`RootMismatch`, the A5 root equation of the range lookup) |

## 10. Open questions

- **Q33** (mirrored in RFC-0019). The development profile depends on three things:
  - a per-module output-uniqueness lemma (§5.2), which is written and tested but not
    machine-checked;
  - a conjectural PCS;
  - an unproven FS line (Q12).

  What would promote a development proof to `standard`? At minimum: Q12; a PCS
  parameter set admitted under RFC-0012 A15; formal statements of the uniqueness
  lemmas (R-FORMAL); and the RFC-0011 passport binding.

## 11. Amendment log

- **E1 (erratum, task E16-02).** §2.3 wrote the source point as `(ρ ‖ bits(k))`;
  in the MSB-first point order of RFC-0005 §2 it is `(bits(k) ‖ ρ)`, with the column
  index in the leading coordinates, as the text already said. §9 NC-1310 named
  `FinalEvaluationMismatch`; the first failing check is the A5 root equation,
  `RootMismatch`. No protocol change.
- **E2 (erratum, task E16-10).** §9 NC-1300 and NC-1301 named
  `FinalEvaluationMismatch`. A false checked token or `y` leaves a margin entry at
  `-1`, outside its unsigned range, and the first failing check is that range's A5
  root equation, `RootMismatch`, as for NC-1310 (E1). NC-1305 and NC-1309 named
  `StatementMismatch`, which is the verifier's fail-fast comparison with a header field
  the prover writes. The binding is §4 step 1: the transcript absorbs the public input
  and the relation digest. With the header set to the verifier's own digest, the first
  failing check is the first zerocheck round, `RoundSumMismatch`. No protocol change.
- **E3 (erratum, task E16-11).** The A3 and A4 motivations quoted proof-byte and time
  measurements that had no `bench/ledger/` record (AGENTS.md §4). They now state the
  reasons without the figures, and §7 points to the E16-11 comparison.
  Development-profile measurements are recorded under
  RFC-0018 A1: `bench/ledger/e16-11-dev-synthetic-8layer.json` and
  `bench/ledger/e16-11-dev-stories42m.json`. No protocol change.

### A1 — RoPE pairs through a public-permutation matmul (row 5)

Status: Accepted. Decision: ADR-077. Review: [E16-06 notes](../../agents/reviews/e16-06-rope.md)
and the independent review of the E16-06 PR.
Motivation: row 5 lists kinds `I, R, P`, but an identity is pointwise. A `Ref` can
permute or drop domain bits, but cannot flip or fix one, so no identity can read
the paired channel `i XOR 2^k` (§3.1). An extra domain bit would work only for
layout 0, or for layout 1 with `r/2` a power of two.

Replacement for row 5, columns "Columns" and "Kinds":

> `Q'`, `K'` (int16) + rounding; `c`, `s` as public columns from
> `model::rotary::Rotation::coefficient`; the paired input `P = x·Perm` (int16) by
> one matmul per tensor with a public 0/1 permutation `Perm` over the head
> channels | I, R, M, P

Soundness ledger: one M per rotated tensor (Q and K per layer), with the existing
§6 lines: SZ `a/|K|` and SC `2d/|K|` with `d = log dh` (no free bit is shared). No new
line or label.
Cost model: none; the development profile claims no cost term.
Affected tasks: E16-06 (implements it), E16-10 (counts the matmul in the ledger).

- **A3 — One A5 statement per table (task E16-12).** Accepted with ADR-078.
  - **Motivation.** One A5 instance per lookup or range gave each check its own
    multiplicity source, certificate and pair of trees. On the E16-10 8-layer model
    (d=64, T=64), the 3,755 multiplicity sources and the lookup proofs were most of
    the proof bytes. Batching them by table met the E16-12 acceptance criterion on a
    lookup-heavy synthetic relation (80 checks into 3 tables). Current end-to-end
    proof sizes are in `bench/ledger/` (E3).
  - **Replacement text, §4 step 3.** "For each **check**, in check order, the prover
    commits the RFC-0008 A5 multiplicity source, which depends on no challenge. Its
    root is absorbed with `relation/roots` and its certificate verified. A check is
    the set of every lookup with the same `TableId`, or every range with the same
    `width.bits`; ranges of either signedness read the same table `[0, 2^bits)`
    through the shift `−width.min()`. Checks are ordered by first use, with lookups in
    relation order first, then ranges in relation order."
  - **Replacement text, §4 step 5, first bullet and Statement bullet.**
    - "One RFC-0008 A5 grouped lookup per check, in check order, with the existing
      lookup labels."
    - "**Concatenation.** The members of a check are its lookups and ranges, in
      relation order, then stably sorted by domain size `m_i`, largest first. Member
      `i` occupies positions `[o_i, o_i + 2^m_i)` of one original domain of `2^m`
      positions, with `o_i = Σ_{j<i} 2^m_j` (a multiple of `2^m_i`) and
      `m = ceil(log2 Σ 2^m_i)`.
      - On member `i`'s block, tuple column `c` reads `x_c(o_i + u) =
        tuple_{i,c}(u)`, shifted by `−width.min()` for a range.
      - `σ` is the member's public selector, or all ones, on its block, and 0 on the
        padding.
      - Padding positions read 0.
      - The Statement is RFC-0008 A2 item 2 over this domain: `N = 2^m`,
        `b = min(m, 30)`, `r = 1`, `d = 4`. A check with `m > 30` is rejected
        (`Unsupported`), so `h = 0`, multiplicities precede every challenge, and each
        count is at most `2^30 < p`."
    - "**Member split.** At the selected-product point `z ∈ K^m` (MSB-first), the
      prover sends `v_{i,c} = tuple_{i,c}~(z_low_i)` for each member and column, where
      `z_low_i` is the last `m_i` coordinates of `z`. The verifier checks
      `Σ_i eq(z_high_i, bits(o_i / 2^m_i))·v_{i,c} = x_c~(z)` for each column, and
      rejects with `MemberSumMismatch` otherwise. Each `v_{i,c}` (plus `width.min()`
      for a range) then becomes a column claim through the member's `Ref` at
      `z_low_i`."
  - **Soundness.**
    - *Unchanged arithmetic.* A3 is the A5 argument on one original with
      RFC-0008 A6 tuples. The concatenation is a fixed public interleaving of
      committed columns. Every group root is absorbed before the check's Beta and
      Alpha draws.
    - *Split is exact.* For an aligned block,
      `x_c~(z) = Σ_i eq(z_high_i, bits(o_i/2^m_i))·tuple_{i,c}~(z_low_i)`, because the
      padding reads 0. So the split check has no Schwartz–Zippel loss.
    - *Split values bound.* The member values are not absorbed when sent. Each one is
      then a claim on a committed source. That source's RFC-0006 A8 batch descriptor
      absorbs it before the batch coefficient, and no draw in between depends on it.
    - *Ledger.* The LU line becomes `(2^m + c·t − 1)/|K|` once per check, instead of
      once per lookup. The A3 tree and leaf lines are charged once per check.
  - **Prover cost.** Per check, the honest prover holds `c + 1` dense tables of `2^m`
    QM31 values (originals and selector) plus `2^m` leaf pairs: about
    `16·(c + 3)·2^m` bytes. Its time is `O(2^m + 2^k)` field operations, plus
    `O(c·Σ 2^m_i)` for the split.
    - Rounding `Σ 2^m_i` up to `2^m` can nearly double the padded `N` of a check.
      The LU numerator and the dense tables grow with it.
    - Batching every same-width range into one domain makes `m > 30` reachable on
      large models, and such a check is rejected (`Unsupported`) rather than split.
      A check-splitting rule would be a further amendment.
    - Field work summed over all checks is about the same as one check per lookup,
      up to the padding factor. Peak prover memory is not: it is set by the largest
      check, about `16·(c + 3)·2^m` bytes, where it used to be the largest single
      lookup.
  - **Cost-model terms.** None (the development profile claims none).
  - **Affected tasks.** E16-12, E16-10.
  - **Control.** `rejects_member_values_that_do_not_sum_to_the_batched_claim`. A
    lying prover commits one witness, proves the lookup on another, and reports the
    member values of what it committed. Only the split check rejects it.
- **A4 — One stacked source (task E16-13).** Accepted with ADR-082.
  - **Motivation.** Each commitment group used to be its own RFC-0010 v2 source, so
    every group paid for its own certificate and opening. On the E16-10 8-layer model
    the 255 group certificates and 313 openings were most of the remaining proof
    bytes, and stacking reduced both on a 40-group synthetic plan. Current end-to-end
    proof sizes are in `bench/ledger/` (E3).
  - **Replacement text, §2.3 (first two bullets and "Order").**
    - **Layout.** "Each commitment group's columns form a block of `2^(n+c)`
      entries, with the column count padded with zero columns to `2^c`. The blocks
      of every group in a proof form **one** RFC-0010 v2 source, the **stacked source**.
      Blocks are placed largest first (ties in `GroupId` order) at offsets that are
      multiples of their size. The message has `2^S` entries with
      `S = max(6, ceil(log2 Σ 2^(n+c)))`, and unused entries are zero."
    - **Column claim.** "Column `k` of a group with `n`-bit columns at block offset
      `o` maps a claim at `ρ` to the stacked-source claim at the MSB-first point
      `(bits(o/2^n + k) ‖ ρ)`, where the index has `S − n` Boolean coordinates. The
      conversion is exact."
    - **Geometry.** "The v2 expander exponent `J ∈ 3..=min(14, S/2)` is the one
      that minimises certificate plus opening bytes (ties: smallest `J`), with
      `ell = S − 2J`. A stacked source with `S > 30` is rejected."
  - **Replacement text, §4 step 2.** "If the relation has a commitment group, absorb
    `relation/roots` with the stacked root. The stacked source's RFC-0010 A9 certificate is
    verified on its own transcript."
  - **Replacement text, §4 step 7, group bullet.** "All group claims are mapped to
    stacked-source claims and reduced with one RFC-0006 A2 mode-1 batch (A8), then opened once
    with `verify_point`. Weight sources follow, each as before."
  - **Replacement text, §4.1.** "The group certificates are replaced by **one**
    stacked-source certificate, a root plus a certificate. There is at most one group opening,
    for the stacked source."
  - **Replacement text, §9 NC-1306.** "Root substitution: replace the stacked root with a multiplicity root:
    `RootMismatch`."
  - **Soundness.** Unchanged:
    - The stacked root is fixed (step 2) before every challenge.
    - Every column claim is a stacked-source claim at a point whose leading coordinates are
      Boolean and known to the verifier, so the conversion adds no Schwartz–Zippel
      term.
    - The A8 batch and A9 opening arguments are the same, on one source.
    - The ledger loses one RLC and SC batch line per removed source, and the PCS
      line is charged once for the stacked source.
  - **Not stacked.**
    - *Multiplicity sources* keep RFC-0008 A5's own layout and prefix-mask openings.
      After A3 there is one per table, so few remain.
    - *Weight sources* stay the model commitment, one source per weight.
  - **Prover cost.** One `2^S` M31 message, plus one QM31 copy of it for the batch.
    Peak memory is about `24·2^S` bytes (the committed and proving M31 messages and one QM31 batch table), plus the encoded columns, against the same per group before. Under
    the stated layout, padding `Σ` up to `2^S` costs at most a factor of 2.
  - **Limit.** The certificate and opening still grow with the stacked source. Under Policy 1
    query counts, a source of `2^S` entries costs about `16·4^J + Q·(4·2^(S−2J) +
    32·(2J+1))` bytes at its best `J`. That is roughly `44·2^S` bytes at `J = 3`,
    and about `2^(S/2 + 11)` bytes at large `S`. Stacking removes the per-group terms,
    but proofs well below about `2^(S/2 + 12)` bytes need a different PCS parameter
    choice (RFC-0010), which is not part of this amendment.
  - **Cost-model terms.** None.
  - **Affected tasks.** E16-13, E16-10.

### A2 — The 1-D artifact records are public inputs (§1.1 item 1)

Status: Accepted (owner authorisation; independent review in the E16-10 PR).
Decision: ADR-085.
Motivation: the rmsnorm_q module (row 2, E16-04) reads its gains `H` as public
columns, so the verifier needs them to rebuild the relation (§8 step 2). The gains
are 1-D artifact records (RFC-0025 §2.1: first, second and final gains). §1.1 binds
neither them nor any commitment to them, and §2.2 commits only matrices.

Replacement for §1.1 item 1:

> 1. `cqis_id`, the canonical `Model`, `Scales` and `Preparation` bytes (RFC-0025
>    §2.7), and every 1-D artifact record as its ordinal and its canonical artifact
>    payload bytes, in artifact record order. The verifier decodes them itself.
>    Mantissas, exponents, fractions, policies, function representations and norm
>    gains are therefore public data, not witness.

Rationale: the gains are model parameters the verifier must know to rebuild the
relation. Binding them in the first transcript frame, before any challenge, is the
treatment the mantissas already get. The development profile is not zero-knowledge
(§1.2), so revealing them adds no leak. Profiles with zero-knowledge will need
committed gains read as weight columns, which changes §2.2 and row 2.
Soundness ledger: none; no challenge, line or label changes.
Cost model: none. Affected tasks: E16-10 (statement codec and public-input file).

- **A5 — Stacked model commitment (task E16-14).** Accepted with ADR-084.
  - **Motivation.**
    - On the E16-10 8-layer model each weight tensor was its own source, so weight
      openings made up nearly all opening sections of a proof.
    - The model commitment carried one certificate per weight.
    - Stacking leaves one opening per model source (measurements in the E16-14 PR;
      ledger entries belong to E16-11).
  - **Replacement text, §1.1 item 2.** "The **model commitment**: the root of each
    model source (§2.2), in split order. A model of at most `2^30` weight entries has
    exactly one model source."
  - **Replacement text, §2.2, "Each weight tensor" bullets and the "matched to the
    model-commitment roots in order" bullet.**
    - "Every `Kind::Weight` column belongs to a **model source**, an RFC-0010 v2
      source, as a block of `2^n` entries. The order is `ColumnId`, and a tied head
      reuses the embedding's column, so it adds no block. Values are the original
      integer codes under the RFC-0010 A6 signed embedding."
    - "**Split.** Weights are assigned in `ColumnId` order to model sources
      `0, 1, …`. A weight starts a new source when adding it would take the current
      source past `2^30` entries."
    - "**Placement.** Inside a source, blocks are placed largest first, with ties in
      `ColumnId` order, at offsets that are multiples of their size. Source `k` has
      `2^(S_k)` entries with `S_k = max(6, ceil(log2 Σ 2^n))`, unused entries are
      zero, and its id is `2^32 + k`. The geometry is A4's byte-minimising `J`. A
      weight with `n > 30` is rejected."
    - "The model commitment is the list of model-source roots, each with one
      RFC-0010 A9 certificate, computed once per model. The verifier checks that the
      supplied certificates match the derived layouts one for one, each under its own
      root. On any count or layout difference it rejects with `Weights`."
    - "**Binding.** Right after the §4 step-1 statement digest, the engine absorbs
      every model root, in split order, with `relation/roots`. The proof therefore
      binds the model even when a caller's public input leaves the roots out."
  - **Replacement text, §9 NC-1304, expected error.** "`RoundSumMismatch`: the
    model root another commitment would produce is absorbed right after the
    statement, so the transcripts diverge before any opening."
  - **Replacement text, §4 step 7, weight bullet.** "For each model source `k`, its
    weight claims are mapped to model claims: weight `w` at block offset `o` with
    claim point `ρ` maps to `(bits(o/2^n) ‖ ρ)`, Boolean in the leading coordinates.
    They are reduced with one RFC-0006 A2 mode-1 batch (A8, batch id `BATCH|(1+k)`)
    and opened once with `verify_point` against that source's certificate. This
    comes after the stacked group source."
  - **Plan obligation (§2.2) unchanged.** The weight-order check now compares the
    derived layout: the same order and the same padded shapes.
  - **Scale (development-profile cap).** Each source is capped at `2^30` entries,
    which is RFC-0010 v2's own per-source cap. A model of `2^33` entries, about 8B
    parameters, needs 8 model sources. Peak memory per model source is set by its
    size:

    | Model-source size | Message, prepared once per model | QM31 batch copy, per proof |
    |---|---|---|
    | `2^30` entries | 4 GiB | 16 GiB |

    Weights are not split across sources; a weight above `2^30` is rejected. The
    open alternative is RFC-0010 A13 root-of-roots shards under one root, which
    would also shrink the per-proof batch copy. It is not adopted here.
  - **Soundness.** Unchanged:
    - Every model root is fixed before any challenge, both by the public input and
      by the absorption above.
    - Each weight claim becomes a model claim at a point with Boolean leading
      coordinates, so there is no Schwartz–Zippel term.
    - The A8 batch and the A9 opening arguments are the same.
    - The ledger has one weight batch (RLC + SC) per model source per proof, and
      the PCS line is charged once per model source.
  - **Cost-model terms.** None.
  - **Affected tasks.** E16-14 and E16-10. E16-10 commits each `model_messages`
    entry under the matching `model_layout` entry.
- **A6 — Row-block split of matmuls past `MAX_VARS` (task E16-19).** Accepted with ADR-092.
  - **Motivation.**
    - §3.1 and §7 say that a matmul with `log(batch) + log(out) + log(d) > 30` is split
      into plan-fixed row blocks by its module. A `Ref` could only permute or drop
      domain bits (A1), so a block could not read one slice of a shared column. Only
      the E16-04 embedding gather split, through per-block columns and a masked
      recombination identity.
    - Projections and attention therefore rejected such plans with
      `Unsupported::Domain`. The llama2.c stories110M head (`6 + 15 + 10 = 31` bits)
      could not be proven, and neither could `T >= 128` or `f >= 11008` shapes.
  - **Replacement text, §3.1, new bullet after the `Ref` bullet.** "A `Ref` of a
    matmul (`out`, `lhs` or `rhs`) may also **fix** column bit `j`: `vars[j]` is
    `FIXED_0 = 0xFE` or `FIXED_1 = 0xFF`, and the read index has bit `j` equal to 0 or
    1 whatever the domain point. In MLE terms the column's MLE is evaluated with
    coordinate `j` set to that Boolean value, so a fixed bit adds no error term.
    Identity and lookup refs never fix a bit."
  - **Replacement text, §3.1, `MAX_VARS` bullet.** "`MAX_VARS = 30` caps every domain.
    A matmul past it is split at declare time by `Relation::add_matmul` (§3.5,
    **row-block split**). Identity, lookup and range domains are never split; a module
    rejects a plan whose identity domain exceeds 30 bits with `Unsupported::Domain`.
    The proof engine never splits a relation."
  - **Replacement text, §3.5, new paragraph "Row-block split".**
    - "A matmul `M` with `a + s > 30` and `a >= 1` is replaced by two **row blocks**.
      The **split bit** `v` is the highest free bit that `rhs` reads (a row bit of the
      weight in a projection), or `a − 1` when `rhs` reads no free bit. Block `b`, for
      `b ∈ {0, 1}`, is named `{M.name}/block{b}`, has `free = a − 1` and `summed = s`,
      and its `out`, `lhs` and `rhs` are `M`'s with domain bit `v` replaced by
      `FIXED_b` and every domain bit above `v` decreased by one. The split repeats on
      each block, block 0 before block 1, until every domain has at most 30 bits. A
      matmul with `a = 0` is not split, and `validate` rejects it."
    - "A matmul that fits is pushed unchanged. Plans with no matmul past 30 bits
      therefore derive the same relation, the same digest and the same proof bytes as
      before this amendment."
    - "**Lemma S (exact recombination).** For every `x ∈ {0,1}^a`, let `b` be bit `v`
      of `x` and `x'` be `x` with bit `v` removed. Block `b`'s statement at `x'` reads
      exactly the entries `M`'s statement reads at `x`, in `out`, `lhs` and `rhs`: a
      ref that reads bit `v` reads the constant `b`, and a ref that does not read it is
      unchanged. The free points of the two blocks partition `{0,1}^a`, so the blocks
      hold over Z if and only if `M` holds. Nothing is recombined: `out` is the same
      column, and each block constrains its slice. The blocks are a function of
      `(a, s, M's refs)`, so the verifier derives them, and the prover chooses
      nothing."
  - **Replacement text, §3.6 item 1, `Ref` bullet.** "a non-injective, out-of-domain or
    wrong-arity `Ref`, or a fixed bit in an identity or lookup ref (injectivity and
    the domain bound apply to the non-fixed entries of a matmul ref);"
  - **Replacement text, §3.6 item 3, matmul bullet.** "being the `out` of a set of
    matmuls whose `lhs` and `rhs` are enforced and whose worst case
    `Bp = 2^s·mag(lhs)·mag(rhs)` satisfies `Bp <= width.max` and `−Bp >= width.min`,
    when the slices of their `out` refs cover every entry of the column. The slice of
    a ref is the set of indices whose fixed bits equal its constants. Soundness: each
    entry lies in the slice of one such matmul, whose true sum `V` has `|V| <= Bp`, so
    the argument of the unsplit case applies entry by entry."
  - **Replacement text, §5 rows 4, 6, 7, 9 and 12, column "Kinds".** "Every matmul is
    declared through `Relation::add_matmul` and is split into row blocks past 30
    bits. A projection rejects `log T + log o > 30` (its output domain); attention
    rejects `max(2·log T + log h, log dh + log h + log T + kb) > 30` (its score and
    block-mode value domains)." Row 1 keeps its E16-04 construction: per-block public
    one-hots, ranged block outputs and a masked recombination identity, with blocks of
    `T` rows. It is exact and plan-fixed; moving it onto fixed bits is left open.
  - **Soundness.**
    - A fixed bit is a Boolean coordinate of a column point, like the column index of a
      group claim (§2.3). It adds no Schwartz–Zippel term.
    - Each block is an ordinary §3.5 matmul with the existing §6 lines: SZ
      `(a − k)/|K|` and SC `(s + k_b)·δ/|K|` per block, where `k` is the number of
      splits above it and `k_b` its shared free bits. A split adds one matmul's lines
      per block and no new line kind, label or challenge.
    - The relation digest (§4 step 1) encodes every `vars` byte, fixed entries
      included, so prover and verifier bind the same blocks.
    - Module lemmas (§5.2) are unchanged by Lemma S. Range discipline of a split `out`
      is item 3 above.
  - **Prover cost.** The operand table of a block skips the entries outside its slice.
    An operand that reads the split bit is therefore read once in total across the two
    blocks; an operand that does not read it is read once per block. The split bit
    is chosen from `rhs` so that a projection's weight, its largest operand, is read
    once (INV-7 shape); the activation operand is read once per block.
  - **Cost-model terms.** None (the development profile claims none).
  - **Affected tasks.** E16-19 (implements it); E16-20 (stories110M, whose head is
    split into two blocks).
  - **Controls.** `rejects_out_tamper_in_each_row_block` (engine, one tamper per
    block), `rejects_out_covered_by_one_row_block` (discipline needs full cover),
    `rejects_fixed_bits_outside_matmuls`, and the projection deletion survey with four
    row blocks, where deleting any block is killed.

### A7 — Circle sources for the stacked and model commitments

Status: Draft (development-tier amendment under RFC-0027 §2). Task: E19-02.
Motivation: the stacked source (A4) and the model sources (A5) are RFC-0010 v2
expander sources. Under Policy 1 they need up to 13,472 certificate and 6,714 opening
responses, against 314 and 130 for the circle code at rate 1/4 (RFC-0010 A3 items 4
and 10). On the eight-layer synthetic proof the two source kinds are 35.3 MB of
45.0 MB (`bench/ledger/e17-00-dev-synthetic-8layer-4core.json`).

Replacement text, A4 "Geometry" bullet and the A5 sentence "The geometry is A4's
byte-minimising `J`":

> "The stacked source and every model source are RFC-0010 source version 1 (Circle,
> A9) with blow-up exponent 2. A source of `2^S` entries has `2^ell` rows of `2^m`
> message elements, `ell + m = S`. The plan chooses the `ell` that minimises
> certificate plus opening bytes under Policy 1 among the values A9 admits (ties: the
> smallest `ell`). A source with no admitted `(ell, m)` is rejected (`Unsupported`).
> A stacked source with `S > 30` is rejected, as before."

Everything else in A4 and A5 stands: layout, block placement, ids, the `2^30` cap per
model source, claim mapping, batching and one opening per source.

These are version-1 sources, whose rows are evaluations (RFC-0010 A2). The recursive
opening of RFC-0029 (Draft) needs coefficient-form rows, so task E19-03 changes the
row map once more and proof bytes change a second time. The development tier has no
long-lived model registration, so nothing needs migrating (RFC-0029 Q48).

Soundness ledger: the PCS line of each such source becomes the Circle line of
RFC-0012 A15 with A9's `N`, `D`, `e`, `q_c`, `q_o`. The v2 setup term leaves every
ledger that has no v2 source. No challenge or label changes.
Proof bytes change, so the pinned E16-10 proof hashes are re-recorded by the task.
Cost: rows are encoded by the circle FFT (RFC-0010 A2); no cost-model term is claimed.
Affected tasks: E19-02; E16-10 fixtures.
Controls: NC-1303, NC-1304 and NC-1306 run unchanged against the new sources.

### A8 — Plan-fixed split of lookup checks

Status: Draft (development-tier amendment under RFC-0027 §2). Task: E20-02.
Motivation: A3 rejects a check whose concatenated domain exceeds `2^30` positions and
names a splitting rule as a further amendment. RFC-0030 (Draft) caps a lookup
instance for `standard`. Large models reach both limits.

Replacement text, A3 "Concatenation", sentence "A check with `m > 30` is rejected":

> "The plan fixes an instance bound `B` (30 in the development profile). A check is
> an ordered list of **instances**. Members are placed in the A3 order; a new instance
> starts when the next member would take the current one past `2^B` positions. A
> member larger than `2^B` is first cut along its leading domain bits into aligned
> blocks of `2^B` positions. A block is a member of its instance over the remaining
> low bits; its value at the instance's point is the original member's column claim
> at `(bits(block index) ‖ z_low)`, mapped through the member's `vars`. Only a
> matmul `Ref` may fix a bit (A6); a lookup `Ref` never does. So the block is defined
> by this claim point, not by a new `Ref`. Each instance is one RFC-0008 A5 statement
> with its own multiplicity source, in instance order; A3's member split applies
> inside each instance."

Soundness: instances are independent A5 statements with their own draws; each keeps
its own LU record and tree lines. Nothing is shared between them.
Cost: one multiplicity source and one pair of trees per instance in place of one per
check. Proof bytes grow with the instance count: each instance carries its own tree
proofs. That is acceptable at `B = 30`, where instances are few. It is not at the
`standard` cap of RFC-0030 (Draft), where a large proof has thousands of instances;
the data-parallel form of RFC-0030 Q49 is needed before any `standard` proof-size
gate. Affected tasks: E20-02, E20-09, E22-04.
Control: a member value moved across an instance boundary without its multiplicity
is rejected by the receiving instance's root equation (`RootMismatch`).

- **A9 — dev-zk relation forms (companion of RFC-0013 A5, task E12-17).**
  Accepted at conditional scope with ADR-098. It applies only to proofs whose
  profile tag is dev-zk (RFC-0013 A5 item 8). Plain development proofs are
  unchanged. Numbered A9 after the Draft A7/A8 on main. It assumes Circle sources:
  dev-zk sources are RFC-0010 A15 hiding sources whether or not the Draft A7 is
  accepted. Under the Draft A8 every lookup instance is masked on its own.
  - **Profile tag.** §4 step 1's public input gains one byte, `profile`: 0 for
    development, 1 for dev-zk. The verifier derives the statement from it and
    rejects a mismatch with `StatementMismatch`. The byte is part of the
    canonical public input, so it is bound before any challenge.
  - **Padding.** Every relation domain with fewer than 3 variables (4 for OM31,
    `c_D + 1` in general) is padded with dummy summed variables before its
    zerocheck, lookup or range. Columns are read by broadcast. Lookup and range
    multiplicities count each entry `2^pad` times; the plan checks
    `B·2^pad < p`.
  - **Identities.** §4 step 4 runs each domain size's combined identity as an
    RFC-0006 A1 instance `Σ_x eq(τ, x)·Σ_k c_k·P_k(x) = 0` (A1 form), where `τ` is
    drawn with the existing `ZeroWeight` label, as an RFC-0013 A4 bound masked
    sumcheck. The A3 skip is not used.
  - **Matmul zero-sum.** §4 step 6 replaces "the prover sends `out~(ρ)`" by the
    single A1 instance
    `Σ_{y,(x_shared)} eq(ρ_shared, x_shared)·(lhs·rhs − 2^{−s}·Ȯ)(ρ, y) = 0`.
    `Ȯ` is `out` broadcast over the summed bits, with its RFC-0013 A5 claim mask
    on a summed variable. No `out~(ρ)` is sent. The SZ line `a/|K|` and the SC
    line are unchanged, with the degree one higher per masked factor (RFC-0013 A5
    item 3). `s` is the inner dimension's bit count before padding. Padded bits
    are broadcast for `lhs` and `rhs` as well, so both parts count `out` `2^pad`
    times and the sum still vanishes (E12-18, ADR-099).
  - **Lookups.** §4 step 5 masks A5's trees per RFC-0008 A7 (ZK-GKR, committed
    top layer).
  - **Batching and openings.** §4 step 7 uses RFC-0013 A5 item 5 per source in
    place of RFC-0006 A2 mode 1.
  - **Controls.** NC-0909..0915 are reserved under RFC-0013 A5.
  - **Implementation note (E12-14b, ADR-102; development tier, pending independent
    review).** A development public input omits the profile byte instead of
    carrying `0`. Its bytes are exactly the pre-A9 encoding, so development proofs
    are unchanged. A dev-zk public input is the development bytes followed by `1`.
    The two encodings are distinct, so the profile is still bound before any
    challenge. NC-0912 covers the header and the transcript.

- **A10 — NC-1310 at the relation-engine level (task E16-02 follow-up).** Accepted
  with ADR-110 after independent review, development tier.
  - **Motivation.** §9 requires every NC-1300..1310 control to run through the actual
    E16-10 verifier. For NC-1310, no window-level tamper meets the rest of its row.
    Every committed column is range-checked (§3.6), so on the synthetic window each
    column that could rebalance an identity after the change is itself read by
    another identity, lookup or compose. Changing one value to `2^30` therefore breaks
    an identity, and the prover fails first. The two ranged columns that no identity
    reads, `attention/maximum/lo` and `hi`, are limbs of a compose.
  - **Exact change.** §9's NC-1310 row is replaced by the following.
    - Tamper: on a minimal relation, run through `stele_reductions::relation::{prove,
      verify}`, commit one ranged witness value as `2^30`, outside its declared width.
      Change one second, in-width value so every identity still holds.
    - Expected: LU rejection, `RootMismatch`, the A5 root equation of the first range
      check, which is the out-of-width value's.
    - §9's "through the actual E16-10 verifier" does not apply to NC-1310. Every other
      row keeps that requirement.
  - **Why this level suffices.**
    - The relation engine is the code under test: the E16-10 verifier calls it for
      every lookup and range (§4 step 5).
    - The window-level path of the same binding is already covered through the actual
      E16-10 verifier. NC-1300 and NC-1301 leave a margin entry at `-1`, outside its
      unsigned range, and are rejected by that range's A5 root equation, `RootMismatch`
      (E2).
  - **INV-4 exception.** The control changes two values. One is out of its width; the
    other stays inside its width and only rebalances the identity. The binding under
    test is "a ranged witness value outside its width is rejected". The relation is
    `x + 2^22·y − c = 0`, with `x` unsigned 8, `y` signed 9 and `c` public.
    `x[0] = 2^30` and `y[0] = −256`.
  - **Soundness, cost and proof bytes.** No new round, error term, label or proof
    byte. Controls: NC-1310. Affected tasks: E16-02 (its NC-1310 obligation).

### A11 — Circle rate-1/4 sources under Policy 2 for development proofs

Status: Accepted (development-tier amendment under RFC-0027 §2, Workflow 02 item 4).
Independent soundness review of #351: FIX-THEN-MERGE, no soundness break; fix 1
(NC-1316) applied, and no distinct policy byte is needed. Task: E16-30. Decision: ADR-111.

**Motivation.** The PCS is most of a development proof. The stacked (A4) and model (A5)
sources are v2 expander sources under RFC-0010 A3 Policy 1, which needs up to 13,472
certificate and 6,714 opening responses. RFC-0010 A14 (Accepted) derived Policy 2: the
same Circle code at rate 1/4 needs 222 and 92, with 16-bit column grinding. The Q12
study projected 18.3 MB for stories42M on such sources, against 113.4 MB
(`research/fs-pcs/PARAMETERS.md` §4, a projection). A14 item 10 deferred the switch to
E16-30's encoding benchmark: the Circle FFT replaces the linear-time v2 encoder. The
benchmark (ledgers below) shows no measurable prove-time cost on the L0, L1 and L2a
rungs while proof bytes fall 3.5 to 6.2 times and verification time falls.

**Exact change.**

1. **Profile byte 2.** A9's profile tag gains the value 2: "development proof on A11
   sources". The development public input (§4 step 1, A2) is unchanged for the pre-A11
   sources: the byte is omitted (A9 implementation note). An A11 public input is the
   development bytes followed by `u8(2)`. The development encoding is self-delimiting,
   so the three encodings (no byte, `1`, `2`) are distinct and the source set is bound
   before any challenge. The verifier derives every source from the byte and the
   relation; no proof byte selects it. The verifier's input file is
   `stele-dev-public-v2` for byte 2, with the `stele-dev-public-v1` layout. The
   container stays `stele-dev-e2e-v1`.
2. **Sources under byte 2.**
   - The stacked source and every model source are RFC-0010 source version 1 (Circle,
     A9) with blow-up exponent 2. A source of `2^S` entries (`S ≥ 6`, as in A4) has
     `2^ell` rows of `2^m` message elements, `ell + m = S`, `m ≤ 28`, `ell ≤ 30`. The
     plan chooses the `ell` that minimises certificate plus opening bytes under item 3
     (ties: the smallest `ell`). This is Draft A7's geometry, priced under Policy 2.
   - The multiplicity sources keep A5's geometry (RFC-0008 A5 Circle rate 1/2).
   - Ids, layout, block placement, the `2^30` cap per model source, claim mapping,
     batching and one opening per source are A4 and A5's, unchanged.
3. **Policy byte 2 on every source.** Every source of a byte-2 proof (stacked, model
   and multiplicity) carries RFC-0010 A14 policy byte 2: the item 2 query counts, the
   item 3 column grinding (`k_q = 16`) and the item 4 tensor grinding, with the item 3
   and 4 wires and the item 8 errors. The counts are resolved as the development
   profile: `registry::resolve_pcs(code, 4, Development)` returns A14's table with
   `proven: false`. LogUp keeps `r = 1` and no (β, α) nonce: RFC-0008 A8 is not
   applied.
4. **No level is claimed.** The development tier still claims no λ, and a byte-2 proof
   certifies no profile. Policy 2's counts are used as a size and speed choice. The §6
   ledger is unchanged in kind: it reports `ε_interactive`, labels FS unproven, and
   prints the PCS lines unsummed and not admitted. Dev-profile use of Policy 2 unlocks
   no standard-profile claim: the standard resolver path and every standard entry point
   stay behind ADR-108's `standard-unproven` quarantine. The development path reaches
   Policy 2 only through `Source::from_code_id_development` and
   `PreparedSource::from_code_id_development`, which resolve `Development`.
5. **Superseded Accepted text, development tier only.**
   - §1.2 "Development proofs use RFC-0010 A3 Policy 1 v2 sources" reads "Development
     proofs use RFC-0010 A3 Policy 1 v2 sources (pre-A11, profile byte omitted) or
     A11's Circle Policy 2 sources (profile byte 2)".
   - RFC-0010 A14 item 1, "RFC-0026 development proofs keep policy 1", and RFC-0012
     A17 item 7, "they still use Policy 1", read "may use policy 1 or, under RFC-0026
     A11, policy 2 without any profile claim".
   - ADR-091 ("Development profile. Unchanged: Policy 1") and ADR-106 ("development
     proofs stay on Policy 1") are superseded by ADR-111 for the development tier.
6. **Old proofs.** A pre-A11 proof is the same bytes and still verifies: its public
   input carries no byte, so the verifier derives the pre-A11 sources. The E16-10 pins
   of those proofs are unchanged; byte-2 proofs have their own pins.

**Soundness.** No challenge, label or ledger line is added. The new rounds are A14's
grinding rounds: one PoW frame (RFC-0012 A17 A1 frame tag 3, `stele/v0.1/grind`) per
certificate and opening column round, and one per certificate tensor round with
`k_t ≥ 1`. Each PCS round's interactive error is A14 item 5's `≤ 2^-108` (Lemmas 5–6,
grinding counted by Theorem 1) instead of Policy 1's `≤ 2^-130`. The composed proof's
worst round is unchanged: it is still the ungrinded LU round (RFC-0012 A17, `2^-97` on
stories42M). None of this is summed into a claimed level; the PCS stays not admitted
for the development tier.

**Cells, lookups, bytes.** Cells and lookups are unchanged. Measured on one Apple M4
Max laptop, back to back, before at `origin/main` and after at this change (ledgers
`bench/ledger/e16-30-*.json`):

| Rung, window | Proof bytes | Stacked certificate | Openings | Multiplicity certificates | Lookups | `public.bin` | Prove (median) | Verify (median) |
|---|---|---|---|---|---|---|---|---|
| L0 1-layer, T = 16, before | 25,363,609 | 9,237,761 | 6,989,810 | 5,767,709 | 3,303,175 | 4,028,337 | 1.41 s | 0.67 s |
| L0 1-layer, T = 16, after | 7,305,217 | 351,345 | 318,754 | 4,120,125 | 2,449,839 | 186,425 | 1.29 s | 0.35 s |
| L1 8-layer, T = 64, before | 44,963,009 | 19,279,617 | 16,048,930 | 5,767,709 | 3,478,919 | 8,455,508 | 9.91 s | 2.01 s |
| L1 8-layer, T = 64, after | 9,795,145 | 1,554,417 | 1,107,186 | 4,120,125 | 2,625,583 | 301,724 | 10.47 s | 0.90 s |
| L2a stories42M, T = 64, before | 113,422,913 | 53,418,369 | 50,189,170 | 5,767,709 | 3,585,399 | 26,419,059 | 197.0 s | 11.06 s |
| L2a stories42M, T = 64, after | 18,325,385 | 5,869,425 | 5,141,506 | 4,120,125 | 2,732,063 | 2,329,123 | 186.9 s | 6.57 s |

Proof bytes fall 3.5 times (L0), 4.6 times (L1) and 6.2 times (L2a). The stories42M
proof is 18,325,385 bytes; the Q12 projection of 18,325,537 is confirmed, the 152-byte
difference being the 19 LU nonces it counted and A11 does not use. `public.bin`, which
holds the model certificates, falls 11 to 28 times. L0 and L1 are five alternating runs
each, L2a one run each, on a host shared with other workloads. The prove-time
difference is within that host's noise (8-layer walls 9.64–35.25 s before,
9.15–31.39 s after); stories42M's model commitment takes 2.52 s against 2.12 s (the
rate-1/4 FFT), its prove wall 186.9 s against 197.0 s and its peak RSS 25.3 GB against
26.2 GB. Verification time falls by half on L0 and L1, and by 40% on L2a. The
multiplicity certificates, still Circle rate 1/2, are now the largest section on L0 and
L1.

**Cost.** Rows are encoded by the circle FFT (RFC-0010 A2) at rate 1/4: a larger
codeword per row, fewer responses per proof. Each grinding round costs the prover
2^16 expected BLAKE3 calls, and the verifier one. No cost-model term is claimed.

**Controls.** NC-1311 (an A11 proof with the byte omitted, header restamped:
`ProofShape`), NC-1312 (a pre-A11 proof with byte 2 added: `ProofShape`), NC-1313,
NC-1314 and NC-1315 (the stacked certificate's, the stacked opening's and the model
certificate's column nonce replaced by one failing the predicate: `GrindMismatch`), and
NC-1316 (the transcript binding of the byte: the engine run with the plan fixed at one
source set and the public input of the other, both ways, so no source shape differs:
`RoundSumMismatch`; removing the byte from the public input turns it red).
NC-1300, NC-1301, NC-1304, NC-1305 and NC-1309 run unchanged on byte-2 proofs.

**Affected tasks.** E16-30 (implements it). E19-02: Draft A7's geometry is A11's; if
A11 is accepted, A7 and E19-02's acceptance should be rebased on Policy 2 or withdrawn.
E19-03 changes the row map again (coefficient-form rows). Promotion to `standard`: not
granted (Workflow 10).
