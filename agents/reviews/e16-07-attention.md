# E16-07 attention module: output-uniqueness lemma and review notes

**Scope.** `stele_reductions::development::attention::Attention` (RFC-0026 §5 rows 6–9,
§5.2), branch `task/E16-07-attention`. Same-author notes; proving is E16-02's.

## Plan and layout

One instance per layer. Inputs are the E16-05 row conversions of `Q'`, `K'` (E16-06
output) and `V`: signed-8 codes and one scale per row (dynamic: witness, 9 bits;
static: the public constant). `t = log T`, `d = log dh`, `hb = log h` (padded),
`rb = log(h/g)`; `dh` and `h/g` must be powers of two, so `head = group·2^rb + k`
and K/V are read through the high `log g` bits of `head` (GQA, §1.3).

| Domain | Bits (low first) | Holds |
|---|---|---|
| `S` | `j`, `head`, `i` | dot, score, exp, one-hot, `Pm`, `Pm·sv` bytes |
| `(j,i)` | `j`, `i` | `sq·sk` bytes; public `causal = [j <= i < n]` |
| `(head,i)` | `head`, `i` | `Mx`, `Z` |
| `O` | `c`, `head`, `i` | division, output (= the O-input row layout) |
| `Ob` | `c`, `head`, `i`, `b` | per-key-block sums (block mode, `b` = absolute 1024-key block) |

Every wide value is byte limbs proven by the E16-05 byte `Chain` (one identity per
radix-256 position, carries range-checked). `Q` (score quotient), `Mx`, `Z` and `q`
are also single columns, composed from their limbs.

## Relations

Row 6 (scores), with `e = e_score − fq − fk + F`, `k = −e` when `e < 0`:
- M `dot = Σ_c q·k` (shared group bits); I `dot = A − 2σA` with `A` bytes;
- chain `W = sq·sk` on `(j,i)` (static scales enter as constant bytes);
- chain `Σ A_a·W_b·m_c·256^(a+b+c) + 2^(k−1) = Q·2^k + ρ`, `ρ` bytes of `k` bits
  (`e >= 0`: `= Q`); `score = (1−2σ)·2^max(e,0)·Q` is never committed.

Row 7 (causal max): I `u = causal·(Mx − score)` through the exp columns (below);
R one-hot `h ∈ {0,1}`; M `Σ_j h·causal = real(i)` (output is the public `real`);
I `h·u = 0`; I `Mx·(1 − real) = 0`.

Row 8 (exp, RFC-0021 §2.1): mode 0 L `(t, P)` in `exp_q/direct`, `t = −u`;
modes 1/2 L `(hi, H)` in `exp_q/hi`, L `(lo, L)` in `exp_q/lo`,
I `u = 2^k·hi + lo` (mode 2 as `t + 2^k·hi + lo = 0` with L `(t, C)` in
`exp_q/correction`), I `H·L = (P − C)·2^E + rr`, R `rr` (E bits); mode 1 adds
I `slack = 2^B·causal − u >= 0` when `2·Smax > 2^B`. Tables are converted on their
`shape().rows()` real rows; canonical zero padding rows are **not** table rows.

Row 9: I `Pm = causal·P`; M `Z = Σ_j Pm`; chain `Pm·sv = Σ p_b 256^b`;
M `T_b = Σ_o p_b·v` per byte row (per key block); chain `Σ 256^b T_b = (1−2σ')·n`.
Block mode: chain `n + 2^(c−1) = qB·2^c + ρB`, I `B = (1−2σ')·qB` (R int16),
M `T = Σ_b B` when there is more than one block, I `T = (1−2τ)·|T|`.
Division (`E2 = fa − fv + c`): for `E2 < 0`, `j = −E2`, chain
`|T| = nh·2^j + bit·2^(j−1) + nl`; chain `2^(E2'+1)·nh + bit + Z = 2·Z·q + r`
(`E2' = max(E2,0)`, `nh = |T|`, `bit = 0` when `E2 >= 0`); chain
`real·(2Z − 1) = r + s`; I `q·(1 − real) = 0`; I `o = (1−2τ)·q`, R `o` int16.

## Lemma A (output uniqueness)

*Let the inputs (codes in signed 8, scales as the conversions declare, padding 0 as
the conversions pin it) be fixed. Every assignment satisfying the relations above
has `Q`, `Mx`, `P` (on scope), `Z`, `B` and `o` equal to the executor's values
(`Executor::attend`), and `o = 0` on padded rows, heads and lanes. Where the executor
rejects (`ExpDomain`, `Range`, `Z = 0`) no assignment exists.*

Proof sketch (each step uses only relations already shown to hold over Z, which
§3.6 gives from the validated bounds and range discipline):

1. `dot` is the code dot product (matmul). `A >= 0` (bytes) and `dot = (1−2σ)A`
   give `A = |dot|`; σ is free only at `dot = 0`, where `A = 0`.
2. The `W` chain with canonical bytes gives `W = sq·sk`. The score chain with
   `ρ ∈ [0, 2^k)` and `Q >= 0` is Euclidean division:
   `Q = floor((|dot|·sq·sk·m + 2^(k−1))/2^k) = |R(dot·sq·sk·m/2^k)|`, so
   `score = (1−2σ)·Q` is the executor's `scaled_sum` (σ is irrelevant when `Q = 0`).
   For `e >= 0`, `Q = |dot|·sq·sk·m` exactly.
3. `u >= 0` on scope: modes 0/2 by the table (`t ∈ [−2^B, 0]`), mode 1 because
   `hi, lo >= 0`. On a real row the matmul and `h ∈ {0,1}` give exactly one in-scope
   `j` with `h = 1`, where `h·u = 0` gives `Mx = score_j`. Hence `Mx` is the attained
   in-scope maximum. On padded rows `Mx = 0`. Mode 1 bounds `u <= 2^B` by the slack
   (or, when omitted, by `u <= 2·Smax <= 2^B` since `Mx` is attained).
4. `lo < 2^k` (table domain) makes `(hi, lo)` the unique split of `u`; `rr ∈ [0, 2^E)`
   makes `P − C = floor(H·L/2^E)`; with the tables this is `exp_q(t)` in each mode,
   and `u > 2^B` (executor `ExpDomain`) has no assignment.
5. `Pm = causal·P`, so `Z` and the byte rows are the executor's masked sums; the byte
   chain fixes `Pm·sv`, the matmuls give `X = Σ_j Pm·sv·v` (per block), and the sign
   chain with `n >= 0` gives `n = |X|`.
6. Block mode: as in 2, `qB = floor((|X| + 2^(c−1))/2^c)`; the int16 range on `B`
   is the executor's `wide`. `T = Σ_b B`, and `|T|` is unique.
7. Division: `r >= 0` and `s >= 0` give `0 <= r <= 2Z − 1` on real rows, so `Z >= 1`
   and `q = floor((2^(E2'+1)·nh + bit + Z)/(2Z))`. For `E2 >= 0` this is
   `floor((2|T|·2^E2 + Z)/(2Z))`; for `E2 < 0` the split is unique (`nl < 2^(j−1)`)
   and `floor((2|T| + Z·2^j)/(2Z·2^j)) = floor((2nh + Z + bit)/(2Z))`, because
   `2nl/2^j ∈ [0,1)` contributes `bit` exactly to the floor. Thus `q = |R(T·2^E2/Z)|`
   and `o = (1−2τ)q` (τ irrelevant when `q = 0`); the int16 range is the executor's
   `wide`. On padded rows `Z = 0`, so `r = s = 0`, and `q` is pinned to 0.
8. Padded heads and lanes: their codes are 0, so scores are 0, `Mx = 0`,
   `Pm = Q_E` on scope, and `v = 0` gives `X = 0` and `o = 0`.

Auxiliary columns are unique except σ at `dot = 0`, `σ'`/`τ` at a zero total, and
`h` off scope or at tied maxima; no output depends on them.

## Tests

- `accepts_honest_executor_values`: eight configurations (product, direct,
  corrected, MHA with static scales, block mode, `E2 < 0`, `e >= 0`, GQA 4:1) on
  random int16 Q'/K'/V converted by `Quantiser`, with the E16-05 conversions and
  the O-input conversion on the output (head assembly).
- `matches_reference_executor_capture_on_fixtures`: every family-1 layer of the
  `model-execution` and `grouped-rows` corpora, honest values from
  `Executor::capture` (all three exp modes, exact and block mode, static and
  dynamic scales, GQA); the executor-equivalent reference used by the other tests
  equals the capture there.
- `rejects_near_miss_outputs`, `rejects_score_other_rounding_direction`: score,
  masked score, dot, exp, `Mx`, `Z`, block and output off by ±1 with downstream
  re-solved as an attacker would; every one is rejected.
- `rejects_every_constraint_deletion`: the deletion survey (below).
- `accepts_static_validity_realistic_shapes`, `rejects_unsupported_plans_before_declaring`.

## Deletion survey

For each module constraint (identity, chain position, lookup, range, matmul,
Compose) in five small configurations, the survey deletes it and looks for an
in-range attacker witness that `check` rejects and the relation without that
constraint accepts (`stele_ir::relation::check_except`). Witnesses
are built as an attacker would: the semantic near misses above; a value moved at a
deleted chain position with the carries re-solved around it; a primary moved by
`256^k` with downstream re-solved (re-division, re-split); single-entry edits; and
limb carry shifts (`limb_i ± 2^w`, `limb_(i+1) ∓ 1`). 334 of 490 deletions have a
witness. The other 156 are all ranges, and each is also rejected statically (the
column becomes undisciplined, §3.6). Each has a recorded reason:
- carries (≈100): fixed over Z by the position values; the range is what keeps the
  position identity below p;
- top or sole limbs of `|dot|`, `sq·sk`, `Q`, `Pm·sv`, `|T|`, `Z`, `q`, `s`, `Mx`, `|T|` in block mode: the
  value is fixed over Z by its composition or producer; the width feeds the bound rule;
- `exp/p`, `exp/masked`: fixed by `exp/product` (or the lookup) and `exp/masked`;
- `output`, `block`, `block/quotient`: the executor's int16/u16 rejection, which
  admitted test inputs do not reach;
- `exp/slack`: the executor's `ExpDomain`, reachable only past `2^B` score spreads.

## Gaps

- No row-block split: plans whose matmul domain `2t + hb + d` exceeds 30 variables
  are `Unsupported::Domain` (for example T = 1024, h = 32, dh = 128, and every
  T = 4096 plan). Splitting needs `Ref` constant bits or selector-linked block
  copies (an E16-01 API question). Validated here: T = 64/128 at d = 512 (h = 8,
  dh = 64, MHA and GQA, exact and block mode), T = 1024 (h = 8, dh = 64) and
  T = 512 (h = 8, g = 2, dh = 128).
- Block mode with more than one key block (`T > 1024`) is declared and validated
  but no executor case reaches it in tests (needs `T > 1024`).
- Score magnitude bound `2^28` (by declared widths) and mode-1 `B <= 29`;
  larger plans are `Unsupported::Domain`.
