# PCS parameters under the Q12 Fiat–Shamir rule (task E12-21)

Status: Draft research. Governing argument: [fs-composition.md](../../formal/fs-composition.md)
(Theorem 1, Lemmas 2–6, profile conditions (C1)–(C4) in §5).

This study answers four questions:

1. Which proven bounds apply to which codes and fields?
2. Which query counts does each profile need, with and without grinding?
3. What do those counts do to the stories42M development proof?
4. Which parameter set should be admitted?

Every decision is made by exact integer or `Fraction` arithmetic in [study.py](study.py).
`python3 research/fs-pcs/study.py --check` pins the receipts quoted here; it runs in the
research CI next to the Policy 1 checker.

## 1. Inputs and provenance

- **`stories42m-inventory.jsonl`** lists every PCS certificate and opening that the
  verifier checks for the recorded stories42M proof, one record each: code family,
  R, C, N, D, q and bytes.
  - Source: commit `e813ce1`, `proof.bin` SHA-256 `507b52b3…5381`, `public.bin`
    SHA-256 `d7f9264b…6cd6d7` ([ledger](../../bench/ledger/e16-18-dev-stories42m.json)).
  - **Capture.** The records come from instrumenting `stele_pcs::verify_certificate`,
    `verify_opening` and `verify_point` with [capture.patch](capture.patch), which
    prints one JSON line per call to stderr.
    - Apply it to `e813ce1`, then build `stele-cli` in release.
    - Run `stele verify-dev --public public.bin --proof proof.bin 2>&1 >/dev/null`
      and keep the lines that start with `PCSINV`.
    - Revert the patch. No code change is part of this study.
  - **Size model.** It reproduces each of the 48 records byte for byte. The
    994,394 non-PCS bytes are defined as the remainder of the 113,422,913-byte
    total, and are not independently checked.
  - The first record is the model certificate, which travels in `public.bin`.
- **`stories42m-ledger.tsv`** holds the 1,792 RLC/SC/SZ/LU lines of the RFC-0026 §6
  ledger. The unpatched `verify-dev` printed them on stdout for the same proof, and
  the first three tab-separated fields were kept.

## 2. Theorems, codes and fields

### Proven chain (unique decoding only)

| Round | Bound | Theorem | Hypotheses | Met by |
|---|---|---|---|---|
| Certificate tensor | 2·ℓ·(e+1)/\|K\| | Diamond–Posen Thm 2 (CIC 1(1), p.10) | linear code over F, distance D, e ≤ ⌊(D−1)/3⌋, ℓ independent uniform weights in K ⊇ F | Circle (D=N−C, deterministic); v2 (D from `rfc-0010-a1/finite-v2`, outside the A7 setup event). QM31 and OM31 both contain M31 |
| Certificate columns | ((N−e−1)/N)^q_c | tensor-opening.md §3 | tensor bound; q_c fresh uniform columns after t is bound | A10 unbiased sampler |
| Opening columns | ((N−D+e)/N)^q_o | certified-functional-opening.md §2 | near frozen W; u bound before columns | A9 schedule |
| FS composition | Q·ε* + ε_floor + H + ε_setup | fs-composition.md Theorem 1 | classical ROM; A1 framing; A8 frozen oracle | RFC-0012 A1/A3/A8/A10 |

### Fields

M31 is the code alphabet. Challenges are QM31, with |K| = p^4 ≈ 2^124, or OM31,
with |K| = p^8 ≈ 2^248.

- **Tensor rounds.** The tensor-round error 2ℓ(e+1)/|K| grows with e, which is
  linear in N. In QM31 it is about 2^-102 for Circle rate 1/4 with N = 2^19 and
  ℓ = 12, and about 2^-98 for v2 at its largest size. Under the standard
  per-round target of 2^-108 they need up to 6 grinding bits in QM31 for the
  stories42M shapes, and up to about 11 bits at the largest v2 size. In OM31
  they need none.
- **Sumcheck rounds.** About 2^-122 in QM31, which passes unaided.
- **LogUp rounds.** (N+|T|)/|K|, with N up to 2^27 for weight range checks. That
  is 2^-97 in QM31 (§4).

### Codes

- **Circle** (RFC-0010 A2). The code is MDS, with D = N−C. Under the generic
  Diamond–Posen radius, unique decoding gives e ≈ (N−C)/3:
  - rate 1/4: e ≈ N/4, and an opening misses with probability about 1/2 per
    query;
  - rate 1/2: e ≈ N/6, and the opening miss is about 2/3.
- **v2 expander** (RFC-0010 A1/A4). The proven distance is only D = ⌊k/25⌋+1 at
  rate 1/2, a relative distance of about 1/50. So e/N ≈ 1/150, and each query
  buys about 0.0096 bits on the certificate and 0.019 bits on the opening. That
  is the root of today's 13k/6.7k counts. No proven theorem in hand improves
  the expander's distance or radius.
- **RAA.** No RAA code is specified or has a distance certificate. Not usable.

### Johnson radius (not adopted)

At rate 1/4 the Johnson radius would roughly halve the Circle certificate's
queries. It needs three things this study does not have.

1. **A proximity-gap theorem up to the Johnson radius.**
   - BCIKS20 Thm 1.5 has an exceptional set of order n²·poly(1/η). At n = 2^30,
     n² ≈ 2^60, which is far above the |QM31|·2^-108 ≈ 2^16 that a QM31 round
     can afford.
   - BCHKS (ePrint 2025/2055) improves this to O(n) exceptional combinations.
     We have not checked its constants against M31/QM31 sizes, and FlashProve
     reports applying it "with no bits to spare" over a larger challenge field.
2. **A written equivalence between the Circle code and a generalized RS code.**
   The circle curve over M31 is rational, so stereographic projection should
   give it, but it is neither written nor checked here.
3. **Out-of-domain binding.** Above the unique-decoding radius, a certificate no
   longer fixes one near message, so every opening needs OOD binding
   (Chiesa–Fenzi–Weissenberg, ePrint 2026/391; FlashProve §5.5). That is a
   protocol change, with its own rounds and controls.

For v2, the Johnson radius 1−√(1−δ) ≈ δ/2, against δ/3 today, gains at most
about 1.5x. We know of no proximity gap for general linear codes at that radius
with an error usable in QM31. This is recorded as future work under Q12 item 4.
No conjecture enters any count below.

## 3. Query counts (Policy 2, proposed RFC-0010 A14)

A query round uses its profile's column target before grinding,
2^-(λ+g−k_q):

- **Standard:** 2^-92, with λ = 100, g = 8 and k_q = 16.
- **Treaty:** 2^-120. This is conditional only; treaty is not admitted.

q_c is the least positive integer with `2^(λ+g−k_q)·(N−e−1)^q_c ≤ N^q_c`. q_o is
the least with `(N−D+e)` in place of `(N−e−1)`. The study checks every
inequality, and its failure at q−1, for all 59 Circle and 12 v2 identities.

For comparison:

- **Policy 1** targets 2^-130 with no grinding: 314/130 for Circle rate 1/4, and
  13,472/6,714 for v2 J=14.
- **The old Q·ε reading** of RFC-0010 A3 item 7 needs 2^-228 per round for
  treaty: 23,627/11,774 for v2 J=14.

### standard: lambda=100, |K|=p^4, g=8, k_q=16, column target 2^-92 before grinding

| code | index range | q_c | q_o |
|---|---|---:|---:|
| Circle b=1 | 0..0 | 92 | 1 |
| Circle b=1 | 1..1 | 222 | 92 |
| Circle b=1 | 2..2 | 222 | 136 |
| Circle b=1 | 3..3 | 308 | 136 |
| Circle b=1 | 4..4 | 308 | 152 |
| Circle b=1 | 5..5 | 339 | 152 |
| Circle b=1 | 6..6 | 339 | 156 |
| Circle b=1 | 7..7 | 347 | 156 |
| Circle b=1 | 8..8 | 347 | 157 |
| Circle b=1 | 9..9 | 350 | 157 |
| Circle b=1 | 10..29 | 350 | 158 |
| Circle b=2 | 0..0 | 92 | 46 |
| Circle b=2 | 1..1 | 222 | 66 |
| Circle b=2 | 2..2 | 222 | 78 |
| Circle b=2 | 3..3 | 222 | 85 |
| Circle b=2 | 4..4 | 222 | 88 |
| Circle b=2 | 5..5 | 222 | 90 |
| Circle b=2 | 6..6 | 222 | 91 |
| Circle b=2 | 7..28 | 222 | 92 |
| v2 J | 3..3 | 339 | 156 |
| v2 J | 4..4 | 8131 | 4050 |
| v2 J | 5..5 | 9297 | 4633 |
| v2 J | 6..6 | 9467 | 4718 |
| v2 J | 7..7 | 9510 | 4739 |
| v2 J | 8..8 | 9532 | 4748 |
| v2 J | 9..9 | 9532 | 4751 |
| v2 J | 10..10 | 9533 | 4751 |
| v2 J | 11..14 | 9534 | 4751 |

### treaty: lambda=128, |K|=p^8, g=8, k_q=16, column target 2^-120 before grinding

| code | index range | q_c | q_o |
|---|---|---:|---:|
| Circle b=1 | 0..0 | 120 | 1 |
| Circle b=1 | 1..1 | 290 | 120 |
| Circle b=1 | 2..2 | 290 | 177 |
| Circle b=1 | 3..3 | 401 | 177 |
| Circle b=1 | 4..4 | 401 | 198 |
| Circle b=1 | 5..5 | 442 | 198 |
| Circle b=1 | 6..6 | 442 | 204 |
| Circle b=1 | 7..7 | 453 | 204 |
| Circle b=1 | 8..8 | 453 | 205 |
| Circle b=1 | 9..9 | 456 | 205 |
| Circle b=1 | 10..12 | 456 | 206 |
| Circle b=1 | 13..29 | 457 | 206 |
| Circle b=2 | 0..0 | 120 | 60 |
| Circle b=2 | 1..1 | 290 | 85 |
| Circle b=2 | 2..2 | 290 | 101 |
| Circle b=2 | 3..3 | 290 | 110 |
| Circle b=2 | 4..4 | 290 | 115 |
| Circle b=2 | 5..5 | 290 | 118 |
| Circle b=2 | 6..6 | 290 | 119 |
| Circle b=2 | 7..28 | 290 | 120 |
| v2 J | 3..3 | 442 | 204 |
| v2 J | 4..4 | 10606 | 5282 |
| v2 J | 5..5 | 12127 | 6043 |
| v2 J | 6..6 | 12348 | 6153 |
| v2 J | 7..7 | 12404 | 6182 |
| v2 J | 8..8 | 12433 | 6192 |
| v2 J | 9..9 | 12433 | 6197 |
| v2 J | 10..12 | 12435 | 6197 |
| v2 J | 13..14 | 12436 | 6197 |


## 4. stories42M development proof, re-priced

**Assumptions of the re-pricing.**

- The witness stack (2^29 entries) and the model source (2^26 entries) take the
  shape that minimizes certificate plus opening bytes within each code family,
  as `relation::stack` does today.
- The 21 Circle rate-1/2 multiplicity sources keep their A5 shapes. Only their
  query counts change.
- Non-PCS bytes (994,394) carry over unchanged.
- Each grinding column round adds an 8-byte nonce.

**Round errors.**

- "Worst round" and "floor" are the (C1) and (C2) quantities of
  fs-composition.md §5, including grinding.
- They are computed over every LU check, counted as two rounds of at most
  numerator+1 each (Lemma 4), every RLC and SZ line, the SC records as sums,
  and every PCS tensor and column round.
- The A7 setup term is added when a v2 source is present.

| policy | profile rule | stack | q_c/q_o | model | q_c/q_o | proof bytes | model cert | worst round | floor | per-proof grind hashes | C1 | C2 |
|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| policy1 | standard | v2 (recorded J) R=512 | 13471/6713 | v2 (recorded J) R=256 | 13469/6713 | 113,422,913 | 26,175,713 | 2^-97.0 | 2^-95.6 | 0 | FAIL | FAIL |
| v2 | standard | v2(J=10) R=512 | 9533/4751 | v2(J=9) R=256 | 9532/4751 | 91,672,193 | 19,750,537 | 2^-108.0 | 2^-102.2 | 3,090,952 | pass | pass |
| circle1 | standard | circle(m=17,b=1) R=4096 | 350/158 | circle(m=16,b=1) R=1024 | 350/158 | 21,909,025 | 2,672,585 | 2^-108.1 | 2^-102.2 | 3,090,980 | pass | pass |
| circle2 | standard | circle(m=17,b=2) R=4096 | 222/92 | circle(m=16,b=2) R=1024 | 222/92 | 18,325,537 | 2,085,769 | 2^-108.0 | 2^-102.2 | 3,091,012 | pass | pass |
| v2 | treaty | v2(J=10) R=512 | 12435/6197 | v2(J=9) R=256 | 12433/6197 | 145,451,681 | 28,679,273 | 2^-136.0 | 2^-130.3 | 3,080,192 | pass | pass |
| circle2 | treaty | circle(m=17,b=2) R=4096 | 290/120 | circle(m=15,b=2) R=2048 | 290/120 | 26,613,889 | 3,582,025 | 2^-136.0 | 2^-130.7 | 3,080,192 | pass | pass |

Treaty rows: OM31 for stack/model rows only; multiplicity rows, non-PCS bytes and the
LU/SC numerators are carried at their recorded QM31 values over p^8. Counts only; not admitted.
Policy 1 is evaluated under the standard rule with no grinding, for comparison.

**Reading.**

- **The recorded proof fails the rule.**
  - Its worst round is LU range_8, the weight range check over 2^27 positions,
    at 2^-97.0. Its floor is 2^-95.6.
  - Policy 1's 2^-130 column target is wasted on the PCS while the LU rounds
    are 2^29 times weaker.
- **v2 under Policy 2 passes at 91.7 MB**, only 19% below today. The expander's
  1/50 distance caps any query saving: one opening query buys 0.019 bits.
- **Circle rate 1/4 under Policy 2 passes at 18.3 MB**, 6.2x below today's
  113.4 MB.
  - Queries drop to 222/92, from 13,471/6,713.
  - The public model certificate shrinks from 26.2 MB to 2.1 MB.
  - Circle rate 1/2 gives 21.9 MB.
  - The remaining bytes are mostly the 16-byte-per-column rows t and u (QM31)
    and the 21 multiplicity sources.
- **Grinding costs the prover about 3.1·10^6 BLAKE3 calls per proof**, and the
  verifier one PoW call per grinding round.
  - 47 per-proof column rounds at k_q = 16.
  - 19 LU (β, α) rounds at 2 to 12 bits.
  - The stack tensor round: 6 bits for Circle, none for v2.
  - The one-time model certificate travels in `public.bin` and adds one column
    round (2^16) and one tensor round (Circle 5 bits, v2 2 bits). These are
    excluded from the per-proof figure.
  - The proof-byte figures include an 8-byte nonce per grinding round.
- **Treaty counts for OM31 (λ=128) are conditional.** They show that the rule
  scales: Circle rate 1/4 needs 290/120. Treaty admission still needs ZK (Q29)
  and its other RFC-0002 §8 rows.

**Not measured.**

- The encoding time of a 2^29-entry Circle rate-1/4 source against v2 at rate
  1/2. Circle needs O(N log N) circle-FFT work per row and twice the codeword
  length; v2 is linear.
- No cost-model constant moves in this study. The switch needs a benchmark
  ledger before RFC-0026 adopts it (proposed follow-up task E16-30).

## 5. Recommendation (proposed for adoption by task E12-22)

The (C1)/(C2) columns above are not an admission. `study.py` does not compute
(C3), the H* endpoint checks, or (C4), the grinding-family rule; the native
verifier must check all four (E8-05).

1. **Standard profile.** λ = 100, g = 8, Q_cap = 2^80, QM31 challenges.
   - Grinding k_q = 16 on every PCS column round.
   - Least-bits grinding (rule C4) on LU and PCS tensor rounds.
   - Policy 2 query tables (§3) for both Circle and v2 identities, under policy
     byte 2.
   - Every other round must meet 2^-108 unaided, or the configuration is
     rejected.
2. **Treaty profile.** Record the λ = 128 tables as conditional. Not admitted.
3. **Codes.** Prefer Circle rate 1/4 for per-proof and weight sources once
   E16-30 measures its prover cost. v2 stays admissible, at about 5x the proof
   bytes.
4. **Not adopted.** Johnson-radius proximity, OOD binding, capacity
   conjectures, and any expander radius beyond ⌊(D−1)/3⌋.

## 6. Proven, conditional and approximate

- **Proven.** The query counts are exact consequences of:
  - Diamond–Posen Thm 2 (published);
  - the query lemmas of tensor-opening.md §3 and certified-functional-opening.md
    §2;
  - Theorem 1 and Lemmas 2–6 of fs-composition.md. These are paper proofs, not
    machine-checked.
- **Conditional** on:
  - BLAKE3 as a classical random oracle;
  - the A8 frozen-oracle events, charged to H;
  - the v2 distance outside the A7 setup event (the Circle distance is
    deterministic).
- **Conjectural.** None. No count uses a conjecture.
- **Approximate, not admission inputs.**
  - The stories42M round inventory: the recorded ledger with Lemma 4's bound of
    two rounds per LU check. The native generator must enumerate exact rounds
    (E8-05).
  - The treaty byte figures, which under-price the multiplicity rows.
