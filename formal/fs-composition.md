# Fiat–Shamir composition, query cap and grinding for Stele (Q12)

Status: Draft. Question Q12 (RFC-0019). Companion parameter study:
`research/fs-pcs/` (task E12-11); this note is task E12-10. Proposed for adoption by RFC-0012 A17, RFC-0010 A14
and RFC-0002 A1. Until those are Accepted, nothing here admits a profile.

Q12 asks two things: which Fiat–Shamir (FS) theorem supports Stele's
non-interactive verifier, and which adversary query cap makes FS and the hash
term H fit each profile target. This note answers both for the classical
random-oracle model (ROM).

1. **Theorem 1** (§3) is the FS bound. It covers round-by-round (RBR) soundness,
   the hash-chain transcript of RFC-0012 A1 and counted grinding. Its error is
   `Q·ε* + ε_floor + H(Q+Q_V) + ε_setup`.
2. **Lemmas 2–6** (§4) give a per-round error for every round family that a
   development proof uses: SC, RLC, SZ, LU (two rounds; Lemma 4 is new), the
   PCS tensor round and the PCS column rounds.
3. **The query cap** (§5). The old reading of RFC-0002 §8 asks for a total error
   of 2^-100 against 2^80 queries (standard), or 2^-128 against 2^100 queries
   (treaty). No 256-bit hash can meet it: H alone is about Q²/2^257, which is
   2^-97 at Q = 2^80 and 2^-57 at Q = 2^100. This note replaces it with a
   per-query target, `ε(Q) ≤ (Q·2^-g + 1)·2^-λ + H(Q+Q_V)`, and states what
   that means.

Everything here is classical. Quantum adversaries (QROM), zero knowledge (Q29) and
the treaty profile's other obligations remain open (§7).

## 1. Model

- **Oracle.** BLAKE3 is a random oracle `O`. One query is one call: one ordinary
  hash or one XOF request, whatever the input length. `H(x)` is the first 32
  bytes of `O(x)`, and `XOF(x)` is its extendable output (RFC-0012 A1). Merkle
  hashing (RFC-0012 A3), transcript frames, column sampling (A10), the setup
  expansion (A7) and grinding (§2) all query this one oracle. Domain separation
  matters only through input inequality, and the frames of A1 are prefix-free
  and tagged.
- **Adversary.** A classical algorithm `P*` that makes at most `Q` oracle
  queries in total, counting every grinding attempt and every abandoned
  attempt. It outputs the public input and the proof, so it chooses the
  statement adaptively. `Q_V` is the number of queries that the verifier makes
  on the output. `Q_cap` is the profile's grinding allowance (RFC-0002 §8:
  2^80 standard, 2^100 treaty).
- **Protocol.** Π is the public-coin interactive protocol that the verifier
  replays. It has one or more **chains**. A chain is a transcript started by
  `Transcript::new` on its own public input: the main relation transcript, and
  one per PCS certificate (RFC-0010 A9 §3). A **round** is a maximal run of
  challenge requests with no absorb between them. Several requests in one round
  form one vector challenge. Examples: the ℓ CertificateWeight draws, the q
  column draws of one response block, the coordinates of one `relation/point`,
  and β followed by α in a lookup.
- **Oracles of the IOP.** A committed source is a Merkle root. RFC-0010 A8
  freezes the field-valued matrix W that the root determines, from the queries
  made before the root's first registration. Outside the A8 events BadCollision
  and BadLate, every accepted column equals W's column. Those events are charged
  to the H line of RFC-0012 A15.

## 2. Grinding (proposed RFC-0012 A17 item 3)

A round with grinding bits `k ≥ 1` is preceded by a prover nonce `n ∈ [0, 2^64)`.
Let S be the transcript state before the round's first challenge request.

1. **PoW predicate.** `w = u64le(H(frame(S, 3, L, u8(k) || u64le(n)))[0..8])`.
   The nonce is valid iff the low k bits of w are zero (`w mod 2^k = 0`). Tag 3
   is new and is used only here.
2. **Absorb.** On a valid nonce, `S ← H(frame(S, 0, L, u8(k) || u64le(n)))`.
   Then the round's challenge requests follow as in A1.

L is the round's registered grinding label. k is derived by the verifier from
the expected context, never read from the proof. Only n is a proof byte. The
prover takes the least valid n (INV-8). The verifier makes one PoW query and
one absorb.

**Independence.** For a fixed (S, n), the PoW input (tag 3) and the absorb input
(tag 0) are distinct oracle inputs. Every input of the following round derives
from the absorb output. Under the ROM, the PoW bit and the round's challenges are
therefore independent and uniform, whichever is queried first.

## 3. Theorem 1 (FS for an RBR-sound Stele protocol, with grinding)

**Definitions.** For each chain, a **state function** maps a partial transcript
to doomed or not doomed. It satisfies:

- (i) the empty transcript of a false statement is doomed;
- (ii) a doomed transcript stays doomed after any prover message;
- (iii) a complete doomed transcript is rejected.

Round i of the chain has **RBR error** ε_i if, for every doomed partial
transcript τ that ends just before round i, a uniform round challenge c makes
τ‖c non-doomed with probability at most ε_i. A false statement of the whole
proof is doomed for at least one chain. §4 states the multi-chain composition.

Let k_i be the grinding bits of round i. Define:

- `ε* = max_i ε_i·2^-k_i`, the largest error of any round reachable under the
  profile's shapes;
- `ε_floor = Σ_{i ∈ rounds(x)} ε_i·2^-k_i`, the sum over the rounds of the one
  verification of the output statement x;
- `H(·)`, the RFC-0012 A15 H line with `Q_total = Q + Q_V`;
- `ε_setup`, the A7 term (zero without a v2 J≥4 source).

**Theorem 1.** For every P* that makes at most Q queries,

```
Pr[V^O accepts (x, π) and x is false] ≤ Q·ε* + ε_floor + H(Q+Q_V) + ε_setup.
```

**Proof.**

1. **Bad events.** Let Bad_H be a collision among the 32-byte outputs of the
   Q+Q_V queries, or an A8 BadLate event. Charge it to `H(Q+Q_V)`; A15 bounds
   it with the deterministic caps of A8. Let Bad_setup be the A7 event.
   Outside both:
   - every transcript state determines its frame history uniquely, because
     A1 frames are injective and S is the hash of the frame that contains the
     previous S;
   - every root determines its frozen matrix W (A8);
   - every v2 code has its stated distance.
2. **Round starts.** A round start is a pair (state S, round i), with the nonce
   n included when k_i ≥ 1. It is identified by its first challenge-request
   input. By step 1, S determines the partial transcript τ. The round's
   challenge is a deterministic function of oracle outputs at fresh inputs,
   namely the request, its state update, the next request, and so on. By the
   A1/A10 exactness lemmas, the challenge is uniform on the round's challenge
   space conditioned on no abort. An abort (SamplingExhausted or
   ColumnSamplingExhausted) ends the verification with a rejection and cannot
   help the adversary.
3. **One start.** Fix one round start. If τ is doomed, the chain leaves doom
   with probability at most ε_i. With k_i ≥ 1 it must also hold a valid nonce,
   which happens with probability 2^-k_i independently (§2). So the
   probability is at most ε_i·2^-k_i ≤ ε*.
4. **Counting starts.** A round start is touched when one of its inputs (the
   PoW input, the absorb input or the first request) is queried by P*, or by V
   if P* did not query it.
   - P* touches at most Q starts. A query touches at most one start: outside
     Bad_H, inputs determine (S, i, n).
   - The starts that V touches but P* did not are the starts of rounds(x), and
     each of them contributes ε_i·2^-k_i.
5. **Union bound.** If V accepts a false x, then property (iii) and the
   doomed initial chain imply that some round start of the verified transcript
   left doom. Outside the bad events, the probability of this is at most
   `Q·ε* + ε_floor`. ∎

**Remarks.**

- This is the standard argument that turns RBR soundness into
  state-restoration soundness and then into BCS/FS soundness in the ROM. RBR
  was defined by Canetti et al., *Fiat–Shamir: From Practice to Theory* (STOC
  2019). Holmgren, *On Round-By-Round Soundness and State Restoration Attacks*
  (ePrint 2019/1261), shows that it is equivalent to state-restoration
  soundness. BCS16 (TCC 2016-B) gives the Merkle compilation. We do not import
  a numbered theorem from these papers. Steps 1–5 are the complete argument for
  Stele's own hash chain.
- The grinding step is the same counting with an independent predicate. It is
  why a k-bit nonce divides the per-query error by 2^k but costs the honest
  prover 2^k expected queries.
- The bound is per proof, for one statement output by P*. Several proofs under
  one model commitment are covered by a union bound over the proofs. The queries
  are shared, so the Q·ε* term does not multiply.

## 4. Round families: RBR errors (Lemmas 2–6)

Each lemma is an RBR restatement of an Accepted interactive argument. The new
work is the doomed-state definition and the per-round split. Every challenge is
uniform in K (|K| = p^4 or p^8) or uniform over column indices.

| Family | Round | RBR error ε_i | Source |
|---|---|---|---|
| SC | one sumcheck round of degree δ | δ/\|K\| | Lemma 2 |
| SC | zerocheck weight vector (j coordinates), skip (degree D) | j/\|K\|, D/\|K\| | Lemma 2 |
| RLC | one batching draw over t claims | t/\|K\| (as recorded) | Lemma 3 |
| SZ | one `relation/point` vector of a coordinates | a/\|K\| | Lemma 3 |
| LU | units θ (h coordinates) | h/\|K\| | Lemma 4 |
| LU | β (tuple compression, arity c) | (c−1)(N+\|T\|)/\|K\| | Lemma 4 |
| LU | α (denominator) | (N+\|T\|−1)/\|K\| | Lemma 4 |
| PCS tensor | ℓ CertificateWeight draws | 2·ℓ·(e+1)/\|K\| | Lemma 5 |
| PCS column | q_c certificate draws | ((N−e−1)/N)^q_c | Lemma 6 |
| PCS column | q_o opening draws | ((N−D+e)/N)^q_o | Lemma 6 |

**Lemma 2 (SC).** Use the state "the current running claim is false"
([sumcheck.md](sumcheck.md), RFC-0006 A1). A false claim is a nonzero difference
between the prover's round polynomial and the true one, of degree at most δ, so a
fresh challenge erases it with probability at most δ/|K|.

For the zerocheck ([zerocheck.md](zerocheck.md)):

- the weight round is doomed iff R(α) ≠ 0 for the chosen bad prefix, at cost
  j/|K|;
- the skip round costs D/|K|;
- each tail round costs δ/|K|.

These are the terms of the zerocheck's own union bound, each attached to the one
round that draws it. A recorded SC numerator (`m·δ`, or `j+D+j·δ`) is therefore
the sum of its per-round RBR errors.

**Lemma 3 (RLC, SZ).** The RLC state is "some batched claim is false". With
coefficients drawn in one round, a false batch survives on the zero set of a
nonzero polynomial of degree at most t−1 in the coefficients. That gives at most
(t−1)/|K| ≤ t/|K|, the recorded RLC numerator.

The SZ state for a matmul out-claim is "the claimed multilinear evaluation is
false". The ρ coordinates are drawn as one round, and Schwartz–Zippel on a nonzero
multilinear difference in a variables gives a/|K| (RFC-0012 A14/A16).

**Lemma 4 (LU, new).** This is the RBR form of
[weighted-logup.md](weighted-logup.md) §2. Fix the bad selected tuple x and its
exact fiber S_0, the set of selected positions whose tuple equals x. Both are
fixed with the sources, before θ. The schedule runs θ, then the multiplicity
commitment, then β, then α. Define the states:

1. **After θ:** doomed iff R_{S_0}(θ) ≠ 0. R_{S_0} is nonzero multilinear of
   degree at most h, so the escape probability is at most h/|K|.
2. **After β:** doomed iff z_β(x) avoids every table tuple and every other
   distinct source tuple. Each difference `z_β(x) − z_β(y)` with y ≠ x is a
   nonzero polynomial of degree at most c−1 in β. There are at most |T| table
   tuples and at most N source tuples, so the escape probability is at most
   (c−1)(N+|T|)/|K|. It is 0 for c = 1.
   Inside this state, S_β = S_0 and R_{S_β}(θ) ≠ 0. So the rational identity
   is false with a pole at z_β(x) outside the table.
3. **After α:** the cleared numerator is nonzero of degree at most N+|T|−1, so
   the escape probability is at most (N+|T|−1)/|K|.

The joint interactive bound of weighted-logup.md analyses θ and β together, in
the sentence "the raw verifier coins β and θ are independent". That analysis is
not RBR: under FS, P* can resample θ and keep the fiber fixed, and then β meets
an adversarially chosen θ. Lemma 4 charges the β round for collisions with source
tuples as well as with table tuples, which closes this gap.

In every RFC-0026 check, c ∈ {1, 2}, h = 0 (b = m) and |T| ≤ 2^16
(`relation.rs`, RFC-0008 A2 item 5). Each LU round is therefore at most N+c·|T|,
which is at most the recorded LU numerator plus one.

**Lemma 5 (PCS tensor).** The certificate chain starts doomed iff the frozen W is
farther than e = ⌊(D−1)/3⌋ columns from the interleaved code. After the row
weights r it stays doomed iff `d(a(r)ᵀW, C) > e`. Diamond–Posen Theorem 2
(CIC 1(1), p.10; [tensor-opening.md §1](tensor-opening.md#1-imported-theorem-and-its-hypotheses))
bounds the escape by 2·ℓ·(e+1)/|K|. Its hypotheses are a linear code over the
field, the distance D, and e ≤ (D−1)/3. The Circle and v2 codes of RFC-0010 A3
item 3 meet them for the evidence IDs pinned there, and v2 only outside Bad_setup.

**Lemma 6 (PCS columns).**

- **Certificate.** Inside the doomed state of Lemma 5, every t has
  `d(Enc(t), aᵀW) ≥ e+1`. q_c fresh uniform columns miss all disagreements with
  probability at most ((N−e−1)/N)^q_c ([tensor-opening.md §3](tensor-opening.md#3-query-and-near-matrix-argument)).
- **Opening.** The main chain is doomed when every source is near and some claim
  is false for its unique near message M* ([certified-functional-opening.md §2](certified-functional-opening.md#2-arbitrary-functionals-after-certification)).
  A false v forces u ≠ aᵀM*, hence `d(Enc(u), aᵀW) ≥ D−e`. The q_o columns
  escape with probability at most ((N−D+e)/N)^q_o, for any a, including an a
  that depends on earlier challenges.

**Composition over chains.** Call a statement false for a proof when one of two
things holds:

- (F1) some certified source is far;
- (F2) every source is near and the relation is false for the near messages.

Under F1, the far source's certificate chain starts doomed. Under F2, the main
chain starts doomed (Lemmas 2–4 and 6). Theorem 1's union over round starts runs
over all chains at once, because P*'s Q queries are shared. A Circle certificate
for a near W says nothing about its rows beyond nearness. Integer range, packing
and model identity remain the consumers' bindings (INV-4, INV-5).

## 5. Profile condition (answer to Q12's query-cap question)

**Convention.** A profile with security level λ, slack g and query cap Q_cap
admits a verifier-derived configuration iff all four conditions hold:

- **(C1)** every reachable round has `ε_i·2^-k_i ≤ 2^-(λ+g)`, so `ε* ≤ 2^-(λ+g)`;
- **(C2)** `ε_floor + ε_setup ≤ 2^-λ`;
- **(C3)** `H(1+Q_V) ≤ 2^-λ` and `H(Q_cap+Q_V) ≤ (Q_cap+1)·2^-λ`;
- **(C4)** every k_i is the least one that meets (C1), and grinding is
  scheduled only in the families listed in A17 (LU, PCS tensor and PCS column).
  Any other round that fails (C1) rejects the configuration as
  UnsupportedParameters.

H is convex in Q and the right side of (C3) is linear in Q, so the two endpoint
checks give `H(Q+Q_V) ≤ (Q+1)·2^-λ` for all 1 ≤ Q ≤ Q_cap. Theorem 1 then gives,
for every Q ≤ Q_cap:

```
ε(Q) ≤ Q·2^-(λ+g) + 2^-λ + H(Q+Q_V)            (exact form)
     ≤ (Q·(1+2^-g) + 2)·2^-λ                   (coarse linear form, by C3)
```

**Meaning, stated without spin.** Take a standard proof (λ = 100, g = 8).

- A tiny Q gives an adversary success probability about 2^-99.
- At Q = 2^80, the round term is 2^-28 and H is about (2^80)²/2^257 = 2^-97, so
  the total is about 2^-28.

The guarantee does **not** reach 2^-100 against 2^80 queries, and nothing with a
256-bit hash can: H(2^80) alone is about 2^-97.

The old literal reading was unsatisfiable, so this change is required, not a
weakening by choice. The resulting notion is the usual one of "λ-bit security"
for hash-based SNARKs, a time/success ratio of about 2^λ. FlashProve states its
theorem in the same form, as q/2^124 + 2^-101.

| Profile | λ | g | Q_cap | K | Grinding k_q on column rounds | Column target before grinding |
|---|---:|---:|---:|---|---:|---:|
| standard | 100 | 8 | 2^80 | QM31 or OM31 | 16 | 2^-92 |
| treaty (conditional, not admitted) | 128 | 8 | 2^100 | OM31 | 16 | 2^-120 |

**Why g = 8.** g is slack that keeps ε_floor ≤ 2^-λ for the round counts of real
proofs, which run to about 2^15 rounds in the stories42M ledger, mostly sumcheck
rounds at about 2^-122. A larger g costs queries. A smaller g pushes ε_floor
above 2^-λ once the LU and PCS rounds are summed.

**Why k_q = 16.** The honest prover pays 2^16 BLAKE3 calls per column round,
about 3.2·10^6 calls for the whole stories42M proof. In exchange, the column
rounds of the PCS, which dominate the proof size, drop to a 92-bit target.

**What C1–C4 need from the ledger.** The verifier or ledger generator (E8-05)
must enumerate every round with its exact numerator and fold the k_i. A record
that sums several rounds, such as SC m·δ or the LU joint numerator, is not a
per-round value. Lemmas 2 and 4 give the per-round split.

## 6. Results for the stories42M development statement

Computed with exact arithmetic by `research/fs-pcs/study.py`, under the
standard rule above. "Floor" is ε_floor + ε_setup.

| Configuration | Worst round | Floor | (C1)/(C2) |
|---|---:|---:|---|
| recorded proof (Policy 1, no grinding) | 2^-97.0 (LU range_8) | 2^-94.6 | fail / fail |
| Policy 2, v2 codes | 2^-108.0 | 2^-102.0 | pass / pass |
| Policy 2, Circle rate 1/4 | 2^-108.0 | 2^-102.0 | pass / pass |

The recorded proof fails even its interactive budget. Its largest LU round, the
weight range check over 2^27 positions, is 2^-97, and the LU sum alone exceeds
2^-100.

Under the rule, 19 of the 21 LU checks grind, at 1 to 12 bits (12 for range_8).
The Circle stack and model tensor rounds grind at 5 and 6 bits, and each of the
48 column rounds at k_q = 16. That is about 3.2·10^6 prover hashes in total. The
alternative to LU grinding is OM31 lookup challenges, which RFC-0026 does not use.

## 7. What is proven, what is conditional, what remains

**Proven (paper proofs, not machine-checked):**

- Theorem 1 in the classical ROM;
- Lemmas 2–6 as RBR statements, given the Accepted interactive lemmas they
  restate;
- the convexity step of §5.

**Imported theorem:** Diamond–Posen Theorem 2 (published, CIC 1(1)), as already
adopted by RFC-0010 A3.

**Conditional on:**

- BLAKE3 as a random oracle;
- the A8 frozen-oracle events charged to H;
- the A7 setup event for v2;
- the code distances pinned by RFC-0010 A3 item 3.

**Not used:** any Johnson-radius, list-decoding or capacity statement. The
Johnson-radius route is analysed in `research/fs-pcs/REPORT.md` and not adopted.
BCHKS (ePrint 2025/2055) proves O(n) exceptional combinations up to the Johnson
radius for Reed–Solomon codes. Two things keep it out:

- applying it to the Circle code needs a generalized-RS equivalence argument
  that we have not written;
- above unique decoding, a certificate no longer fixes a unique near message,
  so openings would need out-of-domain samples (as in Chiesa–Fenzi–Weissenberg,
  ePrint 2026/391), which is a protocol change.

**Remains open:**

1. Quantum adversaries. Theorem 1 is classical-ROM only. A QROM analysis of
   the hash chain, the Merkle frozen oracle and grinding is required before
   any claim against quantum provers. The A7 setup term is already
   seed-universal.
2. Zero knowledge and the treaty profile (Q29, RFC-0013). Masking adds rounds
   whose RBR errors are not derived here.
3. Exact round enumeration in the native generator (E8-05). The stories42M
   figures use the recorded ledger plus Lemma 4's bound of two LU rounds per
   check, each at most the numerator plus one.
4. The consumers:
   - grinding wired into the PCS column rounds and the LU and tensor rounds;
   - Policy 2 tables in `stele-pcs`;
   - a Circle-coded witness and model source for RFC-0026.

   Each is an implementation task with controls. The RFC text admits the
   parameters; no binary does yet.
5. Machine-checked statements (R-FORMAL), and the RFC-0026 promotion
   obligations of Q33 (uniqueness lemmas, passport binding).
