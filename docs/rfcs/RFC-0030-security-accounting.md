# RFC-0030 — Security accounting: round-by-round error, Fiat–Shamir and the profiles

Status: Draft · Version: 0.1.0 · Depends: RFC-0002, RFC-0008 (A2, A5), RFC-0010 (A3, A9), RFC-0012, RFC-0027

Resolves Q12 when Accepted. Until then the texts below stand and no proof is admitted
to `standard` or `treaty`. Tasks: E21-01, E21-04, E12-03.

Texts this RFC proposes to replace, each by an amendment in its own RFC at acceptance:

- RFC-0002 §8 (the profile table);
- RFC-0012 §4, the FS line and the "total" rule; RFC-0012 §3, the option to truncate
  Merkle digests to 192 bits in `standard`;
- RFC-0012 A8, its last paragraph ("treaty therefore requires r=2 and OM31");
- RFC-0008 A2 item 2, the line fixing `r` and `d` per profile, and item 8, the hand
  derivation under the old charge.

## 1. Statement

### 1.1 Motivation

- RFC-0012 §4 charges Fiat–Shamir as "hash queries times the largest round error"
  and then requires the *total* to stay below `2^-100` or `2^-128` for an adversary
  with `2^80` or `2^100` queries. That asks every round for `2^-180` or `2^-228`.
- No parameter set meets it. RFC-0010 A3 item 7 shows Policy 1 failing both profiles.
  RFC-0019 Q12 notes that the hash term `Q²/2^256` alone is `2^-56` at `Q = 2^100`.
- Deployed hash-based systems and the public soundness calculator maintained for
  zkVMs state security per hash query, as below. So does the one machine-checked
  inference prover: FlashProve's bound is "about q/2^124 + 2^-101", a per-query term
  plus a fixed term. Under this convention the query counts RFC-0010 A3 already
  derives (`2^-130` per query round) are sufficient.

### 1.2 Definition

A protocol has **round-by-round error** `ε` when, for every round, the probability
over that round's challenge that a doomed prover state becomes not doomed is at most
`ε`. A proof configuration has **λ bits** when `ε ≤ 2^-λ`.

> **Claim of a profile.** For every adversary making at most `Q` queries to the hash,
> the probability of an accepted false statement is at most
> `c₁·(Q + c₂)·2^-λ + H(Q)`, where `H` is the RFC-0012 A15 hash line and `c₁`, `c₂`
> are the constants of the cited compilation theorem.

The theorem is the BCS compilation of a round-by-round sound interactive oracle
proof in the random-oracle model. Acceptance of this RFC pins the exact statement,
its constants and the conditions it places on the transcript (every prover message
absorbed before the challenge that follows it; the first challenge depends on the
full statement, including every model root and the plan digest).

### 1.3 What a ledger reports

The verifier derives, from the plan and the profile only:

- one record per round family with its numerator and denominator (unchanged lines SC,
  RLC, SZ, LU, PCS, MASK);
- `λ_min`, the least `−log2` over all rounds, and the five weakest rounds by name;
- the H line for the profile's query cap.

It rejects a configuration whose `λ_min` is below the profile's target, an evidence
id it does not know, or a record it cannot derive. The sum of interactive terms is
still printed, as information.

## 2. Round errors

| Family | Round | Error | Basis |
|---|---|---|---|
| sumcheck | each round of degree `δ` | `δ/|K|` | Schwartz–Zippel |
| zerocheck | the `eq` point | `m/|K|` | RFC-0006 A3 |
| claim or identity batch | one coefficient, `t` items | `(t−1)/|K|` | RFC-0006 A2 |
| matmul point | `a` coordinates | `a/|K|` | RFC-0012 A14 |
| lookup instance | unit, beta, alpha rounds | RFC-0012 A8 record, `(h + N + c·t − 1)/|K|` for the pair round | RFC-0008 A2, A5 |
| lookup trees | each layer round | `3/|K|`; layer combination `1/|K|` | RFC-0008 A3 |
| commitment, proximity round | tensor of `ℓ` coordinates, radius `e` | `2·ℓ·(e+1)/|K|` | RFC-0010 A3 item 6 |
| commitment, query round | `q` columns | `((N−e−1)/N)^q` or `((N−D+e)/N)^q` | RFC-0010 A3 item 6 |

Each row is an existing interactive bound read per round. No new bound is introduced.

## 3. Profiles

Proposed replacement for RFC-0002 §8. It is weaker than the letter of that section
by the factor `Q`: a `standard` proof promises `2^-100` per hash query, so about
`2^-20` against `2^80` queries, where §8 asked for `2^-100` in total. That is what
"100-bit security" means in every system this project compares itself with, and it
is the strongest statement a 256-bit hash supports.

| | development | standard | treaty |
|---|---|---|---|
| `λ_min` | not claimed | at least 100 | at least 128 |
| bounds | printed, labelled | proven only | proven only |
| grinding | — | not counted | not counted |
| challenge field | QM31 | QM31 | a wider field for every challenge, wide enough that every round clears 128 (about 152 bits under the caps below) |
| lookup repetitions `r` | 1 | 1 | 1 on the wider field |
| zero knowledge | no | optional until RFC-0013 A2 is Accepted | mandatory |
| hash output | 256 bits | 256 bits, no truncation | 256 bits, leaves domain-separated |

Consequences on QM31 (`|K| ≈ 2^124`), all enforced by plan validation:

The cap is exact: a round with numerator `n` clears 100 bits when
`n ≤ ⌊p^4 / 2^100⌋ = 2^24 − 1`.

- **Lookup instances are capped.** `h + N + c·t − 1 ≤ 2^24 − 1`. The plan uses
  instances of at most `2^23` positions with tables up to `2^16` rows. A larger check
  is split by the plan. A second challenge pair (`r = 2`) is not required.
- **Splitting has a price in bytes.** With independent instances (RFC-0026 A7) each
  instance carries its own tree proofs, tens of kilobytes by RFC-0008 A3's lengths, so
  a proof with thousands of instances spends tens of megabytes on them. The form
  intended for `standard` shares the challenges of a check across its instances and
  proves all their trees as one data-parallel reduction, with one root pair and one
  multiplicity vector per instance (Q49). The alternative is `r = 2` on unsplit
  checks, at twice the lookup prover work.
- **Commitment rows are capped.** `2·ℓ·(e+1) ≤ 2^24 − 1` for every source and level
  (see RFC-0029 Q50 for what this costs in proof bytes).
- **Batches are capped** at `2^24 − 1` items.
- Sumcheck rounds need no cap (`δ ≤ 4`).

No QM31 round reaches 128 bits: a degree-4 sumcheck round is already `2^-122`. So
`treaty` draws every challenge from a wider field. OM31 is implemented; whether a
186-bit extension is cheaper is decided by measurement (task E12-03, R-OCTIC).

Grinding may be added to any query round. It is reported on its own line and adds
nothing to `λ_min`.

## 4. Verifier algorithm and cost

`stele-verifier::accounting` derives the records of §1.3 while it derives the plan,
before the first transcript absorb, and compares `λ_min` with the profile in the
public input. Cost: linear in the number of round families, independent of the
witness.

## 5. Soundness

This RFC changes how existing terms are combined and what the profiles require. Its
own obligations:

1. the compilation theorem and constants of §1.2, cited exactly;
2. a round-by-round statement for each reduction in §2, with the state function
   named (the composition of RFC-0028 §5 inherits them);
3. the transcript conditions of §1.2 checked against `stele-hash` and the relation
   engine: every prover message absorbed before the next challenge, and the first
   absorb holding the whole statement;
3a. separately, the known attack on Fiat–Shamir for proofs of computations that can
   evaluate the hash on their own transcript. Absorb order does not address it. The
   obligation is an argument that no admitted model class can express a BLAKE3
   evaluation (the relation set is fixed integer arithmetic and lookups into public
   tables derived from `cqis_id`), or a stated residual risk;
4. a classical random-oracle claim only. Security against quantum adversaries is a
   separate question and is not claimed.

Items 1 and 2 are written in `formal/` for `standard` and are Lean statements for
`treaty`.

## 6. Negative controls

NC-0804 (ledger total tampered) and NC-0805 (profile downgrade) keep their ids.
Proposed, entered at acceptance:

| NC | Tamper | Expected |
|---|---|---|
| 0806 | a plan with one lookup instance above the cap, presented as `standard` | `ProfileBound` |
| 0807 | a source whose evidence id the verifier does not know | `UnsupportedSource` |
| 0808 | a proof that omits one model root from the first absorb | `RoundSumMismatch` at the first challenge-dependent check |

## 7. Open questions

- **Q12** (restated): the exact theorem, constants and query convention; resolved by
  acceptance of this RFC.
- **Q49**: data-parallel lookup instances. One tree reduction over all instances of
  a check, with shared Beta and Alpha, one root pair and one multiplicity vector per
  instance. The pair round's error is then the largest instance's, because a false
  check has a false instance and the shared challenge must be a root of that
  instance's nonzero rational function. State and prove it; give the proof bytes.
- **Q46**: knowledge soundness. The bounds above are soundness relative to the unique
  near codeword (RFC-0010 A3 item 6). A consumer that needs an extractor (recursion,
  the passport binding) must state and prove it.
- **Q47**: the post-quantum claim. Which statement in the quantum random-oracle model
  is defensible for this protocol, and at what loss.

## 8. Amendment log

None.
