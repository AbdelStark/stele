# Q12 amendments acceptance review (RFC-0012 A17, RFC-0010 A14, RFC-0002 A1; task E12-22)

Reviewed: branch `task/E12-22-q12-amendments`, stacked on E12-21 and E12-20. These are
internal agent passes, not an external cryptographic audit.

The evidence is the two Draft notes that the amendments adopt:

- `formal/fs-composition.md`, with its independent review in
  [q12-fs-composition.md](q12-fs-composition.md): accepted after fixes H1–H3,
  M1–M4 and L1–L5;
- `research/fs-pcs/`, with its independent review in
  [q12-parameter-study.md](q12-parameter-study.md): accepted after fixes H1,
  M1–M3 and L1–L6.

## Pass 1, soundness-auditor (same author)

- **Error terms named.** Each one comes from the fs-composition.md §4 table:
  - SC, RLC and SZ;
  - LU, as one (β, α) round;
  - the PCS tensor round;
  - the PCS column rounds;
  - FS (Theorem 1);
  - H* (a global term, convex in Q_t);
  - the A7 setup term.
- **Theorems cited.**
  - Diamond–Posen Theorem 2 (published), already adopted by RFC-0010 A3.
  - The query lemmas of tensor-opening.md §3 and certified-functional-opening.md
    §2, which are Accepted under A9.
  - Theorem 1 and Lemmas 2–6, which are paper proofs.
- **Proven or conditional.**
  - Everything in the admitted standard parameter set is proven, conditional on the
    ROM, the A8 frozen oracle, the A7 setup event and the A3 item 3 distances.
  - No conjecture is used. The Johnson-radius and capacity routes are explicitly
    not adopted.
- **Profile meaning changed.** It is stated in RFC-0002 A1, ADR-091 and fs-composition
  §5: a per-query bound with a 2^-λ floor, not 2^-λ against Q_cap queries.
- **Treaty.** Not admitted.
- **Development proofs.** Unchanged.

## Pass 2, rfc-author (same author)

- **Amendment format.** Each amendment carries:
  - an id, motivation and exact replacement text;
  - its soundness and cost impact;
  - the affected tasks: E12-22, E12-23, E16-30, E8-05 and E12-04.
- **Accepted text superseded.** It is named exactly:
  - RFC-0010 A3 item 7;
  - RFC-0012 §5's FS illustration;
  - RFC-0026 §1.2's two sentences, for the standard profile only;
  - RFC-0002 §8's two rows.
- **Index, research agenda and logs.**
  - The RFC-0000 index is updated.
  - The Q12 resolution is added to RFC-0019.
  - ADR-091 is appended.
- **Controls catalog.** NC-0806/0807 are reserved as todo for E12-23, and the
  catalog snapshot test is updated.
- **Glossary.** No new term outside the glossary; glossary-lint passes.

## Pass 3, crate owners (stele-hash; same author)

- **Primitive.** `Transcript::grind` and `verify_grind` follow A17 item 5 byte for
  byte.
- **Independent vectors.** The Python reference vectors
  (`research/transcript/check_grind.py`, blake3-py) match the Rust KAT at 1, 8
  and 12 bits in QM31 and OM31.
- **Errors leave the state unchanged.**
- **Work accounting.** A PoW attempt counts as one hash evaluation and no state
  update.
- **Registry and gates.** The registry grows to 47 entries, and the gate inventory
  and test lists are updated.
- **No other consumer changes.** No other crate draws from the new label, and no
  proof byte of any existing protocol changes.

## Independent pass

Pending; recorded below before merge.
