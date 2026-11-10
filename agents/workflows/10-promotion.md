# Workflow 10 — Promote a capability (development → standard → treaty)
A capability is a relation kind, a reduction, a module, a commitment mode or a profile parameter set. Promotion
is its own task and its own change; it never rides with the change that introduced the capability (RFC-0027 §2).

**To `standard` (T1). All of:**
1. Its RFC text is Accepted on the full path of Workflow 02. A development-tier amendment is re-reviewed as if new.
2. Every round it adds has a record the verifier derives, with a named theorem, and clears the profile's λ
   (RFC-0030). No conjectural term. No term outside the ledger.
3. Its soundness argument is written in `formal/`: for a module, the output-uniqueness lemma; for a reduction, the
   round-by-round statement; for a commitment mode, the proximity and query bounds with their evidence ids.
4. Controls: every binding it has is in `tests/negative-controls/catalog.md` with status `done`, run through the
   actual verifier.
5. The independent Python verifier implements it and agrees with the Rust verifier on honest and mutated proofs.
6. Its parser and verifier paths survived the fuzz campaign of Workflow 05 with no panic.
7. The `soundness-auditor` review is recorded in `agents/reviews/` with the Workflow 03 sentence.
8. A `standard` ledger exists on the lowest rung that exercises it.

**To `treaty` (T2). T1 and all of:**
1. Zero knowledge covers it: masks or encodings per RFC-0013, a written simulator argument, the leak list updated.
2. Its rounds clear 128 bits from proven bounds on the treaty challenge field.
3. Its statement in `formal/` is a Lean statement that type-checks, with assumptions listed; its proof checks or the
   gap is recorded in `formal/GAPS.md`.
4. It is inside the scope of the external review.

A promoted capability is frozen at its tier: any subsequent change to it repeats the steps it invalidates.
