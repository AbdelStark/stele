# Coordinated nonlinear contract acceptance (Q25 / E5-02)

Reviewer: codex-root, also author. Same-author soundness-auditor, rfc-author,
cqis-numerics, gkr-reduction-author and pcs-engineer skill passes. This is not
independent audit. The implementing roles cover stele-cqis, stele-ir,
stele-lookup, stele-reductions and stele-passport's affected interfaces.

Decision: accept RFC-0021 and companion RFC-0004 A4, RFC-0005 A1, RFC-0008 A4,
RFC-0009 A1 and RFC-0011 A2 as one contract. The earlier A2 proposal is
superseded by A4; its historical text and all prior Accepted text remain intact.
Native E5-02 remains in progress. No downstream acceptance criterion is removed.
E7-03 is explicitly blocked on the open norm/chunk certificate contract in A3;
its original requirement for dimensions beyond 2^14 remains unsatisfied.

Evidence: the full [numerical studies](../../research/cqis-tables/REPORT.md),
[Draft requirement mapping](cqis-functions-contract-draft.md), and
[table-root review](cqis-table-bindings-study.md). Exact artifacts regenerate.
Review corrected the new contract's passport task reference to E12-05; E9/E10
retain CPU/GPU inference. Earlier proposals' task shorthand is not a replacement
for the actual DAG. Native allocation must remain fallible; choosing a convenient
big-integer library cannot silently relax that rule.

Workflow 03 checklist:
- Public items: deterministic function/table/representation definitions and
  consumer interface requirements, with each byte field and supported parameter
  bounded. No native proof or inference API is admitted by this review.
- Challenges: none. All future actual reductions retain their own accepted
  challenge order, degree bounds and complete accounting. Hashing is ordinary
  BLAKE3; no profile-wide H/FS query budget is inferred.
- Claims/consumers: generated tables are values, not accepted claims. The plan
  binds operation order, sources, scales/gains and selected representations;
  actual lookup and PCS consumers must discharge every original claim.
- Bindings: NC-0412/0413/0414 are reserved as todo for actual function,
  representation and data consumers. Existing NC-0404/0405/0701 and numerical
  controls remain. No primitive test is reclassified as a proof control.
- Ledger: no challenge or loss changes. Uniform deterministic errors are proved
  in the exp, activation, GeLU and norm derivations, not fitted from samples.
  Q12, private PCS, zero knowledge and full lookup obligations remain open.
- Bounds: all parameter/precision/shape limits are static. Norm and wide exp
  identities explicitly require limbs/ranges and verifier-recomputed certificates;
  no modular equality is promoted to a wide integer identity.
- Padding: complete canonical zero rows enter table encoding, while the public
  valid-row selector remains distinct. Attention requires an unmasked attained
  maximum for real rows and excludes padded query rows.
- Determinism: exact signed rounding, fixed precision schedule, complete variants,
  explicit split/scales/epsilon, canonical row/manifest order and full code/tree
  context. Direct/corrected nearest exp share semantics but bind representations.
- Parity: independent exact generation and byte/root evidence supports acceptance.
  Native Rust/NumPy, all generators, 10,000-input and 10,000-point MLE parity,
  malformed/capacity/overflow checks remain mandatory E5-02 delivery gates.
- Cost: all memberships, correction storage, limb work, regeneration, coding
  and hashing are explicit c_lu/c_a/T_misc obligations. No measured constant,
  extra weight pass or new committed intermediate.
- Verifier: sealed checked authority, immutable table objects, complete data
  regeneration, checked lengths and fallible allocation are required. No raw
  manifest, callback, table id or Merkle root can authorize arbitrary contents.
- Glossary: component table, function, representation, data digest and root are
  distinct. A function set is not a complete model plan or passport.

I tried to break it by changing numerical variants, splits, component roles,
rows, field-congruent integer bytes and table roots, and the control checks in
the exact research executables rejected those substitutions. The wrong-table
attack also demonstrates that valid Merkle membership alone is insufficient.
These are research checks; no native catalog-coverage credit is claimed.

Sign-off by implementing role: cqis-numerics accepts the exact numerical and
generator contract; gkr-reduction-author accepts the explicit source/range/
selector obligations; pcs-engineer accepts the exact public matrix/code/root
contract. rfc-author accepts the coordinated amendment and DAG mapping;
soundness-auditor accepts the deterministic scope and retained proof obligations.
Acceptance does not assert implementation, model fidelity, independent audit,
completed lookup/PCS/ZK or either profile's end-to-end security/performance.
