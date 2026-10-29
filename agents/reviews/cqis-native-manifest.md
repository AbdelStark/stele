# Native function manifest review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §4,§6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: Manifest::new derives the exact expected function/component set,
  regenerates every table-data digest and emits the canonical record. Validation
  compares the entire record. Table::generate dispatches only registered components.
  No raw-data constructor or caller-provided table authority exists.
- Challenges: none; ordinary identity/data hashing uses the existing domains.
- Claims/consumers: a deterministic function set, not operation order, the full
  cqis_id preimage, passport or inference acceptance. Expected selections must
  come from their future authenticated consumers.
- Bindings: no new claim-graph edge or NC credit. Primitive tests mutate every
  manifest byte, truncate/append, omit functions and substitute valid representations.
  NC-0412/0413/0414 remain pending their real consumers.
- Ledger: no challenge/label/loss/profile change; accounting remains unchanged.
- Bounds: counts fit u32, descriptor framing fits u16, component candidates are
  bounded by three per function, and all sizes/allocations use checked arithmetic
  and fallible reservation. Each generated component has L<=65536 and c<=2.
  These resource checks do not replace reduction field-faithfulness certificates.
- Padding: full canonical padded integer data contributes to every digest, through
  the existing complete generator/encoder. Lookup selectors remain separate work.
- Determinism: sort by raw identities; reject duplicate FunctionIds even for
  different modes; deduplicate identical components and reject conflicting
  descriptors under one TableId. Input permutation cannot affect output bytes.
- Parity: the full existing Python manifest bytes/digest match. Tests cover empty
  sets, shared exp/rsqrt components, all thirteen generator dispatches, byte/length
  mutations, legal alternative selections and whole-table overflow. The internal
  collision branch is tested without adding any public identity-injection hook.
- Cost: sorting, complete generation/encoding and hashing remain T_misc. No fitted
  constant, benchmark, additional weight pass or committed intermediate is claimed.
- Verifier: no_std/no unsafe/no floats, no new dependency. Temporary vectors and
  the complete result reserve fallibly before append; tables are generated one at
  a time. Failure drops the owned prefix and returns no partial Manifest; expected
  selections remain borrowed and unchanged. Manifest bytes are immutable.
- Glossary: function-set validation does not claim full plan/passport authority.

Tests preceded implementation. I tried to break it by duplicating a semantic
function under two representations, omitting components/functions, altering every
record byte, overflowing a required table and conflicting internal identity
records, and the control checks in native primitive tests rejected those inputs.
They earn no NC credit. Public MLE delivery and actual lookup/private PCS/ZK/
inference consumers remain required; E5-02 stays in progress.
