# Weighted private selection study — same-author skill review

Scope: Q20 / Draft RFC-0006 A4 research, using gkr-reduction-author and
soundness-auditor. This is not an independent audit or protocol acceptance.
Evidence: [study and reproducible checker](../../research/stacked-gkr/WEIGHTED-PRIVATE-SELECTION.md).

- RFC/public items: GridSpec and the weighted wrapper investigate A4's source
  coordinates and selected coefficient semantics; no production API is added.
  Accepted A1 reduction behavior and Accepted RFC text remain unchanged.
- Challenges: full Weighted metadata/query/value precede root A1; every A1
  Instance and Round precedes its Sumcheck draw, Final precedes the following
  instance, and Originals precedes continuation. There is no added draw kind.
- Claims: root coefficient uses the grid-prefix evaluator; internal equality
  finals use full-cube equality; child claims feed their unique tree nodes.
  All k originals retain their exact source points and are independently
  consumed, even with a zero broadcast factor or leaf slope. Actual private
  source/view, bit, integer packing, range and PCS consumers remain missing.
- Bindings/controls: original padding-hole mutation rejects with
  OriginalSourceMismatch; changed scope rejects with OriginalSourceScope.
  Omitting Weighted changes one following final and rejects with
  FinalEvaluationMismatch. These are research checks, not catalog controls;
  no NC-0203 or full claim-graph coverage is claimed.
- Ledger: the candidate paragraph records Weighted/Originals and the unchanged
  a*M draws and a*(3M-1)/|K| conditional loss. No production ledger row or
  FS/H/PCS/ZK term is discharged; accounting gate validation remains required.
- Certificates: no integer inference identity is admitted. Preparing valid
  indices is not a verifier range/packing proof or static bound certificate.
- Padding: source axes form a Cartesian grid with internal holes; root masking
  excludes all invalid cells. Original bit planes are zero there. Affine leaves
  need not be zero; padded tree leaves are one. Category range remains a real
  source obligation, including k=0's unique zero category.
- Determinism: canonical increasing source axes, explicit selectors and fixed
  heap/bit order; no map-dependent transcript order. Seeded checks pass in both
  fields; the prior study's proof/receipt checksum is unchanged.
- Parity: no native/GPU implementation changes or new parity claim. Both-field
  Python reference agreement does not establish CPU/SIMD/CUDA parity.
- Costs: frame, prepared payload cap, transient row vector, grid enumeration,
  proof and consumer costs are explicit in the study. No measured constant or
  benchmark result changes; no ledger performance entry is applicable.
- Verifier: production no_std code is unchanged. Metadata constrains total bits,
  axis count, source order and proof counts. The research object API is not a
  production byte parser or a total process-memory bound.
- Glossary: terminology follows the existing source/claim/coefficient contract;
  glossary and link gates must pass before publication.

I tried to break it by changing an original at a padding hole under zero weights
and omitting Weighted before a chained reduction, and the control rejected it.
The first rejection requires the actual original-source reference consumer;
conditional verification alone intentionally exports that remaining obligation.
