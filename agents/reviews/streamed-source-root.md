# Streamed source root review

Codex-root applies soundness-auditor. This is a same-author review and does
not replace independent audit. The [scope](../../research/merkle/STREAMING.md)
and frozen baseline preceded implementation.

- Public items: `research/merkle/check_merkle.py::root` implements Accepted
  RFC-0012 A3 root construction. The research lookup `commit` keeps its
  descriptor and payload contract; only its root-construction call changes.
- Challenges: no draws, labels or absorbs change. The root is returned only
  after all real leaves, canonical absent padding and exact EOF are checked.
  Complete lookup proof/receipt digests are compared with the prior builder.
- Claims: original lookup source and multiplicity consumers remain intact.
  The helper creates no claims and does not authenticate a caller's source
  merely by computing a root. The caller still compares the expected root.
- Bindings: the existing Merkle suite passed 38 paths and 498 rejection cases.
  New controls cover short/long streams, wrong payload widths, changed ids,
  reordered payloads and explicit-zero replacements for absent padding.
  Complete lookup tests retain source and expected-root substitutions.
- Ledger: no challenge or soundness loss is added. Leaf/node frames and
  collision-resistance assumptions are unchanged. All 96 existing complete
  lookup cases passed with their receipt/accounting checks; required local
  soundness accounting remains pending.
- Bounds: no integer reduction or CQIS certificate changes. The descriptor
  fixes n and width before iteration. Python's integer index arithmetic does
  not truncate; the existing A3 descriptor validates its encoding bounds.
- Padding: the builder hashes exactly P leaves, including P-n absent leaves
  with empty payloads. A real zero-valued payload remains distinct. Node
  levels and indices follow the same complete binary tree as `build`.
- Determinism: leaf order is input order. Each odd node merges with the last
  completed left subtree; this is the binary carry rule for the processed
  prefix. Once P leaves have been processed, one root remains. No hash-map
  iteration, timing choice or second input pass selects the result.
- Parity: native CPU/SIMD/CUDA code is unchanged. Ten existing byte vectors
  retain their roots and paths. Complete revealing lookup parity is checked
  separately in QM31/OM31 with one/two repetitions; this is not GPU parity.
- Costs: P leaf hashes and P-1 node hashes remain. Retained tree digests fall
  from 2P-1 to at most h+1 in the root-only builder. Caller payloads and
  transient hash inputs remain additional. This is a structural bound, not
  a benchmark or fitted c_c/T_cuts/T_misc constant.
- Verifier: no native/no_std surface changes. Invalid descriptor, leaf length
  and stream length reject before returning a root. Caller exception handling
  is unchanged; no bypass or fallback root is introduced.
- Glossary/history: Accepted text is unchanged. The research note and Q26/Q31
  continuation preserve original task criteria. This helper does not raise
  weighted-source capacity or give native/private/model-ownership credit.

I tried to break it by changing a committed lookup source word, and the
CommitmentMismatch control rejected it. A changed expected root also rejected
at FinalEvaluationMismatch. All 96 existing complete lookup cases and their
controls passed. All 10012 new tree cases over 2478160 real leaves, including
the large boundaries, passed. All four frozen complete proof/root/receipt
digests matched the original builder. The checker asserts the corpus count
and digest. All nine CI inventory/aggregate tests passed. Required repository
gates and hosted CI remain pending; independent audit is still required.
