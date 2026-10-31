# Merkle field-oracle research review

Codex-root applied rfc-author, pcs-engineer and soundness-auditor. A separate
read-only agent reviewed the argument and helper and supplied the tiny-output
counterexamples. This is an internal agent review, not an independent audit.

- Public items: Draft RFC-0010 A8 addresses A3's fixed-oracle premise using
  RFC-0012 A3's exact Merkle frames. No native protocol or Accepted rule changes.
- Challenges: the conditional certificate uses independent interactive coins
  only after its source root/context is fixed. The study introduces no native
  transcript label and does not convert that order into a Fiat-Shamir claim.
- Claims: every accepted canonical column equals its frozen completion outside
  Coll or Late. The argument uses event containment without conditioning future
  challenge randomness on the absence of those events. Algebraic consumers
  remain the separate certified-functional-opening argument.
- Bindings: the checker rejects missing paths, malformed leaves, changed
  context and wrong levels. It matches 15 BLAKE3 reference trees and 57 paths,
  including duplicate queries and non-power-of-two padding. Research checks do
  not earn production NC credit. Native NC-0600..0605 remain incomplete.
- Ledger: the research entry counts one global collision event and frozen
  frontier hits over the full lifetime, including verifier and preprocessing
  queries. The explicit root term covers a never-queried one-leaf root. No
  machine-generated production record, proven flag or profile is admitted.
  Final review required a deterministic registration cap as well as per-root
  query caps; A8 and the accounting entry now state that bounded lifetime.
- Bound certificates: no integer identity or native bound certificate is added.
  Canonical u32le M31 values are required; reducing the modulus to zero rejects.
- Padding: the lift concerns real columns only. It does not prove canonical
  absent subtrees or the logical zero padding required by source reductions.
- Determinism: byte order, child positions and field parsing follow RFC-0012 A3.
  The tiny-output oracle has a fixed seed and is explicitly separate from
  BLAKE3. A replay retains its first frozen completion.
- Parity: native CPU/SIMD/CUDA code is unchanged. The new study compares its
  framing with the existing Python Merkle reference; no GPU result is claimed.
- Costs: the log and completed W are mathematical proof devices. Actual column,
  row-vector, encoding and cache work remains in T_misc/c_c. No measured
  constant, weight-pass change or benchmark is supplied.
- Verifier: the study returns no native verification receipt. Its authenticated
  column model rejects malformed fields; zero completion never accepts data.
  Native source/wire/cache/sampling and capacity contracts are still required.
- Glossary/history: A8 is append-only and Draft. Original task criteria remain;
  source ownership, packing, ZK and Q12 are explicitly open.

I tried to break it by supplying a first preimage for an unqueried frozen root.
The tiny-output oracle accepted a changed column without a collision, so the
argument keeps the separate Late event and its nonzero bound.
