# Q23 finite expander sampling review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author and
soundness-auditor passes. Not an independent audit. Research only.

I tried to break it by retaining zero-valued sampled coefficients and enumerating
all tiny graph/entry assignments, and the calculated graph and conditional-entry
probabilities stay below their exact rational union bounds. This is not a test
that a particular production graph has good distance.

- Graph rows select distinct neighbors uniformly; duplicates are excluded.
  Entries are sampled independently from the full field, including zero.
  Changing to nonzero-only entries requires a different probability bound.
- Bad graph probability covers all size-k supports. Conditional on expansion >b,
  every fixed nonzero input has independent uniform output coordinates at its
  neighbors. A low-weight image is contained in some (t-1)-subset of m columns,
  leaving at least b-t+2 independently constrained zeros. The study uses the
  exact number (p-1)^k of nonzero coefficient assignments on each input support.
- Two exhaustive F3 cases enumerate all 27 degree-two graphs and 729 entry
  assignments per graph. An F5 case checks all 15,625 entry assignments for a
  full graph, including the nonzero target-weight condition. Each entry bound
  is strictly between zero and one, with actual conditional failures counted.
  The test separates graph failure from conditional entry failure.
- Each of the six finite matrices checks every required support size. Binary
  search chooses the smallest degree satisfying these sufficient bounds, not
  the smallest degree capable of good distance. That monotonicity follows from
  C(b,d)/C(m,d) decreasing with d for b<m. Fractions use arbitrary-size integers.
- For each recursive step, D=floor(2n/50)+1 and the previous distance threshold
  determine the ranges. A must map nonzero input of weight below D to nonzero;
  B requires image weight D-k for each inner weight k below D. These conditions
  inductively preserve the target distance if the base encoder meets its bound.
- The 748 graph/entry events contribute at most 748/2^160 for this finite
  three-step ensemble. This assumes the stated uniform sampling, not an arbitrary
  fixed seed, adversarial setup, chosen graph, PRNG heuristic or profile.
- Larger lengths require scalable, rigorously rounded interval certificates.
  Code identity, setup selection/grinding/reuse, base encoding and PCS proximity
  remain open. No code registry or proof binding is enabled; no challenge,
  production loss line, NC status, measured constant or weight pass changes.

Sign-off: approve the research evidence while retaining RFC-0010 A1 as Draft and
E4-01 as blocked. Do not import these degrees as production parameters.
