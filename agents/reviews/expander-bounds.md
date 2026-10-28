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
- The schedule covers twelve recursive steps, n=4^j for j=4..15. Each matrix
  checks every support below 128 exactly. The new formal derivation covers every
  larger support with rational bases G_A/G_B/E_A/E_B less than one, whose
  128th powers are checked against 2^-288. No floating-point/entropy estimate
  or sampled interval point is used as certification. Exact combinatorics at
  n=4096 cross-check the implemented interval inequalities.
- Low-support threshold search brackets upward before binary search, avoiding
  unnecessary m-sized powers. Degree search uses monotonicity of
  C(b,d)/C(m,d) for b<m. Its result is the smallest degree satisfying the
  selected sufficient bounds, not the smallest degree with good distance.
- For each recursive step, D=floor(2n/50)+1 and the previous distance threshold
  determine the ranges. A must map nonzero input of weight below D to nonzero;
  B requires image weight D-k for each inner weight k below D. The formal
  induction requires a valid n=64, N=128 base code of distance at least three.
- The 200,431,782 graph/entry events contribute at most 200431782/2^288,
  below 2^-260, under the stated uniform sampling. This is not a certificate
  for an arbitrary fixed seed, adversarial setup, PRNG heuristic or profile.
  The stricter per-event allowance leaves arithmetic headroom for the stated
  grinding cap; it does not discharge Q12 or prove an FS/setup composition.
- Code identity, setup selection/grinding/reuse, base encoding and PCS proximity
  remain open. Other lengths are not covered. No registry or proof binding is
  enabled; no challenge, production loss line, NC status, measured constant or
  weight pass changes.

Sign-off: approve the research evidence while retaining RFC-0010 A1 as Draft and
E4-01 as blocked. Do not import these degrees as production parameters.
