# Q30 — Private verification relation and composition

Question: can a ZK argument of knowledge over the complete Stele verifier hide
its inner proof while preserving the exact statement, treaty budget, one weight
pass and original cost targets? Kill criteria: missing inner checks, statement
substitution, unsupported extraction/privacy/assumptions, extra weight reads or
failure of the complete workload gates. Run
`python3 research/private-verifier/check_boundary.py` (standard library).

The [formal note](../../formal/private-verification.md) defines the private
witness as the entire inner proof and binds the actual verifier and public
statement. It explains why ordinary language soundness is insufficient for
generic composition with a computational inner argument: the existence of an
accepting string need not imply its efficient production. It gives an explicit
conditional extraction interface and derives
`p <= kappa + L*epsilon_inner(T_ext,Q_ext)` from it. This is not a claim that
any backend supplies that interface, or a replacement for its actual theorem.

The finite experiment enumerates 114 search-domain/budget/order cases. Each
oracle hides one accepting candidate in a domain of size 2^bits, bits 1 through
8. The existential statement is true for every oracle. A fixed distinct-query
search nevertheless succeeds on exactly q/N of the uniformly chosen hidden
candidates. No search sees the hidden candidate except through query answers.
This illustrates the difference between language membership and producing a
witness; it is not a cryptographic separation, random-oracle proof or actual
outer verifier. Unqueried-output and repeated-query mutants are rejected by the
experiment's checks. Neither is NC-1203 or a production rejection control.

The [pinned source inspection](UPSTREAM.md) identifies actual Stwo privacy code,
different direct/recursive paths and a 96-bit configuration target. The checker
reproduces that target's integer arithmetic for all three listed configurations;
it does not derive their full security. No profile admission, complete ZK
simulator or evidence of a backend vulnerability follows from these checks.

Keeping inner proof bytes private can address the direct column disclosure
identified by Q29, conditionally on complete outer ZK. Previously public passport
certificates remain disclosures. Repeated proofs, mask entropy, preprocessing,
program outputs and joint hash/FS queries retain their privacy/security duties.
Using the wrapper as treaty privacy would make it mandatory and critical to that
acceptance path, contrary to silently treating the optional wrapper as a fix.
This study selects no such architecture and leaves the native ZK objective intact.

Relevant cost terms are the original T_proof plus witness preparation, proving
the entire verifier execution and serialization; retained inner proof, outer
state and overlapping copies all contribute to peak memory. The dataflow may
avoid rereading private weights if the retained inner proof and public artifacts
are sufficient. This has not been measured. No benchmark constant, one-pass
native result, <=5% overhead result or W8 certificate is supplied.

Recommendation: continue with Q30 under Draft RFC-0016 A1, resolving the actual
backend mode, quantitative knowledge/privacy/FS composition and complete verifier
translation before core implementation. E14-01 remains blocked, including its
original dependencies, Q14, W8 and NC-1203 obligations. Q29, native PCS, packing,
source binding, CQIS and complete inference remain open. No toy wrapper API or
prover-supplied acceptance flag is introduced.
