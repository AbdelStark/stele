# Candidate private verification relation (Q29 / Q30)

Status: Draft, RFC-0016 A1 / RFC-0013 A1. Question: can a complete ZK argument
of knowledge hide an inner proof without rereading original weights, while
preserving the exact inference statement and treaty budget? Kill criteria:
omitted inner check, statement substitution, unproved extraction or privacy,
unaccounted backend assumptions, extra weight reads or failure of full cost gates.
This is a conditional architecture, not an admitted wrapper or completed ZK PCS.

## 1. Exact relation and public boundary

Let V be the approved deterministic inner verifier, whose mathematical source,
parser, integer/field semantics and complete checks are fixed independently of
the proof. Let s be its exact public statement and authenticated public config.
The candidate wrapper relation is

`R_V(s, pi) = [canonical_parse(pi, plan(s)) succeeds AND V(s, pi) accepts]`.

The private witness is the whole inner proof pi, including its round messages,
intermediate claims, row vectors, queried columns, paths and any certificates
that are not already public under the privacy contract. The statement includes
the spec/format version, approved verifier/program identity, minimum and selected
profile, field, CQIS and plan identities, passport root, input/output commitment
or digest, decoding policy and all public security parameters. The ledger is
recomputed from authenticated config; its supplied digest is checked, not trusted.
Canonical encoding and any compressed statement digest need explicit binding.

The wrapper must execute V on that same s, rather than on a different statement
carried inside pi. A claimed accept bit, an unchecked program hash, a proof-supplied
plan, an echo of s or a host callback returning true is not the relation. Verify
the actual parser, transcript schedule, source/claim consumers, bound certificates,
lookup checks, profile accounting and Merkle/PCS checks. Constrain every branch,
byte, integer-to-field conversion and rejection path that affects acceptance.
Compiler correctness and the low-level program identity are part of this boundary.

The public output is the approved statement and outer proof only. Publishing pi,
its row/column payloads or an extra digest of secret-dependent inner data requires
its own allowed-disclosure argument; it does not become safe because another
proof is ZK. Program output, logs, public-memory exports and recursive accumulator
fields must obey the same boundary. Proof lengths/padding derive from public
shapes unless a separate length-hiding policy is specified.

## 2. Soundness requires quantitative extraction

Ordinary language soundness of the wrapper is insufficient in general. An inner
computational argument can have accepting strings for a false inference claim
that are hard to find. Then the existential language of R_V may contain that
claim, so proving membership in that language alone does not preserve the inner
computational soundness guarantee. A wrapper argument of knowledge must yield
an actual accepting pi, with its extraction work and oracle queries accounted.

A precise sufficient conditional interface is the following. For any allowed
outer adversary with false-inference acceptance probability p, an extractor of
bounded work T_ext and oracle access Q_ext outputs (s,pi) with s false and
R_V(s,pi)=1 with probability at least max(0,(p-kappa)/L), where L>=1. If the
inner argument bounds success by epsilon_inner(T_ext,Q_ext) for this extractor,
then

`p <= kappa + L*epsilon_inner(T_ext,Q_ext)`.

This implication is elementary; it is not a theorem that a named backend has
this extractor. The complete outer knowledge error, loss and resource model
must be instantiated, including recursive layers. For a different extraction
transfer function use its actual inverse instead of this expression. A generic
epsilon_inner+epsilon_outer sum is justified only by an applicable loss-one
composition result. Larger extraction work can invalidate the inner query cap.

Q12 applies jointly to inner and outer hashing/Fiat-Shamir. Establish separate
domains, which oracle(s) are shared or programmed, all adversary/extractor/simulator
queries, state-restoration/grinding and the quantum adversary model of RFC-0002.
No classical-only theorem, bare parameter bit count or underlying STARK name
settles that composition. Statement-digest binding losses also remain explicit.

## 3. Privacy and repeated use

Conditionally, a ZK simulator for the exact outer relation can generate its public
view from s without pi. This hides inner row/column payloads even if the inner
protocol by itself reveals them. It addresses Q29's fixed-oracle disclosure issue
only because those payloads are kept private. A publicly released registration
certificate or earlier inner proof remains a disclosure and cannot be retracted
by wrapping later proofs. The passport certificate lifecycle must be compatible.

Require the simulator and secrecy of every outer mask, including base/extension
field support, quotient/FRI disclosures and seed generation. Masking the inner
messages is not a substitute for this outer proof. Conversely, merely running
a validity prover on V does not make its witness pi hidden. Any PRG-derived masks
need a stated assumption and lifecycle; witness-dependent seeds require an
applicable argument rather than an assertion that they look random.

Repeated proofs need the actual multi-session/adaptive privacy guarantee and
fresh permitted outer state. Under an applicable hybrid composition theorem,
the privacy advantage may be bounded by the sum of per-session errors plus
the stated generator/oracle terms. This remains conditional on that theorem's
hypotheses, including prior disclosures and the verifier/adversary class.

## 4. Profiles, native verification and cost

RFC-0016 currently makes the wrapper optional and outside native soundness.
If this construction is selected as the source of treaty privacy, it becomes
mandatory and soundness-critical for that acceptance path. An explicit amendment
must define the external proof type and forbid fallback to the unwrapped inner
format for that path. This study does not select that change. The original
native ZK objective remains until an Accepted complete architecture replaces it.

An internal proof relation may use unmasked messages only under an Accepted
format whose complete mathematical soundness budget meets the outer statement.
It is not a standard-profile downgrade, a missing-MASK bypass or permission for
an existing treaty verifier to ignore a check. No such mode is added here.
Wrapping a lower-security argument does not automatically raise its security.
Keep every existing source, CQIS, packing, proximity, extraction and FS obligation.

The algorithmic dataflow can avoid a second source-weight visit: retain the
already-produced pi and construct the outer witness from pi and public artifacts.
V must not request original private weights. This is a possible schedule, not a
native read-count result. Regenerating discarded inner data, streaming archives,
preprocessing and public-certificate reads still have costs and must be charged.

Let I=|pi|, W_V the full execution/arithmetization work for V, and M_V its retained
state. The relevant totals include

`T_total = T_inner + T_prepare(I,W_V) + T_outer(W_V) + T_serialize`,
`M_peak = peak(inner retained proof/state + outer witness/code/hash state + copies)`.

Do not count just the outer verifier, or assume the wrapper is cheap because V
is sublinear in model size. Hash checks, field conversions, lookups, padding,
allocations, masking, code/FRI work and compilation/preprocessing all contribute.
Keep cold and reusable preparation separate; reusable costs need a declared
lifetime. Actual clean-source ledgers must test the complete original workload,
one weight pass, <=5% ZK overhead, W8 <=500 KB and <=200 ms verification, CPU/GPU
parity and original controls. No such measurement is supplied by this note.

## 5. Backend evidence and implementation gate

The [pinned upstream inspection](../research/private-verifier/UPSTREAM.md) finds
actual Stwo privacy-specific code, not an absence of support. It also finds a
96-bit parameter target in the inspected configuration and different direct/
recursive paths. Those observations do not instantiate Stele's treaty budget,
simulator, quantum composition or verifier translation. No upstream prover is
vendored into core and no dependency or admitted parameter changes here.

Before acceptance, select a complete backend/mode and pin its source, verifier
key/preprocessing and theorem versions; implement the exact V relation; derive
all knowledge/privacy/hash losses and code hypotheses; specify public/private
bytes and the repeated passport lifecycle; and provide the full native costs.
Actual controls must change an inner value/path, expected statement, plan,
program/parameters or hidden-claim relation and fail the real outer consumer.
NC-1203 must include a rejected inner proof presented to the actual wrapper.
No language toy, parameter audit, bit-count formula or host-side V call supplies
that evidence. E14-01 and Q29/Q30 remain unfinished.
