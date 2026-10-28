# Q31 — Ordinary LogUp at the M31 characteristic boundary

Question: does RFC-0008's identity prove lookup membership at the public maximum
counts, with selectors and extension challenges? Kill criteria: an invalid source
satisfies the rational identity or a pole makes the root check vacuous. Cost terms:
c_lu/T_misc, multiplicity commitments, table work and retained state. Reproduce
with `python3 research/logup-characteristic/check_characteristic.py` (stdlib).

The [formal note](../../formal/logup-characteristic.md) gives the exact p-copy
counterexample in characteristic p. QM31 and OM31 have the same characteristic
as M31, so neither a larger challenge field nor repeating the identity fixes it.
The cited LogUp-GKR paper explicitly requires fewer than p lookup positions;
RFC-0012's illustrative N≈2^37 does not satisfy that condition.

The study compares 240 fraction trees to independently summed inverses and rejects
a parent-numerator sign mutant. It checks 3,000 cleared-numerator identities over
F_5, including 2,250 invalid bounded-count cases with nonzero polynomial numerator.
Across five prime fields, 33 nonpole challenge cases make p invalid copies vanish.
All seven nonpole F_9 challenges also vanish, hence all 49 independently chosen
pairs do; this is arithmetic evidence, not a produced LogUp-GKR proof.

Exact pole/padding examples yield (0,0) and expose why cross multiplication alone
is insufficient. Neutral (0,1) padding preserves the other fraction. A separate
146-case tuple-compression check verifies the fixed-bad-tuple collision bound.
These checks do not authenticate selectors, source values, roots or table ids.

Static selected-count partitions below p repair the nonvanishing-residue premise
when each partition is actually proven. Their invalid residues can cancel again
if their equations are merely summed. Exact shape arithmetic gives 65 minimum
capacity-(p-1) partitions or 128 capacity-2^30 partitions for 2^37 positions;
the latter uses 8,388,608 multiplicity slots for a 2^16-slot table. No native
performance, optimality or fitted constant follows. The newer weighted-unit
LogUp work is another candidate, requiring a different complete protocol.

Recommendation: continue Q31 with Draft RFC-0008 A2 / RFC-0012 A8 and keep E3-07
blocked until the selected count/unit, pole, selector, compression and repetition
contracts are complete. Preserve actual table-side committed consumption,
NC-0400..0403 and c_lu measurement. No production challenge/ledger record, core
lookup implementation, admitted profile or native control credit is supplied.

The [weighted-unit continuation](WEIGHTED.md) gives a grouped equality-unit
candidate, a conditional repetition proof, a virtual tree and instrumented
single/paired preparation. It retains all native/privacy/consumer requirements.

The [fraction continuation](FRACTION.md) executes the conditional tree reduction
and selected-product leaf equation with complete public original-array consumers.

The [whole lookup continuation](LOOKUP.md) connects these claims to actual source
and multiplicity Merkle roots, with explicit revealing consumers and full accounting.
