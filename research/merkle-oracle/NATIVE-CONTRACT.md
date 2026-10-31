# Native field-source contract evidence

Question Q27: which exact bytes, finite query policy and source-consumption
schedule can close native A1 claims against Circle/Merkle roots? The security
property is consistency with the certified source's unique near message.
Reject the candidate if it permits proof-selected source authority, biased
indices, an unconsumed original or a circular certificate transcript.

[The proposed contract](../../formal/native-field-pcs.md) binds source context
and the verified certificate before A1, then opens every returned original.
It uses native MSB coordinate order and canonical M31 columns. Certificate
and opening response blocks bind before any continuation. A verified handle
has no unchecked import or boolean acceptance path. Errors abort the whole
attempt, including partially advanced transcripts.

The tests-first policy run failed at the missing native_policy module.
Run `python3 research/merkle-oracle/check_native_policy.py`. Exact integer
inequalities verify the least certificate/opening query counts for all
59 supported Circle identities, including C=1. Exhaustive counts over
12 small Mersenne-field/index distributions verify equal accepted preimages;
direct modulo gives unequal counts. All 30 M31 index exponents pass their
threshold boundaries and reject noncanonical candidates.

The canonical query-pair list has SHA-256
`4252ce8234022de43c3e2b14196221989aa3a6106a37e1cdac67636375a6c406`.
This is deterministic parameter evidence, not a native proof digest or a
performance measurement. The checker uses only standard-library integers;
the native proposal uses immutable tables and requires no big integers.

Read-only review checked certificate circularity, source authority, byte
order, continuation absorption and complete original consumption. Its one
clarification, aborting every verifier error, is now explicit. Native/Python
proof parity, actual negative controls, malformed-proof tests and resource
measurements remain implementation gates. No native PCS behavior, profile,
ZK, fused B, packed source or Q12 result is supplied by this study.
