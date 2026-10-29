# Q26: scale alignment and tied embedding storage

Question: how do configured source/weight scales become wide integer outputs,
how are differing residual units aligned, and which quantised tensor is shared
by embedding and LM-head roles? The properties at stake are reproducible integer
semantics, source-role binding and absence of implicit double rounding. Kill
criteria are an exact-oracle mismatch, premature saturation/range rejection,
an inconsistent zero-scale tuple or different tied tensors being treated as one.
This is research for RFC-0004 A3 / RFC-0017 / RFC-0011, not Accepted behavior.

## Combined matmul scale

With int32 accumulator A, positive 16-bit weight mantissa m, shared weight
exponent e_w, input scale s in source units 2^-F_x and target units 2^-F_o,
the candidate returns the signed-int16 value

    Y = R(A*m*s*2^(e_w-F_x+F_o)).

R is signed half-away, applied once after the exact integer dot product.
F_x,F_o lie in [0,30]; this study bounds e_w in [-1099,1024], covering the
source quantiser candidate. Dynamic mode admits s in [0,259], static mode
s in [1,65535]. The s=0 case additionally requires A=0. This consistency check
does not establish that the original source row was all zero; attained maximum,
source claims and range consumers remain mandatory.

The combined mantissa m*s can exceed 65535: m=65535,s=259 gives 16973565.
Do not truncate it or route it through the existing scalar Requant constructor.
The magnitude of A*m*s is strictly below 2^63 even at A=-2^31 and both static
mantissas 65535. The candidate divides this exact magnitude and rounds using its
remainder. A right shift of at least 64 gives zero because the magnitude is
strictly below the half unit. A nonzero left shift by more than 15 necessarily
overflows int16; smaller left shifts still check the signed endpoint. Zero can
be returned without constructing an enormous shifted integer. Metadata is checked
first, including zero cases. There is no saturation or implicit mode switch.

These capacity arguments do not prove an F_p relation. The full contract must
provide the corresponding wide multiplication, biased quotient/remainder and
range/carry certificates; a valid i64 computation alone is insufficient. Nor does
a supported numerical scale imply that a complete inference configuration is
admissible under those certificates.

## Residual scale alignment

For int16 X,Y in units 2^-F_x,2^-F_y and target F_o, the candidate defines

    Z = R((X*2^-F_x+Y*2^-F_y)*2^F_o).

Choose F=max(F_x,F_y,F_o), form the exact aligned integer sum
(X << (F-F_x))+(Y << (F-F_y)), then round once by F-F_o. Its magnitude is
at most 2^46 for fractional bits in [0,30], so int64 is sufficient. Check only
the final int16 range. Equal scales reduce to existing exact residual addition.

This choice matters: X=Y=1 at F_x=F_y=1 and F_o=0 yields 1, whereas independently
rounding each input yields 2. At X=-Y=32767, F_x=F_y=0, F_o=30, individual
int16 alignment would reject while the exact aligned sum is zero. This is a
proposed semantics for differing scales, not a silent modification of RFC-0004.
The model/plan still must select and bind every tensor exponent explicitly.

## One tied tensor, two roles

The candidate stores an embedding dictionary as vocabulary-major rows. Each
row is one quantiser channel with its own mantissa and the shared exponent.
Embedding gather selects the row and its scale, then rounds to the configured
wide units. The LM head takes integer dot products against those same rows and
applies their scales with the input row scale. It does not requantise a transpose.

This is compatible with a standard per-output-channel LM head: output channels
are vocabulary entries. The embedding role needs this explicit row-scale rule;
the general phrase “per-output-channel” is insufficient to define its axes.
Canonical storage, logical matmul axes and tying/source aliases must be bound by
the eventual artifact/plan contracts. No additional weight tensor or commitment
is introduced by the candidate. One-pass matmul proof scheduling remains separate.

For source rows [[1,2],[3,5]], row-channel int8 quantisation gives codes
[[63,127],[76,127]], while separately quantising the transpose and transposing
back gives [[42,51],[127,127]]. Even with exact source values, these are different
quantised models. The study retains one derived record for both roles and checks
its gather/LM arithmetic; it is not a checkpoint binding proof.

## Evidence and recommendation

Run `uv run --locked --script research/cqis-checkpoint/check_alignment.py`.
Independent exact rational expressions and NumPy integer quotient/remainder
checks agree on 20,000 combined-scale decisions (7,435 successful) and 10,000
residual decisions (3,771 successful); all other outputs reject overflow.
Additional cases check the largest combined product, extreme exponent shifts,
half ties, zero-scale consistency and malformed parameters. NumPy uses uint64
magnitudes and checks range before left shifts, avoiding invalid intermediate
overflow. Another 10,000 gather/LM cases reuse one tensor, split across int4/int8.
Counts and SHA-256 correctness checksums are not benchmark results.

Continue Q26 with these explicit candidates when fixing quantiser/weight bytes
and scale/certificate schemas. Source-role/tie validation, the full operation
plan, wide gain conversion, attention normalisation and complete forward/fidelity
remain required. E5-03 and RFC-0004 A3 stay blocked/Draft; no research helper is
imported into core crates. Preparation and future c_a scale/range work are named,
but no fitted constant, additional weight pass, challenge, NC-0102/0109 credit,
soundness-ledger term or profile admission is supplied here.
