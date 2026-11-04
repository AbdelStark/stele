# Native complete-row conversion — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 §2.2/2.5
and flow §1. The row Quantiser derives and retains the complete existing schema-4
record from its independently supplied parameters before evaluating any row.
Those parameters include full dimension, kind, fraction, policy and u32 scale.
They cannot be changed through the object. Runtime maxima do not enter certificate
derivation, and repeated numerical evaluation reuses that immutable certificate.

Separate int16 and gated entry points check the configured kind and exact complete
row length. Gated values must lie in [-2^30,2^30]; the API is not a general int32
converter. Its bounded numerical inputs do not prove that the original up/SiLU
operation produced those values. Model, operation, original source and actual
consuming-reduction ownership remain separate obligations.

Dynamic mode scans the full row, preserving the first index at each strict
magnitude improvement. The all-zero result retains index zero and maximum zero.
Scale is ceil(M/127), with bounds 259 for int16 and 8454661 for gated inputs.
Static mode retains the exact configured positive scale and has no maximum or
selected-index result. It never switches to dynamic mode on overflow.

Both modes compute floor((2*abs(x)+s)/(2*s)), with the original sign restored
after magnitude rounding. The explicit zero-scale branch is reached only by a
complete dynamic zero row and performs no division. All operands are below 2^33
and use u64. The code range check precedes narrowing and sign restoration, so
the forbidden -128 code cannot escape. A nonzero negative source may round to
code zero without changing the separately retained original input.

The returned row owns all codes together with its full runtime scale and original
parameters/fraction. Its fields are private and read-only accessors expose no
partial mutable result. Input-domain errors are found before allocation; a late
static code overflow discards the entire output. Allocation is fallible and bounded
by the declared dimension. This does not create a committed intermediate tensor.

The new NumPy corpus contains exactly 10000 randomized rows for each of wide
dynamic, wide static, gated dynamic and gated static conversion, plus 74 boundary
cases. It uses int64 absolute values, independent quotient/remainder rounding,
complete code arrays and NumPy's first-maximum selection. Selected cases also
cross-check the unchanged scalar research converter. Each of the 100 configuration
groups compares its complete static record digest with an independent derivation.
Random input rows are reproduced from a public fixed-seed integer generator and
checked against complete input digests. Every expected output byte stays in the
fixture. This avoids checking in redundant random inputs. The generator is test
data only, never a Fiat–Shamir challenge. No historical campaign entry point runs.

Boundaries cover full width 16384, both source endpoints, fraction endpoints,
zero rows, tied attained maxima, negative values rounding to zero, half-away ties,
static overflow and the full gated input/scale ranges. Native controls additionally
reject invalid parameters, empty/short/long rows and mismatched entry-point kinds.
Truncating configured scale 65537 to its otherwise valid low-u16 value makes the
same original row reject. Changing fraction preserves the integer codes while
changing the certificate bytes. These numerical checks do not complete NC-0122
or any source-bound proof control.

## Workflow 03

1. Quantiser::new, parameters and certificate implement flow §1's complete static
   scope. The two conversion methods implement §2.2/2.5 and flow §1. QuantisedRow
   accessors retain the complete codes/scale/fraction bundle and dynamic maximum.
2. No challenge, transcript label or absorb order changes.
3. No proof claim is emitted. Actual Model/operation/source checks, field-relation
   consumers and certificate admission remain required.
4. The row_conversion tests reject scope/parameter/input/range changes and compare
   full scale and first attained index. NC-0109 and NC-0122 retain their existing
   actual-consumer requirements; no catalogue status changes.
5. No random loss or accounting formula changes. Existing source/range/scale
   equality obligations cannot be replaced by a successful numerical result.
6. Schema 4 is unchanged. Every quantiser derives it from declared parameters;
   no data-dependent maximum can relax the certificate.
7. Complete rows have no padding. This operation adds no selector, mask or cut.
8. Fixed original order and strict maximum improvement give deterministic ties.
   No floating point, hash-map order, calibration or automatic policy change occurs.
9. Complete Rust rows match all 40000 randomized NumPy cases and 74 boundaries.
   Model-wide inference, original-source/proof binding and GPU proof parity remain.
10. Row arithmetic is O(d) in T_misc, with one static derivation per immutable
    quantiser. No measured cost constant or online proof weight pass changes.
11. Core stays no_std, forbids unsafe, validates full dimension/kind and uses
    fallible output allocation. Its private iterator is always an immutable slice.
12. Quantiser, complete row, attained maximum, bound certificate, codes, scale
    and fraction retain the accepted meanings. Numerical results grant no authority.

I tried to break it by truncating a valid gated scale, supplying a wrong row kind,
using an out-of-domain gated value and placing a static overflow last; the controls
rejected them without returning a partial row. This same-author review does not
approve the unfinished E5-03 task PR.

Validation: both targeted tests pass, including 37385 successful rows, 2685
unrepresentable static rows and four invalid gated inputs in the reference corpus.
All-target Clippy, no-default-features check, 32 documentation tests, formatting,
533 Accepted RFC references, Rust policy and 755 local documentation links pass.
All 65 qualified reference/helper files remain unchanged. Full-task gates and
assigned actual-consumer controls remain due; frozen original GPT-2 preparation
was not rerun because none of its conversion or configuration code changed.
