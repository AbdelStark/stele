# E16-43 relation projection review

Lane E reviewer `resident_actual` accepts the CPU projection at `02c4e0fb`.
I requested a change to the earlier implementation at `108f3c3a`. A valid
24-axis QM31 column with an eight-entry output could keep two intermediate
arrays of 2²³ and 2²² elements live at once. The revised code evaluates that
subcube directly from the source column.

I checked the plan's coordinate maps for identity, combined relation,
contraction, matrix multiplication and GKR top and leaf inputs. Committed
column lengths and public operand tables match their declared axes. The plan
supplies distinct in-range domain variables, Boolean fixed coordinates and
in-range indices into the step's free challenges. The GKR caller uses only
domain variables.

For each assignment of the read variables, the constructor sets the fixed
source bits and scatters its assignment into the original source-axis
positions, most-significant first. Each free coordinate interpolates two
disjoint subcubes as `low + z * (high - low)`. The source bits for fixed,
variable and free axes are disjoint. Broadcasting either extracts a
contiguous run or gathers the specified variables in their original order.
Unread domain bits never change the selected entry. A scalar projects to a
constant over the entire domain.

With `v` read variables on an `n`-variable step, distinctness implies
`v <= n`. The only temporary field table has at most 2ᵛ entries. The final
output has 2ⁿ entries. All-variable reads borrow the input before broadcast,
and the interpolation stack depth is bounded by the number of free axes.
This accounts for projection working storage. The complete prover's peak is
a separate measurement.

I tried to break it by moving the sole variable between fixed bits in a
65,536-entry column, and the control `matches_reference_wide_column_on_a_small_domain`
rejected disagreement with the directly addressed source values. I reran that
test and `matches_reference_projected_relation_columns`. The latter compares
with an independent equality-weighted multilinear evaluation over scalar,
permuted, fixed, free and broadcast cases, including extension-field points.
Both passed.

The change is private to the producer. The verifier still evaluates its own
column claims and verifies source openings. The transcript, degrees, rank
checks, profile, padded-domain semantics and soundness ledger retain their
existing definitions. Full native controls, fixed proof bytes and matched
stories42M measurements remain merge evidence for the intended tree.
