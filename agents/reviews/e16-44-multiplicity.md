# E16-44 lookup multiplicities

The independent resident-backend reviewer inspected `25ced32d` against
`f32d8d1c`. The actual witness values, canonical M31 lookup table ordering and
existing binary search determine which table row receives a selected point.
The implementation reuses the key buffer and the same sort and search for
arbitrary tuples, including duplicate canonical rows. Fixed, permuted and
shifted references and selectors retain the original projection and padding.

Review requested one change. A caller can replace the table exposed by
`Layout.statement` after derivation. Direct singleton indexing must be
injective over that table's valid rows, including when the provided valid
count exceeds the stored table length. At `392afdaa` the shortcut scans the
actual valid prefix, requires exactly one integer per row equal to its index,
and limits that prefix to the field modulus. Larger tables use the general
canonical search. The full-column loop also requires one unselected identity
projection of the correct length.

The reviewer accepted the corrected implementation and independently reran
the differential for canonical aliases, duplicate keys, signed shifts,
fixed and permuted coordinates, selectors, unmatched tuples and padding.
No transcript or verifier operation changes.
