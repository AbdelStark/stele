# E16-40r H100 GKR construction review

Lane E reviewer `resident_actual` accepts the lane V research implementation
at `b9444699` and the component evidence from Lucid job 6774. The H100 ran
`490379a4`. The intervening commit adds a host-only test that invokes the same
span writer. I operated the run and reviewed the implementation independently
of its authors. [Hardware receipt](e16-40r-h100.json)

I traced each borrowed input in RFC-0008 A7 from the production construction
interface to its output address. Equality uses the offset-relative MSB-first
index. Blocks interpolate the two halves at the line-fold point. Column and
mask gathers use checked bit positions. Child pairs select
`values[2 * position + side][component]`. Table compression gives the
low-index tuple entry coefficient one and writes one on padding. Disjoint
member ranges preserve selector and shifted-column ownership. Combined mask
indices use the low bits, and allocations are zeroed for unowned positions.

The domain and each repeated span bound every destination. Source bounds
follow from the gather length, layer dimensions, block shape, equality
point length and uniform width of valid table rows. Domain powers and mask
coordinates are checked before launch. The device receives the original
field words, coordinate shifts and production term descriptors. The host
counts the explicit input and descriptor transfers, including repeated
uploads. Construction does not measure peak residency or launch parameters.

In the raw pass every input field limb receives the modulus, including
constant and gather field arguments. Dimensions, indices and bit shifts keep
their integer representation. The writer canonicalizes each output limb.
The readback rejects a noncanonical word before constructing an M31 element.

The exact CUDA test checked 1,000 seeded statements and 2,728 construction
steps in both representations, for 5,456 comparisons of complete initial
states, rounds and folded states. It compared every compact final, applied
production expansion and routing, and called the ordinary CPU proof verifier.
The host control rejected an oversized span, an invalid gather and a ragged
table. Both exact tests passed. I replayed archive and manifest validation,
checked the executable readback and both Slurm records. Slurm recorded
`COMPLETED`, `0:0` and zero restarts.

The CPU authored the proofs and transcript. The device constructed resident
summands and performed the compared arithmetic. Whole-proof GPU parity, peak
memory, scale and performance remain separate qualifications under ADR-127.
