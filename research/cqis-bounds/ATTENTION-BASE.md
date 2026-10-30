# Consumed attention offset base (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the same
probability-sum source Z bind the common offset base H=S*Z without a whole
M31 product or unchecked configured factor? Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if a valid different Z/product source, an altered S at Z=0,
a bounded H+p alias, a carry error or truncated external root is accepted.

The expected schema is the existing attention-sum schema. An expected actual
key count n satisfies1<=n<=min(configured term capacity,16384). It fixes the
static source cap Zmax=n*2^E<=2^28. S is the schema's exact restored-value bound:
127*259 for dynamic values, or s*min(127,floor((65536+s)/(2*s))) for static.
No runtime value chooses either bound. Absolute-key/mask ownership belongs to
the probability-sum composition. Zero Z remains valid for a block contribution;
whole-row positivity still requires actual attained-maximum/exponential proofs.

Consume Z with a complete scalar wide range. Bind its compact root separately
and zero-extend the actual bytes to the external four-byte root already used
by the probability-sum consumer. Use the existing complete limb-product with
one term, left cap Zmax, right cap S and radix256. Its paired source bytes are
exactly the verified Z bytes and public configured S bytes, padded to the
product's static input width. Every whole-source range, packing relation,
polynomial identity, carry/output range and original consumer remains required.

Compare the product's supplied source layout with that exact expected layout;
then run the complete product verifier on its derived source root. This check
remains mandatory at Z=0, where a changed S would otherwise leave H unchanged.
The internal product output root stays compact; zero-extend its actual canonical
bytes to the external eight-byte H root. K<=6 result columns imply its strict
next-power output padding uses at most eight bytes. There is no verifier-side
plaintext multiplication, supplied receipt or new parent challenge.

Before implementation reserve identity<2^44 and base=2^63+2^18*identity.
The Z range uses identity4096*identity+1 and source base+1. The complete product
uses identity64*identity+1, paired source base+2 and compact output base+3;
its namespace occupies[base+4096,base+8192), disjoint from the Z range. Two
distinct external ids stay outside the entire span. Parent context binds the
full expected schema/count/ids, external Z/H roots, compact Z/product-output
roots, exact product-input root and both complete verified child states.

Let bz be the compact Z byte-width exponent, b the product input byte-width
exponent, and g the product's padded result-dimension exponent. The four lookup
dimensions are bz+1,b+2,g+3,g+3. Keep each independent identity
((2^m+255)/|Kfield|)^r and unsquared reduction
r*(F(m)+F(8)+3*m)/|Kfield|, F(m)=3*m*(m-1)/2+2*m.
The planned range/A3 numerator is7*bz+9*b+18*g+31. Retain the product's
separate identity numerator K-1 and reduction numerator4*b. Nonlookup draw
counts are3*bz+4*b+8*g+13 ZeroWeight and3*bz+6*b+8*g+14 Sumcheck.
The wrapper draws none. Confirm every formula with actual receipts before
claiming evidence; Binding, FS/H and private composition remain additional.

Write tests first:10000 independent NumPy products, convolution/carry checks,
canonical source layouts and external roots, both policies, exponent/count
extremes and compact widths. Cover both fields/repetitions, zero and maximum Z,
minimum products and strict output padding. Mutate each external root; substitute
independently valid different Z and product children; change configured S while
Z=0; forge H+p using genuine bounded output bytes; retain every child and all
full roots at zero. Compose actual probability-sum proofs on the same Z root,
including valid different probability sums. Require the maximum supported
Z=16384*2^14, S=65535 scalar product and all repository gates. This is a scalar
binding; it does not claim a new full-row reduction or increased key capacity.

The tests-first run rejected the missing module. Seed2736 passed all10000
independent cases and66186 paired source cells; the frozen corpus hash is
`ce46ecda5b6958819169b8f74fbb7c43d594ef21138313f492b889e892bdfa88`.
External-root, valid source-substitution and zero-hidden configured-factor
controls passed. A bounded H+p, actual Z-cap violation and high external
planes rejected at their required consumers. The initial complete receipt
and draw account matched. Actual probability-sum proofs composed for1,3 and65
keys, including valid alternate-sum rejection. All 16 matrix proofs passed both fields/repetitions with exact receipt and draw
accounts; their frozen SHA-256 is
`7b5e6bd9488d8e13cf6f50ee9488d66aa4c6c1d83550b67c9f247680c646eae7`.
The maximum scalar proof also passed with Z=2^28 and S=65535, hash
`5e222abd79ef0680c10068f5d19a1eeed808f7212f39934987651b32dfc1f223`.
Required repository gates remain queued.

Continue Q26/Q31 with canonical sign and
magnitude of O-H, block rounding and normalization. Full source/model ownership,
native/private PCS/ZK/FS, fidelity, GPU/scale and original criteria remain open.
