# Consumed RMSNorm exponent factors — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3 and
RFC-0022 §2.3 require a in[-23,9] and the factors4^-min(a,0),4^max(a,0).
This relation does not establish that a normalizes N/P: that requires the
remaining scaled numerator, divisor, mantissa and strict remainder consumers.
No native/private/model admission, production cut or complete norm is claimed.

Question before implementation: can a bounded exponent select both exact
factor byte vectors while consuming every original source and public claim?
Cost terms: c_a/c_sc/c_lu/T_misc for the one range, two A3s and one A1,
including all actual openings. Kill criterion: an out-of-range index, empty
selection, changed factor byte, inactive factor, or altered public final passes.

Expected metadata is the complete closed norm Spec(d,F,G,E,en,ed), retaining
all RFC-0021 parameter domains. External roots bind one canonical-u32 slot
for offset=a+23 and16 slots for two little-endian eight-byte factors, negative
then positive. Neither a signed field lift nor a whole-field power replaces
these bytes; the negative factor reaches2^46. All input fields are canonical.

An actual wide-range child has64 one-byte indicator words, caps1 for indices
0..32 and0 for33..63. Its complete lookup, source, cap, Boolean carry and
terminal consumers remain. An A1 of dimension6 enforces sum(indicator)=1;
the static bound64<p gives exactly one selected index in integers. A dimension6
A3 enforces indicator*(offset-index)=0. Public index is0..32 followed by
zero padding; it is derived, never supplied. These establish offset in[0,32].

A dimension10 A3 uses the same indicator repeated across16 factor-byte slots:
indicator[i]*(factor[j]-grid[j,i])=0. For i<33, grid contains the corresponding
byte of4^max(23-i,0) or4^max(i-23,0); other entries are zero. The plane index
is leading and the exponent index trailing, MSB-first. The actual original
indicator, offset, factor and public-table MLE claims are all consumed at their
emitted points by the existing full-table consumer, even when a branch factor
equals1. Exactly one indicator proves every factor slot is its canonical byte,
including all high zeros; no separate supplied byte bound is authority.

Namespace: identity<2^50, base=2^63+4096*identity. Indicator source base+1;
wide-range child id64*identity+1 has span base+64..base+127. Parent A3 ids
256*identity+128,+129 and A1 id+130 do not overlap child A3 ids+4..+7.
Public/source views use base+8..base+13. External offset/factor ids are distinct
u64>=2 outside the entire parent span. Prefix stele/research/q26/norm-exponent/v1
plus NUL, version/field/repetitions, three u64 ids and complete norm function
bytes seed the parent along with offset/factor/indicator roots and the verified
range state. Parent order is exponent A3, factor A3, then one-hot A1. Each
instance and round/final frame retains the inherited transcript order.

Account before implementation: the indicator range has a=6,b=0, A3 numerator54
and lookup dimension7. Its identity loss is(383/|K|)^r and reduction198r/|K|,
using F(m)=3m(m-1)/2+2m. Parent degree2 A3s add3*6+3*10=48; total A3 is102.
The one-hot degree1 A1 adds6/|K| separately, unsquared and unrepeated by r.
Parent ZeroWeight draws16 and Sumcheck22; full nonlookup draws40 and46.
The range lookup retains r beta/alpha and15r gamma/fold draws, plus56r Sumcheck
draws (7*6/2+8*7/2+7=56); no Unit draws. FS/H and binding remain additional.

Tests first: all33 exponents and10000 independent NumPy integer byte cases;
both fields/repetitions with endpoints, zero and both signs; exact draws/losses.
Check public table evaluation at10000 extension-field points per field against
independent equality-basis evaluation, including Boolean and special points.
Controls change each role, high bytes and expected metadata; forge empty/two-bit
selection, a zero-cap padded selection with wrapped slack, and a nonbit selection.
Forge valid range children with wrong exponent or factors, and preserve a
zerocheck final composition while changing actual originals/public values.
Malformed roots, shapes and noncanonical fields must reject before arithmetic.

Recommendation: continue Q26/Q31 with the actual scaled numerator/divisor,
mantissa/strict remainder, complete rsqrt lookup, and output branches. Bind the
same offset and factor roots there; this receipt alone does not prove exponent
normalization or ownership of any upstream statistic/model tensor.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_exponent.py`.
Tests first failed with the missing implementation module. All33 public rows
match exact integer powers and byte encodings; seed2686 covers10000 NumPy
integer cases and complete expected metadata. Frozen corpus SHA-256:
`cb0a9948a89b6da7522709e62144c297f404742067906c41dab2ee42363aed20`.
All16 complete proofs passed for a=-23,-1,0,9 in both fields/repetitions,
including exact accounts, draws and all original/public claim counts. States:
`9f539bcceead4396722ec3e4e295af53d5a910de423d9ed37f84aad9a8faf650`.

All planned controls passed. Genuine ranged empty/two-bit selections reject;
one-value changes to every external slot fail root binding. Fresh parent
proofs with changed high/low factor bytes or exponent fail actual relations.
Changing both original/public finals while preserving their composition fails
the original consumer. A padded selection with wrapped slack satisfies every
parent relation and sum1 but rejects Indicator:TerminalCarry:RoundSumMismatch.
The nonbit selection also rejects its actual bound. No verifier bypass or
expected-rejection repair was needed. Public-point checks and local gates are
pending; no measured performance or independent audit is claimed.
