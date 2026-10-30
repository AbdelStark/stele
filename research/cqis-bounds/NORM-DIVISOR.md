# Consumed RMSNorm divisor — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3 and
RFC-0022 §2.3 require paired A=N*4^-min(a,0), D=P*4^max(a,0), where
P=ed*d*2^(2F). This extends the fully consumed scaled numerator with the
same actual exponent's divisor. It does not establish the normalized interval,
mantissa/remainder, rsqrt, outputs or physical/model/private inference proof.

Question before implementation: can the same verified exponent indicator bind
every configured divisor byte while retaining the scaled numerator's actual
sources and all original/public claims? Cost terms: c_a/c_sc/c_lu/T_misc for
the complete child and one extra A3 with fixed public/source views. Kill
criterion: substituted indicator, zero/noncanonical divisor, high padding,
whole-field alias or modified public final survives its actual consumer.

Expected metadata is the complete closed norm Spec(d,F,G,E,en,ed), with all
original domains. Four independent external roots bind N, offset=a+23, A and
D. The first three retain the scaled consumer's exact representations. D has
exactly16 canonical-u32 byte slots; static Dmax=P*2^18<2^124 fits without
truncation. No supplied P, factor, table or observed maximum is authority.

Fully verify one scaled child against its three expected roots. That child
already verifies the exponent one-hot range, sum1, offset/factor A3s and the
complete scaled product, so the exponent is consumed once. Read its same
actual64 indicator words and repeat them across16 byte planes. Derive the
entire public grid from expected metadata: for i<33, a=i-23 and grid[j,i]
is byte j of P*4^max(a,0); indices33..63 are zero. One dimension10 degree2
A3 enforces indicator[i]*(D[j]-grid[j,i])=0. Its three originals are the
verified indicator view, actual bound divisor view and exact public grid;
all final MLE claims retain actual emitted-point consumers. Plane variables
lead the six exponent variables, MSB-first.

Exactly one valid index is already established by the child's actual range
and sum. The new relation therefore forces every canonical divisor byte,
including high zeros, and yields D>0 and D<=Dmax. It uses the full public
domain rather than recomputing a whole private power from a supplied exponent.
Negative exponents share the same D=P; their offset binding and scaled source
relations remain mandatory even when N=0 also makes every scaled result zero.
This study introduces no additional Accepted limb role or public-MLE kind.

Namespace: identity<2^38, base=2^63+2^24*identity. Scaled child id64*identity+1
occupies base+2^18..base+2^19-1; its descendant roots remain inside that span.
Parent view ids are base+8,+9,+10. The parent A3 id2^20*identity+2^19 is
disjoint from the child's descendant invocations below that offset. All four
external ids are distinct u64>=2 outside the whole parent span. Prefix
stele/research/q26/norm-divisor/v1 plus NUL, version/field/repetitions, five
u64 ids and complete expected norm function bytes seed the parent with all
four expected roots and the fully verified child state before the A3 starts.
Every weight/round/final keeps the inherited transcript framing and order.

Account before implementation: the new dimension10 degree2 A3 contributes
30/|K|,10 ZeroWeight draws and10 Sumcheck draws. With product planes2^b and
output slots2^g, total A3 numerator163+9b+18g. Retain the child's four separate
lookup dimensions7,b+2,g+3,g+3, their identity/reduction losses, exponent A1
loss6, product identity C-1 and product A1 loss4b; none is squared or repeated
except each lookup's own specified repetition. Full nonlookup ZeroWeight
draws63+4b+8g and Sumcheck70+6b+8g include product rho/A1s. Binding, FS/H,
remaining normalized interval and model/private composition are additional.

Tests first:10000 independently computed NumPy object-integer divisors, all33
exponents, maximum124-bit D and complete parameter bounds. Public grids must
match independent equality-basis MLE evaluation at10000 extension-field points
per field, varying configured P and including Boolean/zero/one/minus-one points.
Complete proofs cover both fields/repetitions, negative/zero/positive exponents
and maximum parameters, with exact losses/draws and all original/public claims.
Controls change every divisor slot, fresh valid-range D and D+p, same-result
negative exponent proofs under the wrong offset root, actual indicator words,
and composition-preserving original/public finals. Supplied grid/P overrides,
malformed shapes, roots, metadata and noncanonical fields must reject. Compose
an actual upstream numerator root; a valid substitute must fail its source join.

Recommendation: continue Q26/Q31 with M in[16384,65535], actual MD=M*D,
A=MD+R and strict0<=R<D, then the complete rsqrt lookup and output branches.
Only those consumers establish the unique normalization interval. Original
task status/criteria, production controls and private proof obligations remain.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_divisor.py`.
Tests first failed with the missing module. All33 exponents and10000 varied
NumPy object-integer divisor cases passed, including the124-bit bound and
every zero-pad index. Seed2690 frozen corpus SHA-256:
`04185115f4347a30084ce0cee2e441d557b54336bbc52cd5ca28d342b16ea4ac`.

Every source/public/alias control and actual upstream numerator composition
passed. A false D proved against a one-cell-corrupted public grid satisfies
all Boolean equations and the final composition but rejects Divisor:ClaimMismatch
at the actual public consumer. Composition-preserving final alterations also
reject there. Fresh zero D, D+p and high-byte proofs fail the actual relation.
A valid different negative exponent retains identical N,A,D at N=0 but fails
the independently expected offset root. No verifier or expected-error change
was needed. All16 complete proofs passed in both fields/repetitions, negative,
zero and positive exponents, including actual124-bit maximum divisors with
nonzero byte15. Every proof checks exact losses, draws and parent claims.
Frozen proof-state SHA-256:
`b888f31a2ab75071db6053258bf61224da1682b3270ae1e75f8e768eb762ce5e`.
Independent equality-basis evaluations passed at10000 points per field, with
varied configured P and degenerate/Boolean points. Frozen public SHA-256s:
QM31 `11ef1acd733e033f81d984356bae5d90514bc6f1d3ff1c44bc0562e5251e5fd9`;
OM31 `9e68cf408d67a90c22faf8b21529c88b41cfa86b47cade83aa9c038ea30f3d5f`.
All required local gates passed. No measured performance, native control credit
or independent audit is claimed.
