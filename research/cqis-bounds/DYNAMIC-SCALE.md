# Consumed dynamic row scale — Q26 / Q31

Status: preimplementation research for RFC-0004 §5.5 / Draft A3/A8. Original
E5-03 and downstream criteria remain blocked/open; no production cut or private
proof is admitted. Apply cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor with same-author review, not independent audit.

Question: can the actual attained-magnitude consumer prove the independently
expected dynamic scale S=ceil(M/127), including the all-zero row, with linear
byte work and no plaintext verifier maximum/division? Cost/security terms are
c_a/c_sc/c_lu/T_misc, source association, static faithfulness and exact ceiling.
Kill criterion: any wrong scale, slack127, substituted source, carry or final
passes; a claim lacks an actual consumer; or whole-word field arithmetic replaces
the static integer argument. Stop rather than admit an unaccounted protocol.

Use only closed dynamic row_bounds.Spec, same wide/gated bounds and at most2048
elements as the attained-magnitude adapter. N=2^a; magnitude bytes B=2^b in{2,4}.
Fully consume that proof, an actual scale range at the closed scale_max, an
actual slack range0..126, and a B-element biased-carry range0..127. M has an
explicit auxiliary root passed to the actual maximum proof; raw input and scale
roots are independently expected. No supplied source map or optional consumer.

Prove 127*S=M+slack. The carry is signed: with S=256, M=32386, slack=126,
the low byte requires carry -1 because M_low+slack=256. Store T=C+1 instead,
with public T0=1 and terminal TB=1. For each byte j, consume degree1 A3:

    127*S_j + T_j + 255 - M_j - slack_j - 256*T_(j+1) = 0.

Here slack is its actual one-byte source at j=0 and public zero on higher
planes. Incoming T is public1 followed by the authenticated prefix; all other
operands are actual range-checked bytes. T in[0,127] gives integer side bounds
32767 and32893, so 2*32893<p. A second degree1 dimension0 A3 consumes TB-1=0.
These are fixed full-vector views; every emitted final is consumed even when
a coefficient is zero or dimension is zero.

Honest carries follow Cnext=(127*Sbyte+Cprev-Mbyte-slackbyte)/256. Exact global
equality makes each numerator divisible by256, and the bounds inductively give
C in[-1,126]. Initial/final C=0 give exact integer telescoping. With slack in
[0,126], 127*S=M+slack uniquely gives ceil(M/127); M=0 iff S=0. This does not
yet prove a separately committed nonzero flag, predecessor or row output codes.

The own A3 numerator is2b, with b draws each of ZeroWeight/Sumcheck. Three new
wide ranges contribute7b+0+9b; total A3 including attained magnitude becomes
71a+66b+9, retaining its separate A1 numerator a. Preserve the six inherited
lookup identities plus dimensions b+1,1,b+1 for scale/slack/carry, each with its
own repetition and reduction loss. Five roots and four verified child states
precede the parent A3 invocations; no new label, retry or inverted challenge.
Binding, FS/H and private composition remain separate.

Candidate namespace: parent identity<2^40 reserves base=2^63+2^22*identity.
External raw/scale ids are distinct u64>=2 outside that span. M/slack/carry
roots use base+1..3; incoming/slack/terminal views use base+8..10. The maximum
child identity is64*identity+1; scale/slack/carry wide ids are65536*identity+
4096..4098. Parent A3 ids are262144*identity+32768..32769, separate from all
nested spaces. Metadata and every capacity derive before payloads.

Tests first: exact integer corpus, all-zero and 127-multiple boundaries, the
negative-carry case, both fields/repetitions, malformed/canonical field controls,
wrong expected sources, coherent wrong scale with valid child ranges, and the
false zero-row S1/slack127 statement whose arithmetic holds but actual slack
range must reject. Check every source/view final and nested account; compare
small parent proofs with the naive A3 oracle. No performance measurement yet.
