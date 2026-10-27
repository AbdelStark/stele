# Transcript byte contract (Q11, RFC-0012 A1 candidate)

Question: can two implementations reproduce every absorb and extension challenge
from RFC-0012 §1 without choosing additional conventions? No: length widths,
initial state, XOF framing, post-challenge state and eight-limb sampling were
unspecified. The primitive also cannot infer a caller's required message schedule.

Security property: unambiguous framed inputs and unbiased field coefficients under
the ideal-XOF model, with explicit fail-closed behavior. Kill criterion: any frame
ambiguity, nonuniform accepted coefficient, field-domain alias, missing state
update, or claim of protocol control coverage without a real consumer blocks
promotion of the candidate. No performance benchmark is part of this study.

## Reproduce

```sh
uv run --locked --script research/transcript/check_transcript.py
```

The adjacent lock pins blake3-py 1.0.11 and distribution hashes. Python implements
the byte framing and sampling independently of future Stele Rust code. The
[Python package](https://pypi.org/project/blake3/1.0.11/) uses the official Rust
BLAKE3 backend: this is **not an independent cryptographic hash implementation**.
The script checks the empty-input BLAKE3 known answer, then the committed candidate
vectors. `--write-candidate` creates a new vector file exclusively; it cannot
replace the existing record. Nothing under research is imported by core crates.

## Checked claims and limits

- Fixed-width lengths make the frame parse uniquely. The script round-trips
  registered labels, operation tags and empty/binary payloads, rejecting trailing
  bytes. Domain tags distinguish absorb, challenge request and state update.
- Each accepted M31 candidate has two u32 preimages after masking; only
  0x7fffffff and 0xffffffff reject. Reduced-width exhaustive counts corroborate
  the argument. Forced vectors cover both rejected words, zero, p-1, high-bit
  aliases, success at the last available word, and exhaustion.
- Rejection positions are independent of accepted values in the ideal model.
  Thus a fixed attempt cap preserves the conditional uniform distribution over
  p^d outcomes. The cap's abort probability is bounded in A1; abort never accepts
  a false proof. This argument does not prove that BLAKE3 is a random oracle.
- QM31/OM31 degree bytes separate requests; successful requests update state
  before returning. Fixed vectors detect a repeated-state implementation, early
  challenge, omitted final message and one changed message byte. These are
  deterministic sensitivity checks, **not NC-0800/0802 verifier rejection tests**.
- One duplicate registered label is rejected with DuplicateLabel. A registry
  validator operates on configuration, not a proof witness. Its eventual catalog
  entry must identify that boundary and must not use a toy proof verifier.

The initial state is H of a short domain string, which is shorter than any frame.
Consequently all normal chain states are hash outputs on domain-distinguishable
inputs; the initial state cannot silently serve as an unhashed reset sentinel.
No keying, implicit UTF-8 conversion, modulo reduction of rejected words, or
caller-supplied state is part of the candidate core contract.

## Recommendation

Amend RFC-0012 through Workflow 02. Split primitive delivery into E2-00 and retain
all E2-01 acceptance criteria after E3-01 supplies a real schedule consumer. No
negative-control catalog status changes with this study. Wire actual primitive
and label-accounting checks before replacing the hash scaffold guards.

Q12 remains open: neither KATs nor the sampling lemma instantiate the full
Fiat-Shamir theorem. In particular, Q=2^100 gives the current H formula 2^-56,
which cannot meet 2^-128. A profile must not be certified using that illustration.
The final proof/accounting tasks must resolve query conventions and admissible
budgets, including failed attempts and grinding, and reject invalid profiles.
