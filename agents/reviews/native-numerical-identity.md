# Native numerical identity and preparation composition — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 encoding §6
and the execution appendix's original-source preparation section. NumericalIdentity
constructs the exact 152-byte preimage from complete immutable Model, Scales,
Registry and Bounds. It checks each child's Model identity and Bounds' Scales and
Registry identities before copying the four hashes in canonical order. Registry
constructors require complete native regeneration; Bounds constructors require
every statically derived record. No raw bytes or supplied hash tuple can construct
either child or this identity. Reusing those completed owned objects preserves
their validation without repeating generation. Verification compares the whole
independently expected frame, including the prefix and exact length.

The identity test reuses the existing independently qualified Bounds fixtures:
both model families, with greedy and sampled decoding. It compares all 152 bytes,
mutates each byte, tests every truncation and a suffix, and mixes completed children.
Changing a nonmaximum channel mantissa rejects against the old Bounds. Rebuilding
Bounds still changes the numerical identity, even though that matrix's maximum
mantissa is unchanged. A changed Model logits fraction rejects with old children;
rebuilding all its children still rejects against the original expected identity.

Six new small-model fixtures exercise the public native APIs together, starting
with complete original files and ending with source-derived Scales, actual stored
Artifact validation, a fully regenerated Registry, complete Bounds and cqis_id.
They cover all three explicit adapters, all four selected IEEE types, and single
and indexed three-shard sources. SourceConfig, conversion and stored validation
receive the same Model, Preparation/Map and Assets. Source reads and stored reads
deliberately return short chunks. Every output byte, SourceConfig frame and Scales
frame is compared with the independent fixture; all static records contribute to
the expected Bounds hash and length. The final identity retains all four hashes.

The generator calls qualified pure helpers, never historical campaign entry
points. These new synthetic fixtures choose equal activation input/output units:
the independent Registry oracle's fixed 256-bit intervals cannot resolve some
unequal-unit GELU tail half ties. This is a stated fixture constraint, not a change
to Model's domain or any original named configuration. The six fixtures establish
API composition; they do not implement inference or qualify original checkpoints.

The integration controls change one stored int16 vector byte after the sink has
acknowledged emission: complete stored validation rejects under the fixed emitted
digest. A changed original epsilon fails its original Assets hash; updating that
hash still fails SourceConfig's Model epsilon join before any output is written.
These are native numerical controls, not production NC completion or passport
admission. The integration test introduces no new preparation authority handle.

## Workflow 03

1. NumericalIdentity::new, as_bytes, identity and verify implement encoding §6's
   four-artifact join, exact preimage, cqis_id and full-frame comparison.
2. No challenge, transcript label or absorb order changes.
3. No proof claim is emitted. Expected source/passport authority, commitments,
   actual consuming reductions and proof admission remain separate requirements.
4. The identity and preparation_pipeline controls above catch changed children,
   config and stored bytes. NC-0120/0121 and the other assigned production controls
   retain their owning-consumer requirements and are not marked complete.
5. No new randomness or security-budget term. Existing complete artifact hashing
   obligations remain; no supplied digest authenticates its own expected value.
6. All Bounds come from the existing full static derivation. No runtime maxima
   or new arithmetic schema is introduced.
7. The existing complete Artifact validator checks all code/padding bytes. This
   identity adds no lookup selector, mask or intermediate tensor commitment.
8. The four hashes have fixed order and a fixed domain prefix. The constructor
   allocates no heap memory and uses no floats, hash-map order or timing input.
9. Small native fixture bytes match independent expectations. Original named
   sources, inference/fidelity and CPU/GPU proof parity remain required.
10. This is an offline T_misc join of a fixed 152-byte frame. No online weight pass
    or measured cost constant changes; no benchmark or throughput claim is made.
11. The crate stays no_std and forbids unsafe. The constructor's fixed slices and
    32-byte slots cannot depend on untrusted lengths; verification accepts a slice.
12. Model, Scales, Registry, Bounds, numerical identity and cqis_id retain their
    specified meanings. A numerical identity is not a complete passport.

I tried to break it by changing a nonmaximum scale, rebuilding a changed Model's
children, changing a config with fresh file hashes, and altering stored output;
the controls rejected them under their original expected inputs. This same-author
review does not approve the unfinished E5-03 task PR.

Validation: both targeted tests pass, covering four complete identity cases and
six complete preparation chains. All-target Clippy, no-default-features check,
31 documentation tests, formatting, 529 Accepted RFC references, Rust policy
and 755 local documentation links pass. All 58 qualified Python files and seven
legacy helper files retain their pinned bytes. Full-task native gates, original
named-source qualification and assigned production controls remain due.
