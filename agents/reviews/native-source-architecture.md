# Native source architecture and configuration — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source
architecture §§1–4. Architecture derives configuration metadata. SourceConfig
requires a completed SourcePackage, revalidates its original config bytes, and
joins every derived field and physical source role to the checked Model/Map.
Neither type establishes expected publisher/passport authority, source conversion,
tokenizer behavior, fidelity, a production control or proof admission.

The layout is explicit: bare GPT-2, prefixed GPT-2 or HF Llama with split-half
rotation. The parser preserves integer versus decimal token types, negative zero
semantics and exact reduced rational values. It rejects malformed UTF-8/JSON,
unpaired surrogates, duplicate decoded keys at every depth, unknown fields and
all out-of-domain values, including inside nonarchitectural annotations.
The original-byte, node/key, depth and decoded-string limits are independent.

Decimal parsing uses the existing bounded Natural implementation with a separate
local proof: at most 64 token characters and exponent magnitude 64 keep every
unreduced operand below 512 bits. Euclidean reduction precedes the 256-bit result
check. Retained numerators and denominators occupy fixed inline words. Every
Natural allocation, including discarded results, is conservatively charged before
the operation; tree vectors, decoded strings, EOS storage and output frames are
also charged before fallible allocation. Freed temporary allocations do not
restore the allowance. Allocator rounding/bookkeeping and the bounded snapshot
read buffer remain separate from this requested-allocation budget.

Architecture retains the full shape/context, exact epsilon and rotation, BOS,
optional pad and complete sorted distinct EOS. Closed absence rules do not choose
CQIS fractions, quantization, table representations, decoding or runtime behavior.
Unknown source architecture and remote-code selectors reject.

SourceConfig reads the config only through the package's authenticated asset
view. Package construction has already checked the exact joint file set and all
original checkpoint/index/config/tokenizer/generation files. Config replay checks
the same bytes again; subsequent tensor/tokenizer consumers must use their own
revalidated views. No hash callback or supplied parsed Architecture can substitute
for these checks.

The join checks Model and Map shape, every first/second/final norm epsilon,
every block rotation, every physical source name/transform/part, the sole optional
GPT-2 head alias, and the closed in-range ignored-buffer names. Checked Map
validation already derives full raw dimensions from those exact roles and
transforms; the package already compares actual raw dtype/dimensions/length.
Expected role names use bounded stack storage. The binding retains complete
Model/Map/Assets hashes and the full derived Architecture frame. Verification
compares the entire independently expected frame, including counts and suffixes.

Fixtures use pinned pure Python helpers and a separate canonical framing oracle;
no historical campaign entry point runs. They include the original public GPT-2
config, explicitly synthetic full Llama/max geometries, exact decimal boundaries,
all JSON resource boundaries, complete small source packages for all three
layouts, and a complete 50000-EOS binding. These do not qualify named original
checkpoint conversion or inference. Single-value controls cover all physical
source names, a Map-valid square-projection transform, every norm position,
rotation layout, model shape, alias/ignored names, expected-frame bytes and
replayed original config mutation.

## Workflow 03

1. Architecture and its metadata accessors implement source architecture §§1–2
   and §4 framing. SourceConfig implements §§3–4 through the complete source
   package and original-byte views from source §§1–4.
2. No challenges, transcript labels or absorb-order changes occur.
3. No proof claim is emitted. The next consumer is exact original-source
   conversion; expected passport authority and proof consumers remain required.
4. Native source_architecture cases reject the one-value changes listed above.
   Assigned NC-0118/0119/0120/0121 and other E5-03 production registrations remain
   required at their actual consuming boundaries; unit fixtures are not NC credit.
5. Existing accounting inventory covers complete SourceConfig BLAKE3 and config
   snapshot replay SHA-256. No hash-loss formula/profile budget changes. Full task
   accounting/native gates remain due before the completed task PR.
6. No arithmetic certificate instance or bound changes. All dimensions remain
   static; full context capacity never shrinks to a request extent.
7. No inference masks or lookup selectors change. Ignored buffers cannot choose
   masks or rotary coefficients; the exact allowed names remain checked.
8. Parsing and role joins use deterministic ordered vectors. EOS normalization
   sorts exact integer IDs. No host floating-point conversion occurs.
9. Complete canonical architecture/binding bytes are compared with independent
   fixtures. GPU/proof parity and original named-model execution are not claimed.
10. Work remains preparation T_misc, with no online weight pass, new cut or
    measured performance constant.
11. The crate remains no_std and forbids unsafe code. All config lengths and
    allocation admissions are bounded; the JSON recursion depth is at most 32.
12. Source, Assets, Architecture, SourceConfig, Model, Map and physical roles retain
    their specified meanings. Metadata derivation is not source authority.

I tried to break it by changing a raw source name, a norm epsilon and a rotation
layout while preserving valid surrounding Model/Map/package encodings, and the
controls rejected them with SourceRole, SourceEpsilon and Rotation respectively.
This same-author review does not approve the unfinished E5-03 task PR.

Validation: 174 architecture cases (67 accepted), 114 complete package-binding
cases (16 accepted), and 139 exact-number cases (128 accepted). Full canonical
bytes and all eight numerator/denominator words match the independent fixtures.
The source container, index and package regressions pass, as do all-target Clippy,
no-default-features checking, 29 documentation tests, formatting, RFC references,
Rust policy and local documentation links. All 58 qualified Python source pins
and seven legacy helper hashes remain unchanged.
