# Q26: attention value units and output normalization

Question: how do quantised value rows, their scales and block shifts determine
one exact attention output, with the same result in a full causal pass and a
cached prefix? This is research for RFC-0004 A3 / RFC-0009, not admitted behavior.

Security properties: source/scale association, signed rounding, positive divisor,
canonical masks and block units. Cost terms: c_x/c_a, row accumulation, scale
reads and retained row state. Kill criteria: an exact-oracle mismatch, ignored
value scale, lost block shift, inconsistent cached-prefix result or dynamic
runtime data used as a static field certificate.

The study will retain explicit exact/block modes, fixed absolute block boundaries
and checked configured units. It will exercise actual exponential functions and
the existing candidate value conversion. Full QK/RoPE scale semantics, native
forward parity, proof consumers, private PCS and fidelity remain separate work.
