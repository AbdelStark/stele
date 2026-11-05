# Complete Llama RoPE reference evidence

These files preserve the completed independent/native Registry qualification at
commit `3a571eb9391a78b503731e26a6d8eccce6787d5b`. The exact receipt SHA-256 is
`ba79c35caccee80272ea99b7c7d8f224ace2d317884cabf9a352cfc2b215fb42`.
Every file named in its artifact manifest is included unchanged. They contain
numerical definitions, Registry frames and identities, not checkpoint weights.

The run generated all 8388608 RoPE coefficient pairs for width 128 and context
131072, with the original Llama-3.1 definition: split layout, theta 500000,
factor 8, low/high frequency factors 1/4 and original context 8192. The complete
native Registry frame matched the independent reference frame byte for byte.
The receipt pins both implementations and their output files.

The original-source checker `tests/support/qualify_original_llama.py` accepts
this directory through `--rotation-reference`. It validates the exact receipt,
the full reference files, the unchanged research source pins and the complete
typed rotation definition before extracting its independent data digest. It
does not reuse this historical Model or Registry for original-source preparation.
All other reference function data is freshly generated, and the native adapter
still regenerates every RoPE coefficient in each original-source run.

This evidence qualifies the complete numerical rotation data only. Full original
source conversion, stored Artifact validation and complete current Model, Scales,
Registry, Bounds and numerical identity comparison remain separate checks.
It grants no inference, fidelity, proof, privacy or profile completion.
