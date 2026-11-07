"""Explicit E5-04 diagnostic configuration; never an overflow fallback.

Keep original embedding, norm-output, Q/K/V, attention, activation and logit
precision. Change only residual and residual-projection units, then the matching
norm-input descriptors. Shapes, source roles, weights and physical formats stay.
This does not calibrate fidelity or establish a new four-artifact cqis_id.
"""
from dataclasses import replace


def residual_units(original, fraction, version=1):
    """version=2 also selects RFC-0004 A14's int24 residual (rmsnorm_q version 2, Llama only)."""
    assert type(fraction) is int and 0 <= fraction <= 30 and version in (1, 2)
    norm = (lambda n, **k: replace(n, **k)) if version == 1 else (lambda n, **k: replace(n, version=2, **k))
    blocks = []
    for i, b in enumerate(original.blocks):
        fractions = list(b.fractions)
        fractions[3] = fractions[-1] = fraction
        blocks.append(replace(b, fractions=tuple(fractions), mid=fraction, out=fraction,
            norm1=norm(b.norm1, F=original.f0 if i == 0 else fraction),
            norm2=norm(b.norm2, F=fraction)))
    return replace(original, blocks=tuple(blocks), final_norm=norm(original.final_norm, F=fraction))
