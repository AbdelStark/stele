"""Explicit E5-04 diagnostic configuration; never an overflow fallback.

Keep original embedding, norm-output, Q/K/V, attention, activation and logit
precision. Change only residual and residual-projection units, then the matching
norm-input descriptors. Shapes, source roles, weights and physical formats stay.
This does not calibrate fidelity or establish a new four-artifact cqis_id.
"""
from dataclasses import replace


def residual_units(original, fraction):
    assert type(fraction) is int and 0 <= fraction <= 30
    blocks = []
    for i, b in enumerate(original.blocks):
        fractions = list(b.fractions)
        fractions[3] = fractions[-1] = fraction
        blocks.append(replace(b, fractions=tuple(fractions), mid=fraction, out=fraction,
            norm1=replace(b.norm1, F=original.f0 if i == 0 else fraction),
            norm2=replace(b.norm2, F=fraction)))
    return replace(original, blocks=tuple(blocks), final_norm=replace(original.final_norm, F=fraction))
