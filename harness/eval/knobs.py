"""E5-05b configuration knobs: explicit Model fraction changes, never overflow fallbacks.

Each knob replaces Model fields that the encoding appendix (RFC-0025 §4) lets a
configuration choose, keeping every join the Model codec checks:
- attention: the assembled attention row fraction (O's source fraction).
- qk: Q and K projection fractions. score_e is unchanged: the score shift
  score_e - fQ - fK + exp.F already absorbs the fractions (RFC-0025 attend).
- v: the V projection fraction (attention alignment derives from it).
- act: (F, E) of the SiLU table; F is the gate fraction, so the down input becomes
  up + E. The table must still fit int16 over every int16 input (RFC-0021 §2.2).
- norm_e: every norm's output units E (the converted row fraction follows).
- group: one dynamic scale per `group` features (RFC-0004 A15) on every dynamic
  affine-input row: both norm outputs, the attention row, the FFN row and the final row.
The result is validated by encoding it; the Registry/Bounds derive from it.
"""
from dataclasses import replace

import model_codec


def configure(model, attention=None, qk=None, v=None, act=None, norm_e=None, group=None):
    blocks = []
    for b in model.blocks:
        f = list(b.fractions)
        changes = {}
        if attention is not None:
            changes['attention'] = attention
        if qk is not None:
            f[0] = f[1] = qk
        if v is not None:
            f[2] = v
        if act is not None:
            F, E = act
            f[5] = F
            changes['activation'] = replace(b.activation, F=F, E=E)
        if norm_e is not None:
            changes['norm1'] = replace(b.norm1, E=norm_e)
            changes['norm2'] = replace(b.norm2, E=norm_e)
        if group is not None:
            changes['policies'] = tuple((2, group) if j in (0, 4, 5, 6) and p == (0, 0) else p for j, p in enumerate(b.policies))
        blocks.append(replace(b, fractions=tuple(f), **changes))
    out = replace(model, blocks=tuple(blocks))
    if group is not None and out.final_policy == (0, 0):
        out = replace(out, final_policy=(2, group))
    if norm_e is not None:
        out = replace(out, final_norm=replace(out.final_norm, E=norm_e))
    model_codec.encode(out)  # rejects any broken join
    return out
