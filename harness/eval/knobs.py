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
The result is validated by encoding it; the Registry/Bounds derive from it.
"""
from dataclasses import replace

import model_codec


def configure(model, attention=None, qk=None, v=None, act=None, norm_e=None):
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
        blocks.append(replace(b, fractions=tuple(f), **changes))
    out = replace(model, blocks=tuple(blocks))
    if norm_e is not None:
        out = replace(out, final_norm=replace(out.final_norm, E=norm_e))
    model_codec.encode(out)  # rejects any broken join
    return out
