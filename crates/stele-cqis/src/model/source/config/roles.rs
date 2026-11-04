//! RFC-0025 source architecture §3: exact physical-role names, transforms and parts.
use super::{Architecture, Error};
use crate::model::{Model, Physical, Role, SourceMap};
use core::fmt::Write;

pub(super) fn check(a: &Architecture, model: &Model, map: &SourceMap<'_>) -> Result<(), Error> {
    if a.shape != model.shape() || a.shape != map.shape() {
        return Err(Error::Shape);
    }
    for norm in core::iter::once(model.final_norm()).chain(
        model
            .blocks()
            .iter()
            .flat_map(|b| [b.first_norm(), b.second_norm()]),
    ) {
        // Model already checks the norm kind. Encoding §4 puts epsilon after
        // HBBBB for LayerNorm, HBBB for RMSNorm; both are complete u32 pairs.
        let p = norm.function().parameters();
        let at = if a.layout == 2 { 5 } else { 6 };
        let n = u32::from_le_bytes(p[at..at + 4].try_into().map_err(|_| Error::Norm)?);
        let d = u32::from_le_bytes(p[at + 4..at + 8].try_into().map_err(|_| Error::Norm)?);
        if (n, d) != a.epsilon {
            return Err(Error::SourceEpsilon);
        }
    }
    if model
        .blocks()
        .iter()
        .any(|b| b.rotation().copied() != a.rotation)
    {
        return Err(Error::Rotation);
    }
    for (i, entry) in map.entries().iter().enumerate() {
        let physical = a.shape.physical(i as u16).ok_or(Error::SourceRole)?;
        let (name, transform, part) = role(a.layout, physical)?;
        if entry.name().as_bytes() != name.as_bytes()
            || entry.transform() != transform
            || entry.part() != part
        {
            return Err(Error::SourceRole);
        }
        // The checked Map already derives complete raw dimensions from this exact
        // shape, physical role and transform. Package checked the actual raw dtype.
    }
    if map
        .alias_name()
        .is_some_and(|s| a.layout == 2 || s != "lm_head.weight")
    {
        return Err(Error::SourceAlias);
    }
    for name in map.ignored() {
        let prefix = if a.layout == 2 {
            "model.layers."
        } else if a.layout == 1 {
            "transformer.h."
        } else {
            "h."
        };
        let (index, suffix) = name
            .strip_prefix(prefix)
            .and_then(|s| s.split_once('.'))
            .ok_or(Error::SourceIgnored)?;
        if index.is_empty()
            || (index.len() > 1 && index.starts_with('0'))
            || !index.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::SourceIgnored);
        }
        let layer = index.parse::<u16>().map_err(|_| Error::SourceIgnored)?;
        if layer >= a.shape.layers()
            || if a.layout == 2 {
                suffix != "self_attn.rotary_emb.inv_freq"
            } else {
                !matches!(suffix, "attn.bias" | "attn.masked_bias")
            }
        {
            return Err(Error::SourceIgnored);
        }
    }
    Ok(())
}
fn role(layout: u8, physical: Physical) -> Result<(Name, u8, Option<u8>), Error> {
    use Role::*;
    let mut name = Name {
        bytes: [0; 96],
        len: 0,
    };
    let (mut transform, mut part) = (0, None);
    if layout == 2 {
        if let Some(layer) = physical.layer() {
            write!(&mut name, "model.layers.{layer}.").map_err(|_| Error::SourceRole)?;
        }
        name.write_str(match physical.role() {
            Token => "model.embed_tokens.weight",
            FinalGain => "model.norm.weight",
            Head => "lm_head.weight",
            FirstGain => "input_layernorm.weight",
            SecondGain => "post_attention_layernorm.weight",
            Query => "self_attn.q_proj.weight",
            Key => "self_attn.k_proj.weight",
            Value => "self_attn.v_proj.weight",
            Output => "self_attn.o_proj.weight",
            Up => "mlp.up_proj.weight",
            Gate => "mlp.gate_proj.weight",
            Down => "mlp.down_proj.weight",
            _ => return Err(Error::SourceRole),
        })
        .map_err(|_| Error::SourceRole)?;
    } else {
        if layout == 1 {
            name.write_str("transformer.")
                .map_err(|_| Error::SourceRole)?;
        }
        if let Some(layer) = physical.layer() {
            write!(&mut name, "h.{layer}.").map_err(|_| Error::SourceRole)?;
        }
        let suffix = match physical.role() {
            Token => "wte.weight",
            Position => "wpe.weight",
            FinalGain => "ln_f.weight",
            FinalBias => "ln_f.bias",
            FirstGain => "ln_1.weight",
            FirstBias => "ln_1.bias",
            SecondGain => "ln_2.weight",
            SecondBias => "ln_2.bias",
            Query | Key | Value | QueryBias | KeyBias | ValueBias => {
                let bias = matches!(physical.role(), QueryBias | KeyBias | ValueBias);
                transform = if bias { 3 } else { 2 };
                part = Some(match physical.role() {
                    Query | QueryBias => 0,
                    Key | KeyBias => 1,
                    _ => 2,
                });
                if bias {
                    "attn.c_attn.bias"
                } else {
                    "attn.c_attn.weight"
                }
            }
            Output => {
                transform = 1;
                "attn.c_proj.weight"
            }
            OutputBias => "attn.c_proj.bias",
            Up => {
                transform = 1;
                "mlp.c_fc.weight"
            }
            UpBias => "mlp.c_fc.bias",
            Down => {
                transform = 1;
                "mlp.c_proj.weight"
            }
            DownBias => "mlp.c_proj.bias",
            _ => return Err(Error::SourceRole),
        };
        name.write_str(suffix).map_err(|_| Error::SourceRole)?;
    }
    Ok((name, transform, part))
}
// Closed names and layer<=127 fit 96 ASCII bytes without heap allocation.
struct Name {
    bytes: [u8; 96],
    len: usize,
}
impl Name {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl Write for Name {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(core::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
