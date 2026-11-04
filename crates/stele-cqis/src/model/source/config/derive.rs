//! RFC-0025 source architecture §§1–2: closed adapter fields and absence rules.
use super::{
    json::{Object, Value},
    Architecture, Budget, Error,
};
use crate::model::{codec::Writer, Rotation, Shape};

pub(super) fn derive(layout: u8, d: &Object, budget: &mut Budget) -> Result<Architecture, Error> {
    let llama = layout == 2;
    fields(d, llama)?;
    if d.required("model_type")?.string() != Some(if llama { "llama" } else { "gpt2" }) {
        return Err(Error::SourceFamily);
    }
    let class = if llama {
        "LlamaForCausalLM"
    } else {
        "GPT2LMHeadModel"
    };
    if !matches!(d.required("architectures")?, Value::Array(v) if v.len()==1 && v[0].string()==Some(class))
    {
        return Err(Error::SourceFamily);
    }
    if d.required(if llama {
        "hidden_act"
    } else {
        "activation_function"
    })?
    .string()
        != Some(if llama { "silu" } else { "gelu_new" })
    {
        return Err(Error::Activation);
    }
    let names: &[&str] = if llama {
        &[
            "num_hidden_layers",
            "hidden_size",
            "num_attention_heads",
            "max_position_embeddings",
            "vocab_size",
        ]
    } else {
        &["n_layer", "n_embd", "n_head", "n_positions", "vocab_size"]
    };
    let mut dimensions = [0; 5];
    for (out, name) in dimensions.iter_mut().zip(names) {
        *out = dimension(d.required(name)?)?;
    }
    let [layers, width, heads, context, vocabulary] = dimensions;
    if !width.is_multiple_of(heads) {
        return Err(Error::Shape);
    }
    let hidden = if llama {
        dimension(d.required("intermediate_size")?)?
    } else {
        4 * width
    };
    let groups = if llama {
        match d.get("num_key_value_heads").filter(|v| !v.null()) {
            Some(v) => dimension(v)?,
            None => heads,
        }
    } else {
        heads
    };
    let head_width = width / heads;
    if llama {
        optional_dimension(d, "head_dim", head_width, false)?;
    } else {
        optional_dimension(d, "n_ctx", context, false)?;
        optional_dimension(d, "n_inner", hidden, true)?;
    }
    let mut raw = [0; 21];
    raw[0] = u8::from(llama);
    for (i, v) in [layers, width, heads, groups, head_width, hidden]
        .iter()
        .enumerate()
    {
        raw[1 + 2 * i..3 + 2 * i]
            .copy_from_slice(&u16::try_from(*v).map_err(|_| Error::Shape)?.to_le_bytes());
    }
    raw[13..17].copy_from_slice(&(vocabulary as u32).to_le_bytes());
    raw[17..21].copy_from_slice(&(context as u32).to_le_bytes());
    let shape = Shape::decode(&raw)?;
    let (n, dn) = d
        .required(if llama {
            "rms_norm_eps"
        } else {
            "layer_norm_epsilon"
        })?
        .ratio(u64::from(u32::MAX))?;
    let rotation = if llama {
        Some(rotation(d, shape, budget)?)
    } else {
        None
    };
    let bos = token(d.required("bos_token_id")?, shape)?;
    let pad = d
        .get("pad_token_id")
        .filter(|v| !v.null())
        .map(|v| token(v, shape))
        .transpose()?;
    let eos = d.required("eos_token_id")?;
    let values = match eos {
        Value::Array(v) => v.as_slice(),
        _ => core::slice::from_ref(eos),
    };
    if values.is_empty() {
        return Err(Error::SourceToken);
    }
    let mut eos = budget.vector(values.len())?;
    for v in values {
        eos.push(token(v, shape)?);
    }
    eos.sort_unstable();
    if eos.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::SourceToken);
    }
    Ok(Architecture {
        layout,
        shape,
        epsilon: (n as u32, dn as u32),
        rotation,
        bos,
        pad,
        eos,
    })
}
fn dimension(v: &Value) -> Result<u64, Error> {
    v.unsigned()
        .filter(|v| (1..=1 << 20).contains(v))
        .ok_or(Error::Shape)
}
fn optional_dimension(d: &Object, name: &str, expected: u64, nullable: bool) -> Result<(), Error> {
    if let Some(v) = d.get(name).filter(|v| !nullable || !v.null()) {
        if v.unsigned() != Some(expected) {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
fn token(v: &Value, shape: Shape) -> Result<u32, Error> {
    v.unsigned()
        .filter(|v| *v < u64::from(shape.vocabulary()))
        .map(|v| v as u32)
        .ok_or(Error::SourceToken)
}
fn fields(d: &Object, llama: bool) -> Result<(), Error> {
    for (name, value) in d.fields() {
        let flag = match name {
            "tie_word_embeddings" => Some(!llama),
            "add_cross_attention" | "is_encoder_decoder" => Some(false),
            "attention_bias" | "mlp_bias" if llama => Some(false),
            "scale_attn_weights" if !llama => Some(true),
            "scale_attn_by_inverse_layer_idx" | "reorder_and_upcast_attn" if !llama => Some(false),
            _ => None,
        };
        if let Some(expected) = flag {
            if !matches!(value,Value::Boolean(v) if *v==expected) {
                return Err(Error::SourceFlags);
            }
            continue;
        }
        match name {
            "pretraining_tp" if llama => {
                if value.unsigned() != Some(1) {
                    return Err(Error::SourceFlags);
                }
            }
            "_name_or_path" | "_commit_hash" | "transformers_version" | "torch_dtype" => {
                string_metadata(value)?
            }
            "summary_type" | "summary_activation" if !llama => string_metadata(value)?,
            "return_dict" | "output_attentions" | "output_hidden_states" | "use_cache" => {
                boolean_metadata(value)?
            }
            "summary_use_proj" | "summary_proj_to_labels" if !llama => boolean_metadata(value)?,
            "initializer_range" => {
                if !matches!(value,Value::Number(n) if n.nonnegative()) {
                    return Err(Error::SourceMetadata);
                }
            }
            "task_specific_params" => {
                if !matches!(value, Value::Null | Value::Object(_)) {
                    return Err(Error::SourceMetadata);
                }
            }
            "resid_pdrop" | "embd_pdrop" | "attn_pdrop" | "summary_first_dropout" if !llama => {
                dropout(value)?
            }
            "attention_dropout" if llama => dropout(value)?,
            "architectures" | "model_type" | "bos_token_id" | "eos_token_id" | "pad_token_id"
            | "vocab_size" => (),
            "n_layer"
            | "n_embd"
            | "n_head"
            | "n_positions"
            | "n_ctx"
            | "n_inner"
            | "activation_function"
            | "layer_norm_epsilon"
                if !llama => {}
            "num_hidden_layers"
            | "hidden_size"
            | "num_attention_heads"
            | "num_key_value_heads"
            | "intermediate_size"
            | "max_position_embeddings"
            | "head_dim"
            | "hidden_act"
            | "rms_norm_eps"
            | "rope_theta"
            | "rope_scaling"
                if llama => {}
            _ => return Err(Error::SourceFields),
        }
    }
    Ok(())
}
fn string_metadata(v: &Value) -> Result<(), Error> {
    if v.null() || v.string().is_some() {
        Ok(())
    } else {
        Err(Error::SourceMetadata)
    }
}
fn boolean_metadata(v: &Value) -> Result<(), Error> {
    if matches!(v, Value::Boolean(_)) {
        Ok(())
    } else {
        Err(Error::SourceMetadata)
    }
}
fn dropout(v: &Value) -> Result<(), Error> {
    if matches!(v,Value::Number(n) if n.unit_interval()) {
        Ok(())
    } else {
        Err(Error::SourceMetadata)
    }
}
fn rotation(d: &Object, shape: Shape, budget: &mut Budget) -> Result<Rotation, Error> {
    let theta = d.required("rope_theta")?.ratio(u64::MAX)?;
    let (mut family, mut original, mut ratios) = (0, 0u32, [theta, (1, 1), (0, 1), (0, 1)]);
    if let Some(scaling) = d.get("rope_scaling").filter(|v| !v.null()) {
        let Value::Object(s) = scaling else {
            return Err(Error::Rotation);
        };
        let mode = s
            .get("rope_type")
            .or_else(|| s.get("type"))
            .and_then(Value::string)
            .ok_or(Error::Rotation)?;
        family = match mode {
            "linear" => 1,
            "llama3" => 2,
            _ => return Err(Error::Rotation),
        };
        if s.get("type").is_some_and(|v| v.string() != Some(mode)) {
            return Err(Error::Rotation);
        }
        for (key, _) in s.fields() {
            let allowed = matches!(key, "type" | "rope_type" | "factor")
                || (family == 2
                    && matches!(
                        key,
                        "low_freq_factor" | "high_freq_factor" | "original_max_position_embeddings"
                    ));
            if !allowed {
                return Err(Error::Rotation);
            }
        }
        ratios[1] = s.get("factor").ok_or(Error::Rotation)?.ratio(u64::MAX)?;
        if family == 2 {
            ratios[2] = s
                .get("low_freq_factor")
                .ok_or(Error::Rotation)?
                .ratio(u64::MAX)?;
            ratios[3] = s
                .get("high_freq_factor")
                .ok_or(Error::Rotation)?
                .ratio(u64::MAX)?;
            original = s
                .get("original_max_position_embeddings")
                .and_then(Value::unsigned)
                .filter(|v| (1..=1 << 20).contains(v))
                .ok_or(Error::Rotation)? as u32;
        }
    }
    budget.spend(128)?;
    let mut w = Writer::new(128)?;
    w.push(b"stele/v0.1/cqis/rotation")?;
    w.push(&shape.head_width().to_le_bytes())?;
    w.push(&shape.context().to_le_bytes())?;
    w.push(&[family, 1])?;
    w.push(&original.to_le_bytes())?;
    for (n, d) in ratios {
        w.push(&n.to_le_bytes())?;
        w.push(&d.to_le_bytes())?;
    }
    Rotation::decode(&w.finish())
}
