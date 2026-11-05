//! RFC-0025 collection §§2–3: every prescribed record in canonical slot order.
use super::parameters::{attention_policy, exponential, norm, norm_fraction, row, Context};
use crate::{
    bounds::arithmetic::*,
    model::{Error, Role},
};

pub(super) fn records(
    c: &Context<'_>,
    mut emit: impl FnMut(Record) -> Result<(), Error>,
) -> Result<(), Error> {
    let m = c.model;
    let s = m.shape();
    let llama = s.family() == 1;
    for (ordinal, format) in m.formats().iter().enumerate() {
        emit(Record::physical(
            s,
            u16::try_from(ordinal).map_err(|_| Error::Capacity)?,
            format.bits(),
            format.parameter(),
        )?)?;
    }
    emit(Record::embedding(Embedding {
        vocabulary: s.vocabulary(),
        context: s.context(),
        output_fraction: m.initial_fraction(),
        token: c.weight(c.physical(Role::Token, None)?)?,
        position: if llama {
            None
        } else {
            Some(c.weight(c.physical(Role::Position, None)?)?)
        },
    })?)?;
    let shape = AttentionShape {
        heads: s.heads(),
        groups: s.groups(),
        width: s.head_width(),
        context: s.context(),
    };
    let kv_width = s.groups().checked_mul(s.head_width()).ok_or(Error::Shape)?;
    let mut incoming = m.initial_fraction();
    for (layer, b) in m.blocks().iter().enumerate() {
        let layer = Some(u16::try_from(layer).map_err(|_| Error::Capacity)?);
        let p = b.policies();
        let f = b.projection_fractions();
        let exp = exponential(b.exponential(), s.context())?;
        emit(norm(b.first_norm())?)?;
        let first = row(s.width(), 0, norm_fraction(b.first_norm())?, p[0]);
        emit(Record::row(first)?)?;
        for (j, role) in [Role::Query, Role::Key, Role::Value]
            .into_iter()
            .enumerate()
        {
            emit(c.project(role, layer, first, f[j])?)?;
        }
        if llama {
            let rotation = b.rotation().ok_or(Error::Rotation)?;
            for (j, heads) in [s.heads(), s.groups()].into_iter().enumerate() {
                emit(Record::rotary(Rotary {
                    heads,
                    width: s.head_width(),
                    rotary_width: rotation.width(),
                    context: s.context(),
                    layout: rotation.layout(),
                    fraction: f[j],
                })?)?;
            }
        }
        for (j, width) in [s.width(), kv_width, kv_width].into_iter().enumerate() {
            emit(Record::row(row(width, 0, f[j], p[j + 1]))?)?;
        }
        let (multiplier, exponent) = b.score_multiplier();
        let (score, score_bound) = Record::score(Score {
            shape,
            query_fraction: f[0],
            key_fraction: f[1],
            exp_fraction: exp.source_fraction,
            query_policy: attention_policy(p[1])?,
            key_policy: attention_policy(p[2])?,
            multiplier,
            exponent,
        })?;
        emit(score)?;
        emit(Record::maximum(Maximum {
            context: s.context(),
            score_bound,
            domain_bits: exp.domain_bits,
            fraction: exp.source_fraction,
        })?)?;
        emit(Record::exponential(exp)?)?;
        let weighted = Weighted {
            shape,
            value_fraction: f[2],
            exp_fraction: exp.output_fraction,
            policy: attention_policy(p[3])?,
            mode: b.accumulation(),
            drop: b.drop(),
        };
        emit(Record::weighted(weighted)?)?;
        emit(Record::normalize(Normalize {
            source: weighted,
            output_fraction: b.attention_fraction(),
        })?)?;
        let attention = row(s.width(), 0, b.attention_fraction(), p[4]);
        emit(Record::row(attention)?)?;
        emit(c.project(Role::Output, layer, attention, f[3])?)?;
        emit(Record::residual(Residual {
            dimension: s.width(),
            input_fractions: [incoming, f[3]],
            output_fraction: b.mid_fraction(),
        })?)?;
        emit(norm(b.second_norm())?)?;
        let second = row(s.width(), 0, norm_fraction(b.second_norm())?, p[5]);
        emit(Record::row(second)?)?;
        emit(c.project(Role::Up, layer, second, f[4])?)?;
        if llama {
            emit(c.project(Role::Gate, layer, second, f[5])?)?;
        }
        let function = b.activation().function();
        let kind = match function.name() {
            "silu_q" => 1,
            "gelu_tanh_q" => 4,
            _ => return Err(Error::Activation),
        };
        let [source_fraction, output_fraction] = function.parameters() else {
            return Err(Error::Activation);
        };
        emit(Record::activation(Activation {
            dimension: s.hidden(),
            kind,
            source_fraction: *source_fraction,
            output_fraction: *output_fraction,
            cap_m: 0,
            cap_f: 0,
        })?)?;
        if llama {
            emit(Record::gated(Gated {
                dimension: s.hidden(),
                up_fraction: f[4],
                activation_fraction: *output_fraction,
            })?)?;
        }
        let fraction = output_fraction
            .checked_add(if llama { f[4] } else { 0 })
            .ok_or(Error::Units)?;
        let ffn = row(s.hidden(), s.family(), fraction, p[6]);
        emit(Record::row(ffn)?)?;
        let down_fraction = *f.last().ok_or(Error::Units)?;
        emit(c.project(Role::Down, layer, ffn, down_fraction)?)?;
        emit(Record::residual(Residual {
            dimension: s.width(),
            input_fractions: [b.mid_fraction(), down_fraction],
            output_fraction: b.output_fraction(),
        })?)?;
        incoming = b.output_fraction();
    }
    emit(norm(m.final_norm())?)?;
    let final_row = row(
        s.width(),
        0,
        norm_fraction(m.final_norm())?,
        m.final_policy(),
    );
    emit(Record::row(final_row)?)?;
    emit(c.project(
        if llama { Role::Head } else { Role::Token },
        None,
        final_row,
        m.logits_fraction(),
    )?)?;
    emit(Record::logits(Logits {
        vocabulary: s.vocabulary(),
        fraction: m.logits_fraction(),
    })?)?;
    if let Some(sampling) = m.decoding().sampling() {
        let exp = exponential(sampling.exponential(), s.vocabulary())?;
        emit(Record::temperature(Temperature {
            logits_fraction: m.logits_fraction(),
            temperature: sampling.temperature(),
            exp,
        })?)?;
        emit(Record::exponential(exp)?)?;
        emit(Record::sampling(Sampling {
            vocabulary: s.vocabulary(),
            exp_fraction: exp.output_fraction,
            top_p: sampling.top_p(),
        })?)?;
    }
    emit(Record::request(Request {
        vocabulary: s.vocabulary(),
        context: s.context(),
        mode: u8::from(m.decoding().sampling().is_some()),
    })?)
}
