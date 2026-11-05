//! RFC-0025 collection §§2–3: closed physical, function and policy parameter joins.
use crate::{
    bounds::arithmetic::{Affine, Exponential, Record, Row, Weight},
    functions::Representation,
    model::{Error, Model, Physical, Policy, Role, Scales},
};

pub(super) struct Context<'a> {
    pub model: &'a Model,
    pub scales: &'a Scales,
}
impl Context<'_> {
    pub fn physical(&self, role: Role, layer: Option<u16>) -> Result<Physical, Error> {
        let shape = self.model.shape();
        let (prefix, block) = if shape.family() == 0 { (2, 16) } else { (1, 9) };
        let range = match layer {
            Some(l) if l < shape.layers() => prefix + block * l..prefix + block * (l + 1),
            Some(_) => return Err(Error::Physical),
            None => 0..shape.record_count(),
        };
        range
            .filter_map(|i| shape.physical(i))
            .find(|p| p.role() == role && p.layer() == layer)
            .ok_or(Error::Physical)
    }

    pub fn weight(&self, physical: Physical) -> Result<Weight, Error> {
        let ordinal = physical.ordinal();
        let scale = self.scales.matrix(ordinal).ok_or(Error::Physical)?;
        let format = self
            .model
            .formats()
            .get(usize::from(ordinal))
            .ok_or(Error::Physical)?;
        // Complete Scales validation precedes this maximum. Actual consumers retain
        // the original channel values; this maximum is a static bound only (§2).
        let mantissa = scale
            .mantissas()
            .iter()
            .copied()
            .max()
            .ok_or(Error::Physical)?;
        Ok(Weight {
            bits: format.bits(),
            exponent: scale.exponent(),
            mantissa,
        })
    }

    pub fn project(
        &self,
        role: Role,
        layer: Option<u16>,
        source: Row,
        output: u8,
    ) -> Result<Record, Error> {
        let physical = self.physical(role, layer)?;
        if physical.dimensions().get(1) != Some(&u32::from(source.dimension)) {
            return Err(Error::Physical);
        }
        let bias_fraction = if self.model.shape().family() == 0 && layer.is_some() {
            let bias = match role {
                Role::Query => Role::QueryBias,
                Role::Key => Role::KeyBias,
                Role::Value => Role::ValueBias,
                Role::Output => Role::OutputBias,
                Role::Up => Role::UpBias,
                Role::Down => Role::DownBias,
                _ => return Err(Error::Physical),
            };
            let ordinal = self.physical(bias, layer)?.ordinal();
            Some(
                self.model
                    .formats()
                    .get(usize::from(ordinal))
                    .ok_or(Error::Physical)?
                    .parameter(),
            )
        } else {
            None
        };
        Ok(Record::affine(Affine {
            source,
            weight: self.weight(physical)?,
            output_fraction: output,
            bias_fraction,
        })?)
    }
}

pub(super) fn row(dimension: u16, kind: u8, fraction: u8, policy: Policy) -> Row {
    Row {
        dimension,
        kind,
        fraction,
        policy: policy.mode(),
        scale: policy.scale(),
    }
}
pub(super) fn attention_policy(policy: Policy) -> Result<(u8, u16), Error> {
    Ok((
        policy.mode(),
        u16::try_from(policy.scale()).map_err(|_| Error::Policy)?,
    ))
}
pub(super) fn norm(selection: &Representation) -> Result<Record, Error> {
    let function = selection.function();
    Ok(match (function.name(), selection.mode()) {
        ("layernorm_q", 4) => Record::layernorm(*function)?,
        ("rmsnorm_q", 3) => Record::rmsnorm(*function)?,
        _ => return Err(Error::Norm),
    })
}
pub(super) fn norm_fraction(selection: &Representation) -> Result<u8, Error> {
    selection
        .function()
        .parameters()
        .get(4)
        .copied()
        .ok_or(Error::Norm)
}
pub(super) fn exponential(selection: &Representation, count: u32) -> Result<Exponential, Error> {
    let function = selection.function();
    let (bits, source, output, split) = match (
        function.name(),
        selection.mode(),
        function.parameters(),
        selection.parameters(),
    ) {
        ("exp_q/nearest", 0, [b, f, e], []) => (*b, *f, *e, 0),
        ("exp_q/product", 1, [b, f, e, k], []) => (*b, *f, *e, *k),
        ("exp_q/nearest", 2, [b, f, e], [k]) => (*b, *f, *e, *k),
        _ => return Err(Error::Exponential),
    };
    Ok(Exponential {
        count,
        domain_bits: bits,
        source_fraction: source,
        output_fraction: output,
        mode: selection.mode(),
        split,
    })
}
