//! RFC-0025 encoding §4: numerical units, function selection and complete-row policies.
use super::{
    codec::{Reader, Writer},
    Error, Rotation, Shape,
};
use crate::functions::{Descriptor, Representation};

pub(super) fn selection(r: &mut Reader<'_>) -> Result<Representation, Error> {
    let f = Descriptor::decode(r.blob(128)?).map_err(Error::Function)?;
    Representation::decode(f, r.blob(192)?).map_err(Error::Function)
}
pub(super) fn write_selection(w: &mut Writer, r: &Representation) -> Result<(), Error> {
    w.blob(r.function().encode().map_err(Error::Function)?.as_bytes())?;
    w.blob(r.encode().map_err(Error::Function)?.as_bytes())
}
pub(super) fn fraction(r: &mut Reader<'_>) -> Result<u8, Error> {
    let f = r.u8()?;
    if f > 30 {
        return Err(Error::Units);
    }
    Ok(f)
}
pub(super) fn norm(r: &Representation, s: Shape, input: u8) -> Result<(), Error> {
    let f = r.function();
    let p = f.parameters();
    let name = if s.family() == 0 {
        "layernorm_q"
    } else {
        "rmsnorm_q"
    };
    if f.name() != name || u16::from_le_bytes([p[0], p[1]]) != s.width() {
        return Err(Error::Norm);
    }
    if p[2] != input {
        return Err(Error::Units);
    }
    Ok(())
}
pub(super) fn exponential(r: &Representation) -> Result<(), Error> {
    if !matches!(r.function().name(), "exp_q/product" | "exp_q/nearest") {
        return Err(Error::Exponential);
    }
    Ok(())
}

/// A complete-row policy, with the domain checked at its owning Model role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    mode: u8,
    scale: u32,
}
impl Policy {
    pub(super) fn read(r: &mut Reader<'_>, gated: bool) -> Result<Self, Error> {
        let mode = r.u8()?;
        let scale = r.u32()?;
        if !((mode == 0 && scale == 0)
            || (mode == 1 && (1..=if gated { 8454661 } else { 65535 }).contains(&scale)))
        {
            return Err(Error::Policy);
        }
        Ok(Self { mode, scale })
    }
    pub(super) fn write(self, w: &mut Writer) -> Result<(), Error> {
        w.push(&[self.mode])?;
        w.push(&self.scale.to_le_bytes())
    }
    /// Dynamic=0, static=1; there is no automatic fallback.
    pub fn mode(self) -> u8 {
        self.mode
    }
    /// Configured scale; dynamic configuration stores zero, not the runtime scale.
    pub fn scale(self) -> u32 {
        self.scale
    }
}

/// Complete checked block configuration; static/data admission remains separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    first_norm: Representation,
    second_norm: Representation,
    fractions: [u8; 7],
    projection_count: usize,
    mid: u8,
    out: u8,
    attention: u8,
    policies: [Policy; 7],
    score_m: u16,
    score_e: i8,
    accumulation: u8,
    drop: u8,
    exp: Representation,
    activation: Representation,
    rotation: Option<Rotation>,
}
impl Block {
    pub(super) fn read(r: &mut Reader<'_>, s: Shape, input: u8) -> Result<Self, Error> {
        let first_norm = selection(r)?;
        let second_norm = selection(r)?;
        let projection_count = if s.family() == 0 { 6 } else { 7 };
        let mut fractions = [0; 7];
        for f in &mut fractions[..projection_count] {
            *f = fraction(r)?;
        }
        let mid = fraction(r)?;
        let out = fraction(r)?;
        let attention = fraction(r)?;
        norm(&first_norm, s, input)?;
        norm(&second_norm, s, mid)?;
        let mut policies = [Policy { mode: 0, scale: 0 }; 7];
        for (i, p) in policies.iter_mut().enumerate() {
            *p = Policy::read(r, s.family() == 1 && i == 6)?;
        }
        let score_m = r.u16()?;
        let score_e = r.u8()? as i8;
        let accumulation = r.u8()?;
        let drop = r.u8()?;
        if score_m == 0
            || !(-62..=30).contains(&score_e)
            || accumulation > 1
            || drop > 62
            || (accumulation == 0 && drop != 0)
        {
            return Err(Error::Attention);
        }
        let exp = selection(r)?;
        exponential(&exp)?;
        let activation = selection(r)?;
        let expected = if s.family() == 0 {
            "gelu_tanh_q"
        } else {
            "silu_q"
        };
        if activation.function().name() != expected {
            return Err(Error::Activation);
        }
        if activation.function().parameters()[0] != fractions[if s.family() == 0 { 4 } else { 5 }] {
            return Err(Error::Units);
        }
        let raw = r.blob(128)?;
        let rotation = if s.family() == 0 {
            if !raw.is_empty() {
                return Err(Error::Rotation);
            }
            None
        } else {
            let v = Rotation::decode(raw)?;
            if v.width() > s.head_width() || v.length() != s.context() {
                return Err(Error::Rotation);
            }
            Some(v)
        };
        Ok(Self {
            first_norm,
            second_norm,
            fractions,
            projection_count,
            mid,
            out,
            attention,
            policies,
            score_m,
            score_e,
            accumulation,
            drop,
            exp,
            activation,
            rotation,
        })
    }
    pub(super) fn write(&self, w: &mut Writer) -> Result<(), Error> {
        write_selection(w, &self.first_norm)?;
        write_selection(w, &self.second_norm)?;
        w.push(self.projection_fractions())?;
        w.push(&[self.mid, self.out, self.attention])?;
        for p in self.policies {
            p.write(w)?;
        }
        w.push(&self.score_m.to_le_bytes())?;
        w.push(&[self.score_e as u8, self.accumulation, self.drop])?;
        write_selection(w, &self.exp)?;
        write_selection(w, &self.activation)?;
        match self.rotation {
            Some(v) => w.blob(&v.encode()?),
            None => w.blob(&[]),
        }
    }
    /// First normalization function and representation.
    pub fn first_norm(&self) -> &Representation {
        &self.first_norm
    }
    /// Second normalization function and representation.
    pub fn second_norm(&self) -> &Representation {
        &self.second_norm
    }
    /// Q,K,V,O,up,[gate],down output fractions in physical projection order.
    pub fn projection_fractions(&self) -> &[u8] {
        &self.fractions[..self.projection_count]
    }
    /// Middle residual fraction.
    pub fn mid_fraction(&self) -> u8 {
        self.mid
    }
    /// Outgoing residual fraction.
    pub fn output_fraction(&self) -> u8 {
        self.out
    }
    /// Assembled attention output fraction before row conversion.
    pub fn attention_fraction(&self) -> u8 {
        self.attention
    }
    /// Seven policies in the exact whole-row order of the encoding appendix.
    pub fn policies(&self) -> &[Policy; 7] {
        &self.policies
    }
    /// Exact score multiplier mantissa and signed exponent.
    pub fn score_multiplier(&self) -> (u16, i8) {
        (self.score_m, self.score_e)
    }
    /// Exact=0 or block1024=1; Bounds must still admit the configured full block.
    pub fn accumulation(&self) -> u8 {
        self.accumulation
    }
    /// Configured block drop, zero in exact mode.
    pub fn drop(&self) -> u8 {
        self.drop
    }
    /// Attention exp function and representation.
    pub fn exponential(&self) -> &Representation {
        &self.exp
    }
    /// Prescribed FFN activation function and representation.
    pub fn activation(&self) -> &Representation {
        &self.activation
    }
    /// Configured rotation; coefficient regeneration is not provided by this field.
    pub fn rotation(&self) -> Option<&Rotation> {
        self.rotation.as_ref()
    }
}
