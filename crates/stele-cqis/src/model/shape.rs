//! RFC-0025 encoding §1: derive all physical roles from the complete checked Shape.
use super::{codec::Reader, Error};

/// Closed physical role, independent of source names or payload metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Token embedding matrix; also the GPT-2 head.
    Token,
    /// Learned GPT-2 position matrix.
    Position,
    /// First norm gain.
    FirstGain,
    /// First norm bias.
    FirstBias,
    /// Q projection.
    Query,
    /// Q bias.
    QueryBias,
    /// K projection.
    Key,
    /// K bias.
    KeyBias,
    /// V projection.
    Value,
    /// V bias.
    ValueBias,
    /// O projection.
    Output,
    /// O bias.
    OutputBias,
    /// FFN up projection.
    Up,
    /// FFN up bias.
    UpBias,
    /// Llama gate projection.
    Gate,
    /// FFN down projection.
    Down,
    /// FFN down bias.
    DownBias,
    /// Second norm gain.
    SecondGain,
    /// Second norm bias.
    SecondBias,
    /// Final norm gain.
    FinalGain,
    /// Final norm bias.
    FinalBias,
    /// Distinct Llama head matrix.
    Head,
}
impl Role {
    /// Exact role label in RFC-0025's physical expansion.
    pub fn name(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Position => "position",
            Self::FirstGain => "norm1.gain",
            Self::FirstBias => "norm1.bias",
            Self::Query => "Q",
            Self::QueryBias => "Q.bias",
            Self::Key => "K",
            Self::KeyBias => "K.bias",
            Self::Value => "V",
            Self::ValueBias => "V.bias",
            Self::Output => "O",
            Self::OutputBias => "O.bias",
            Self::Up => "up",
            Self::UpBias => "up.bias",
            Self::Gate => "gate",
            Self::Down => "down",
            Self::DownBias => "down.bias",
            Self::SecondGain => "norm2.gain",
            Self::SecondBias => "norm2.bias",
            Self::FinalGain => "final.gain",
            Self::FinalBias => "final.bias",
            Self::Head => "head",
        }
    }
}

/// Derived physical geometry. Distinct roles retain distinct ordinals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Physical {
    ordinal: u16,
    role: Role,
    layer: Option<u16>,
    dimensions: [u32; 2],
    rank: usize,
}
impl Physical {
    /// Prescribed physical record index.
    pub fn ordinal(self) -> u16 {
        self.ordinal
    }
    /// Prescribed role, never read from an artifact.
    pub fn role(self) -> Role {
        self.role
    }
    /// Block index, or absence for model boundaries.
    pub fn layer(self) -> Option<u16> {
        self.layer
    }
    /// Exact positive dimensions, with channel axis first for matrices.
    pub fn dimensions(&self) -> &[u32] {
        &self.dimensions[..self.rank]
    }
}

/// Structurally checked dimensions; these do not authenticate a named checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shape {
    family: u8,
    layers: u16,
    width: u16,
    heads: u16,
    groups: u16,
    head_width: u16,
    hidden: u16,
    vocabulary: u32,
    context: u32,
}
impl Shape {
    /// Decode exactly 21 bytes and enforce the complete family/head/width domains.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != 21 {
            return Err(Error::Shape);
        }
        let mut r = Reader(raw);
        let s = Self {
            family: r.u8()?,
            layers: r.u16()?,
            width: r.u16()?,
            heads: r.u16()?,
            groups: r.u16()?,
            head_width: r.u16()?,
            hidden: r.u16()?,
            vocabulary: r.u32()?,
            context: r.u32()?,
        };
        if s.family > 1
            || !(1..=128).contains(&s.layers)
            || !(1..=128).contains(&s.heads)
            || !(1..=128).contains(&s.groups)
            || !(1..=16384).contains(&s.width)
            || !(1..=16384).contains(&s.hidden)
            || !(1..=16384).contains(&s.head_width)
            || !(1..=1 << 20).contains(&s.vocabulary)
            || !(1..=1 << 20).contains(&s.context)
            || u32::from(s.heads) * u32::from(s.head_width) != u32::from(s.width)
            || !s.heads.is_multiple_of(s.groups)
            || (s.family == 0
                && (s.groups != s.heads || u32::from(s.hidden) != 4 * u32::from(s.width)))
        {
            return Err(Error::Shape);
        }
        Ok(s)
    }
    /// Exact fixed-width Shape bytes.
    pub fn encode(self) -> [u8; 21] {
        let mut out = [0; 21];
        out[0] = self.family;
        for (i, value) in [
            self.layers,
            self.width,
            self.heads,
            self.groups,
            self.head_width,
            self.hidden,
        ]
        .iter()
        .enumerate()
        {
            out[1 + 2 * i..3 + 2 * i].copy_from_slice(&value.to_le_bytes());
        }
        out[13..17].copy_from_slice(&self.vocabulary.to_le_bytes());
        out[17..21].copy_from_slice(&self.context.to_le_bytes());
        out
    }
    /// Family tag: GPT-2=0, Llama=1.
    pub fn family(self) -> u8 {
        self.family
    }
    /// Block count.
    pub fn layers(self) -> u16 {
        self.layers
    }
    /// Residual width.
    pub fn width(self) -> u16 {
        self.width
    }
    /// Query head count.
    pub fn heads(self) -> u16 {
        self.heads
    }
    /// Key/value group count.
    pub fn groups(self) -> u16 {
        self.groups
    }
    /// Width of one attention head.
    pub fn head_width(self) -> u16 {
        self.head_width
    }
    /// FFN hidden width.
    pub fn hidden(self) -> u16 {
        self.hidden
    }
    /// Complete vocabulary size.
    pub fn vocabulary(self) -> u32 {
        self.vocabulary
    }
    /// Configured context capacity, independent of a request's actual extent.
    pub fn context(self) -> u32 {
        self.context
    }
    /// Exact physical count, including boundaries and the prescribed head tie.
    pub fn record_count(self) -> u16 {
        if self.family == 0 {
            16 * self.layers + 4
        } else {
            9 * self.layers + 3
        }
    }
    /// Derive one physical role. The GPT-2 head has no additional record.
    pub fn physical(self, ordinal: u16) -> Option<Physical> {
        use Role::*;
        if ordinal >= self.record_count() {
            return None;
        }
        let prefix = if self.family == 0 { 2 } else { 1 };
        let per = if self.family == 0 { 16 } else { 9 };
        let (role, layer) = if ordinal == 0 {
            (Token, None)
        } else if self.family == 0 && ordinal == 1 {
            (Position, None)
        } else if ordinal - prefix < per * self.layers {
            let i = ordinal - prefix;
            let roles: &[Role] = if self.family == 0 {
                &[
                    FirstGain, FirstBias, Query, QueryBias, Key, KeyBias, Value, ValueBias, Output,
                    OutputBias, Up, UpBias, Down, DownBias, SecondGain, SecondBias,
                ]
            } else {
                &[
                    FirstGain, Query, Key, Value, Output, Up, Gate, Down, SecondGain,
                ]
            };
            (roles[usize::from(i % per)], Some(i / per))
        } else if ordinal == self.record_count() - 2 {
            (FinalGain, None)
        } else {
            (if self.family == 0 { FinalBias } else { Head }, None)
        };
        let d = u32::from(self.width);
        let f = u32::from(self.hidden);
        let kv = u32::from(self.groups) * u32::from(self.head_width);
        let (dimensions, rank) = match role {
            Token | Head => ([self.vocabulary, d], 2),
            Position => ([self.context, d], 2),
            Query | Output => ([d, d], 2),
            Key | Value => ([kv, d], 2),
            Up | Gate => ([f, d], 2),
            Down => ([d, f], 2),
            KeyBias | ValueBias => ([kv, 0], 1),
            UpBias => ([f, 0], 1),
            _ => ([d, 0], 1),
        };
        Some(Physical {
            ordinal,
            role,
            layer,
            dimensions,
            rank,
        })
    }
}
