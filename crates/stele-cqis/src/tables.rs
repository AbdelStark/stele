//! RFC-0021 §§2,4: closed component descriptors and canonical identity bytes.
//!
//! Descriptor metadata alone does not admit table rows. Generated tables validate
//! their complete integer encodings; neither API authenticates model configuration,
//! enforces membership or accepts a proof.

mod activation;
mod exp;
mod fixed;
mod natural;
pub use fixed::Table;

const PREFIX: &[u8] = b"stele/v0.1/table/identity";
const MAX_DESCRIPTOR: usize = 128;

/// Rejected table metadata or integer data; no partial checked object is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The component name is outside the closed registry.
    Name,
    /// Only definition version 1 is supported.
    Version,
    /// Parameters have the wrong shape, domain or canonical form.
    Parameters,
    /// Malformed framing, non-ASCII name, excess length or trailing bytes.
    Encoding,
    /// A bounded output capacity or checked length cannot be satisfied.
    Capacity,
    /// The complete table-data length differs from the expected descriptor.
    Length,
    /// The table-data domain prefix is not canonical.
    DataHeader,
    /// The table identity differs from the expected generated table.
    Identity,
    /// Claimed rows, padding or tuple width differ from the expected shape.
    Shape,
    /// A real row differs from the complete integer definition.
    Entry,
    /// A padded entry is not zero.
    Padding,
    /// Exact certificate arithmetic violates an interval or magnitude invariant.
    Interval,
    /// The fixed precision/series schedule cannot certify a unique integer.
    Precision,
    /// One generated activation output is outside signed int16.
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    High,
    Low,
    Direct,
    Correction,
    Sigmoid,
    Silu,
    Gelu,
    GeluTanh,
    Softcap,
    Rsqrt,
    Range8,
    Range12,
    Range16,
}

impl Kind {
    fn parse(name: &str) -> Result<Self, Error> {
        match name {
            "exp_q/hi" => Ok(Self::High),
            "exp_q/lo" => Ok(Self::Low),
            "exp_q/direct" => Ok(Self::Direct),
            "exp_q/correction" => Ok(Self::Correction),
            "sigmoid_q" => Ok(Self::Sigmoid),
            "silu_q" => Ok(Self::Silu),
            "gelu_q" => Ok(Self::Gelu),
            "gelu_tanh_q" => Ok(Self::GeluTanh),
            "softcap_q" => Ok(Self::Softcap),
            "rsqrt_q" => Ok(Self::Rsqrt),
            "range_8" => Ok(Self::Range8),
            "range_12" => Ok(Self::Range12),
            "range_16" => Ok(Self::Range16),
            _ => Err(Error::Name),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::High => "exp_q/hi",
            Self::Low => "exp_q/lo",
            Self::Direct => "exp_q/direct",
            Self::Correction => "exp_q/correction",
            Self::Sigmoid => "sigmoid_q",
            Self::Silu => "silu_q",
            Self::Gelu => "gelu_q",
            Self::GeluTanh => "gelu_tanh_q",
            Self::Softcap => "softcap_q",
            Self::Rsqrt => "rsqrt_q",
            Self::Range8 => "range_8",
            Self::Range12 => "range_12",
            Self::Range16 => "range_16",
        }
    }

    fn parameter_length(self) -> usize {
        match self {
            Self::High | Self::Low | Self::Correction => 4,
            Self::Direct => 3,
            Self::Sigmoid | Self::Silu | Self::Gelu | Self::GeluTanh => 2,
            Self::Softcap => 5,
            Self::Rsqrt | Self::Range8 | Self::Range12 | Self::Range16 => 0,
        }
    }
}

/// Descriptor-derived dimensions, never authority for supplied table contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shape {
    rows: u32,
    padded: u32,
    columns: u8,
}

impl Shape {
    /// Number of real rows in increasing integer-input order.
    pub fn rows(self) -> u32 {
        self.rows
    }
    /// Power-of-two row count including canonical all-zero padding.
    pub fn padded(self) -> u32 {
        self.padded
    }
    /// Tuple-column count; range tables have one, all others have two.
    pub fn columns(self) -> u8 {
        self.columns
    }
}

fn power(exponent: u8) -> Result<u32, Error> {
    1u32.checked_shl(u32::from(exponent))
        .ok_or(Error::Parameters)
}

fn shape(kind: Kind, p: &[u8]) -> Result<Shape, Error> {
    let scales = |f: u8, e: u8| f <= 30 && e <= 14;
    let rows = match (kind, p) {
        (Kind::High | Kind::Low | Kind::Correction, [b, f, e, k])
            if (7..=31).contains(b) && scales(*f, *e) && (1..=16).contains(k) =>
        {
            let high_bits = b
                .checked_sub(*k)
                .filter(|bits| *bits <= 15)
                .ok_or(Error::Parameters)?;
            match kind {
                Kind::High => power(high_bits)?.checked_add(1).ok_or(Error::Parameters)?,
                Kind::Low => power(*k)?,
                Kind::Correction if *b <= 15 => {
                    power(*b)?.checked_add(1).ok_or(Error::Parameters)?
                }
                _ => return Err(Error::Parameters),
            }
        }
        (Kind::Direct, [b, f, e]) if (7..=15).contains(b) && scales(*f, *e) => {
            power(*b)?.checked_add(1).ok_or(Error::Parameters)?
        }
        (Kind::Sigmoid | Kind::Silu | Kind::Gelu | Kind::GeluTanh, [f, e]) if scales(*f, *e) => {
            65536
        }
        (Kind::Softcap, [f, e, low, high, cap_f]) if scales(*f, *e) && *cap_f <= 30 => {
            let cap_m = u16::from_le_bytes([*low, *high]);
            if cap_m == 0 || (*cap_f != 0 && cap_m % 2 == 0) {
                return Err(Error::Parameters);
            }
            65536
        }
        (Kind::Rsqrt, []) => 49152,
        (Kind::Range8, []) => 256,
        (Kind::Range12, []) => 4096,
        (Kind::Range16, []) => 65536,
        _ => return Err(Error::Parameters),
    };
    let padded = rows
        .checked_next_power_of_two()
        .filter(|n| *n <= 65536)
        .ok_or(Error::Parameters)?;
    let columns = if matches!(kind, Kind::Range8 | Kind::Range12 | Kind::Range16) {
        1
    } else {
        2
    };
    Ok(Shape {
        rows,
        padded,
        columns,
    })
}

/// Immutable validated version-1 metadata. Parsing is not content verification.
///
/// Unchecked construction is unavailable:
/// ```compile_fail
/// use stele_cqis::tables::Descriptor;
/// let mut d = Descriptor::new("range_8", 1, &[]).unwrap();
/// d.parameters = [0; 5];
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    kind: Kind,
    parameters: [u8; 5],
    shape: Shape,
}

impl Descriptor {
    /// Check the exact closed parameter schema and all shape arithmetic.
    /// Activation metadata may still describe a table whose generation overflows.
    pub fn new(name: &str, version: u32, parameters: &[u8]) -> Result<Self, Error> {
        let kind = Kind::parse(name)?;
        if version != 1 {
            return Err(Error::Version);
        }
        let shape = shape(kind, parameters)?;
        let mut stored = [0; 5];
        stored
            .get_mut(..parameters.len())
            .ok_or(Error::Parameters)?
            .copy_from_slice(parameters);
        Ok(Self {
            kind,
            parameters: stored,
            shape,
        })
    }

    /// The exact ASCII registry name.
    pub fn name(self) -> &'static str {
        self.kind.name()
    }
    /// The only admitted definition version.
    pub fn version(self) -> u32 {
        1
    }
    /// Canonical parameter bytes; their length is a closed constant in 0..=5.
    pub fn parameters(&self) -> &[u8] {
        &self.parameters[..self.kind.parameter_length()]
    }
    /// Dimensions derived at construction; not proof-supplied dimensions.
    pub fn shape(self) -> Shape {
        self.shape
    }

    /// Parse exact framing under the 128/32/64-byte caps before schema validation.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_DESCRIPTOR {
            return Err(Error::Encoding);
        }
        let mut reader = Reader {
            remaining: raw.strip_prefix(PREFIX).ok_or(Error::Encoding)?,
        };
        let name_length = usize::from(reader.u16()?);
        if !(1..=32).contains(&name_length) {
            return Err(Error::Encoding);
        }
        let name = core::str::from_utf8(reader.take(name_length)?).map_err(|_| Error::Encoding)?;
        if !name.is_ascii() {
            return Err(Error::Encoding);
        }
        let version = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| Error::Encoding)?);
        let parameter_length = usize::from(reader.u16()?);
        if parameter_length > 64 {
            return Err(Error::Encoding);
        }
        let parameters = reader.take(parameter_length)?;
        if !reader.remaining.is_empty() {
            return Err(Error::Encoding);
        }
        Self::new(name, version, parameters)
    }

    /// Encode into a bounded stack object, with no heap allocation.
    pub fn encode(&self) -> Result<EncodedDescriptor, Error> {
        let name = self.name().as_bytes();
        let parameters = self.parameters();
        let name_length = u16::try_from(name.len())
            .map_err(|_| Error::Capacity)?
            .to_le_bytes();
        let parameter_length = u16::try_from(parameters.len())
            .map_err(|_| Error::Capacity)?
            .to_le_bytes();
        let mut encoded = EncodedDescriptor {
            bytes: [0; MAX_DESCRIPTOR],
            length: 0,
        };
        for part in [
            PREFIX,
            &name_length,
            name,
            &1u32.to_le_bytes(),
            &parameter_length,
            parameters,
        ] {
            let end = encoded
                .length
                .checked_add(part.len())
                .ok_or(Error::Capacity)?;
            encoded
                .bytes
                .get_mut(encoded.length..end)
                .ok_or(Error::Capacity)?
                .copy_from_slice(part);
            encoded.length = end;
        }
        Ok(encoded)
    }

    /// Ordinary unkeyed BLAKE3-256 of canonical metadata, not an FS challenge.
    pub fn identity(&self) -> Result<[u8; 32], Error> {
        Ok(*blake3::hash(self.encode()?.as_bytes()).as_bytes())
    }
}

/// Canonical descriptor bytes with private, checked length and unused capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedDescriptor {
    bytes: [u8; MAX_DESCRIPTOR],
    length: usize,
}

impl EncodedDescriptor {
    /// Exact protocol bytes; unused backing capacity is never serialized.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let prefix = self.remaining.get(..length).ok_or(Error::Encoding)?;
        self.remaining = self.remaining.get(length..).ok_or(Error::Encoding)?;
        Ok(prefix)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
}
