//! RFC-0021 §§2,4: canonical function identities and selected representations.
//! Metadata checks do not authenticate configuration, table contents or a proof.
use crate::tables;

mod representation;
pub use representation::Representation;

const FUNCTION: &[u8] = b"stele/v0.1/function/identity";
const REPRESENTATION: &[u8] = b"stele/v0.1/function/representation";
const MAX_DESCRIPTOR: usize = 128;
const MAX_ENCODING: usize = 192;

/// Rejected function/representation metadata; no partial checked object is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unknown function name, including a component used as a function.
    Name,
    /// Only definition version 1 is supported.
    Version,
    /// A parameter has the wrong length, domain or canonical form.
    Parameters,
    /// Invalid framing, length, non-ASCII name or trailing bytes.
    Encoding,
    /// Checked output capacity cannot be satisfied.
    Capacity,
    /// The representation belongs to a different expected function.
    Identity,
    /// Invalid or unexpected mode, parameters, component roles, order or identity.
    Representation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Product,
    Nearest,
    Norm,
    Component(tables::Descriptor),
}

/// Immutable version-1 semantic definition. Parsing does not select a representation.
/// ```compile_fail
/// use stele_cqis::functions::Descriptor;
/// let mut f = Descriptor::new("range_8",1,&[]).unwrap();
/// f.parameters = [0;13];
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    kind: Kind,
    parameters: [u8; 13],
}

fn component(name: &str, parameters: &[u8]) -> Result<tables::Descriptor, Error> {
    tables::Descriptor::new(name, 1, parameters).map_err(|_| Error::Parameters)
}

fn norm(parameters: &[u8]) -> Result<(), Error> {
    let p: &[u8; 13] = parameters.try_into().map_err(|_| Error::Parameters)?;
    let d = u16::from_le_bytes([p[0], p[1]]);
    let mut en = u32::from_le_bytes(p[5..9].try_into().map_err(|_| Error::Parameters)?);
    let mut ed = u32::from_le_bytes(p[9..13].try_into().map_err(|_| Error::Parameters)?);
    if !(1..=16384).contains(&d) || p[2] > 30 || p[3] > 30 || p[4] > 14 || en == 0 || ed == 0 {
        return Err(Error::Parameters);
    }
    while ed != 0 {
        (en, ed) = (ed, en % ed);
    }
    if en != 1 {
        return Err(Error::Parameters);
    }
    Ok(())
}

impl Descriptor {
    /// Validate the closed function schema, including every canonical RMSNorm parameter.
    /// Valid activation metadata may still describe a table whose generation overflows.
    pub fn new(name: &str, version: u32, parameters: &[u8]) -> Result<Self, Error> {
        let kind = match name {
            "exp_q/product" => Kind::Product,
            "exp_q/nearest" => Kind::Nearest,
            "rmsnorm_q" => Kind::Norm,
            "sigmoid_q" | "silu_q" | "softcap_q" | "gelu_q" | "gelu_tanh_q" | "range_8"
            | "range_12" | "range_16" => {
                if version != 1 {
                    return Err(Error::Version);
                }
                Kind::Component(component(name, parameters)?)
            }
            _ => return Err(Error::Name),
        };
        if version != 1 {
            return Err(Error::Version);
        }
        match kind {
            Kind::Product => {
                component("exp_q/hi", parameters)?;
            }
            Kind::Nearest => {
                component("exp_q/direct", parameters)?;
            }
            Kind::Norm => norm(parameters)?,
            Kind::Component(_) => {}
        }
        let mut stored = [0; 13];
        stored
            .get_mut(..parameters.len())
            .ok_or(Error::Parameters)?
            .copy_from_slice(parameters);
        Ok(Self {
            kind,
            parameters: stored,
        })
    }

    /// Exact ASCII function name, distinct from exponential/rsqrt component names.
    pub fn name(self) -> &'static str {
        match self.kind {
            Kind::Product => "exp_q/product",
            Kind::Nearest => "exp_q/nearest",
            Kind::Norm => "rmsnorm_q",
            Kind::Component(d) => d.name(),
        }
    }
    /// The only supported definition version.
    pub fn version(self) -> u32 {
        1
    }
    /// Canonical semantic parameters; no unresolved defaults.
    pub fn parameters(&self) -> &[u8] {
        let length = match self.kind {
            Kind::Product => 4,
            Kind::Nearest => 3,
            Kind::Norm => 13,
            Kind::Component(d) => d.parameters().len(),
        };
        &self.parameters[..length]
    }

    /// Parse under the 128/32/64-byte caps before admitting the exact schema.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_DESCRIPTOR {
            return Err(Error::Encoding);
        }
        let mut reader = Reader {
            remaining: raw.strip_prefix(FUNCTION).ok_or(Error::Encoding)?,
        };
        let n = usize::from(reader.u16()?);
        if !(1..=32).contains(&n) {
            return Err(Error::Encoding);
        }
        let name = core::str::from_utf8(reader.take(n)?).map_err(|_| Error::Encoding)?;
        if !name.is_ascii() {
            return Err(Error::Encoding);
        }
        let version = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| Error::Encoding)?);
        let n = usize::from(reader.u16()?);
        if n > 64 {
            return Err(Error::Encoding);
        }
        let parameters = reader.take(n)?;
        if !reader.remaining.is_empty() {
            return Err(Error::Encoding);
        }
        Self::new(name, version, parameters)
    }

    /// Canonical function descriptor in a bounded stack buffer; no heap allocation.
    pub fn encode(&self) -> Result<Encoded, Error> {
        let name = self.name().as_bytes();
        let parameters = self.parameters();
        let mut encoded = Encoded::new();
        for part in [
            FUNCTION,
            &u16::try_from(name.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
            name,
            &1u32.to_le_bytes(),
            &u16::try_from(parameters.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
            parameters,
        ] {
            encoded.push(part)?;
        }
        if encoded.length > MAX_DESCRIPTOR {
            return Err(Error::Capacity);
        }
        Ok(encoded)
    }

    /// Ordinary unkeyed BLAKE3-256 of the semantic descriptor, not an FS challenge.
    pub fn identity(&self) -> Result<[u8; 32], Error> {
        Ok(*blake3::hash(self.encode()?.as_bytes()).as_bytes())
    }
}

/// Canonical function or representation bytes with private length and capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Encoded {
    bytes: [u8; MAX_ENCODING],
    length: usize,
}

impl Encoded {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_ENCODING],
            length: 0,
        }
    }
    fn push(&mut self, part: &[u8]) -> Result<(), Error> {
        let end = self.length.checked_add(part.len()).ok_or(Error::Capacity)?;
        self.bytes
            .get_mut(self.length..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(part);
        self.length = end;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_capacity_and_oversized_reads_without_exposing_prefixes() {
        let mut encoded = Encoded::new();
        encoded.push(&[7; MAX_ENCODING]).expect("exact capacity");
        let before = encoded;
        assert_eq!(encoded.push(&[1]), Err(Error::Capacity));
        assert_eq!(encoded, before);
        let mut reader = Reader {
            remaining: &[1, 2, 3],
        };
        assert_eq!(reader.take(usize::MAX), Err(Error::Encoding));
        assert_eq!(reader.remaining, &[1, 2, 3]);
    }
}
