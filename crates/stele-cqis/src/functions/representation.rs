//! RFC-0021 §4: derive complete ordered component roles from the selected function.
use super::{
    component, tables, Descriptor, Encoded, Error, Kind, Reader, MAX_ENCODING, REPRESENTATION,
};

/// Immutable representation with schema-derived components; decoding is metadata
/// parsing only. Use the expected object's validation to enforce a selected mode.
/// ```compile_fail
/// use stele_cqis::functions::{Descriptor,Representation};
/// let mut r = Representation::new(Descriptor::new("range_8",1,&[]).unwrap(),0,&[]).unwrap();
/// r.mode = 3;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Representation {
    function: Descriptor,
    mode: u8,
    parameters: [u8; 1],
    parameter_length: u8,
    components: [tables::Descriptor; 3],
    component_count: u8,
}

fn components(names: &[&str], p: &[u8]) -> Result<([tables::Descriptor; 3], u8), Error> {
    if !(1..=3).contains(&names.len()) {
        return Err(Error::Representation);
    }
    let mut result = [component(names[0], p).map_err(|_| Error::Representation)?; 3];
    for (slot, name) in result.iter_mut().zip(names) {
        *slot = component(name, p).map_err(|_| Error::Representation)?;
    }
    Ok((
        result,
        u8::try_from(names.len()).map_err(|_| Error::Capacity)?,
    ))
}

impl Representation {
    /// Check the only legal mode/parameter combination and derive all components.
    pub fn new(function: Descriptor, mode: u8, parameters: &[u8]) -> Result<Self, Error> {
        let p = function.parameters();
        let (components, component_count) = match (function.kind, mode, parameters) {
            (Kind::Product, 1, []) => components(&["exp_q/hi", "exp_q/lo"], p)?,
            (Kind::Nearest, 0, []) => components(&["exp_q/direct"], p)?,
            (Kind::Nearest, 2, [k]) => components(
                &["exp_q/hi", "exp_q/lo", "exp_q/correction"],
                &[p[0], p[1], p[2], *k],
            )?,
            (Kind::Norm, 3, []) => components(&["rsqrt_q"], &[])?,
            (Kind::Component(d), 0, []) => ([d; 3], 1),
            _ => return Err(Error::Representation),
        };
        Ok(Self {
            function,
            mode,
            parameters: [parameters.first().copied().unwrap_or(0)],
            parameter_length: u8::try_from(parameters.len()).map_err(|_| Error::Capacity)?,
            components,
            component_count,
        })
    }

    /// The exact expected semantic definition, independent of representation choice.
    pub fn function(&self) -> &Descriptor {
        &self.function
    }
    /// Closed mode byte: direct 0, product 1, corrected nearest 2, norm 3.
    pub fn mode(&self) -> u8 {
        self.mode
    }
    /// The explicit correction split, or empty for the other modes.
    pub fn parameters(&self) -> &[u8] {
        &self.parameters[..usize::from(self.parameter_length)]
    }
    /// Complete schema-derived components in their required role order.
    pub fn components(&self) -> &[tables::Descriptor] {
        &self.components[..usize::from(self.component_count)]
    }

    /// Canonical representation bytes, including every ordered component identity.
    pub fn encode(&self) -> Result<Encoded, Error> {
        let mut encoded = Encoded::new();
        for part in [
            REPRESENTATION,
            &self.function.identity()?,
            &[self.mode, self.parameter_length],
            self.parameters(),
            &[self.component_count],
        ] {
            encoded.push(part)?;
        }
        for d in self.components() {
            // Checked component descriptors can fail encoding only on capacity.
            encoded.push(&d.identity().map_err(|_| Error::Capacity)?)?;
        }
        Ok(encoded)
    }

    /// Ordinary unkeyed BLAKE3-256 of the selected representation bytes.
    pub fn identity(&self) -> Result<[u8; 32], Error> {
        Ok(*blake3::hash(self.encode()?.as_bytes()).as_bytes())
    }

    /// Decode a schema-valid representation for an already expected function.
    /// This does not authorize its choice; validate against the expected selection.
    pub fn decode(function: Descriptor, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_ENCODING {
            return Err(Error::Encoding);
        }
        let mut reader = Reader {
            remaining: raw.strip_prefix(REPRESENTATION).ok_or(Error::Encoding)?,
        };
        if reader.take(32)? != function.identity()? {
            return Err(Error::Identity);
        }
        let header = reader.take(2)?;
        if header[1] > 1 {
            return Err(Error::Representation);
        }
        let result = Self::new(function, header[0], reader.take(usize::from(header[1]))?)?;
        if raw != result.encode()?.as_bytes() {
            return Err(Error::Representation);
        }
        Ok(result)
    }

    /// Reject any change to this expected representation, including a different
    /// schema-valid representation of the very same semantic function.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if Self::decode(self.function, raw)? != *self {
            return Err(Error::Representation);
        }
        Ok(())
    }
}
