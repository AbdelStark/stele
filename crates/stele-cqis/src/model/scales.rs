//! RFC-0025 encoding §5: complete Scales, derived matrix order and bounded stream reads.
use super::{
    codec::{reserved, Writer},
    Error, Model, Physical,
};
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/scales";
const LIMIT: u64 = 1 << 26;

fn matrices(model: &Model) -> impl Iterator<Item = Physical> + '_ {
    (0..model.shape().record_count())
        .filter_map(|i| model.shape().physical(i))
        .filter(|p| p.dimensions().len() == 2)
}

/// Checked public scale parameters for exactly one derived physical matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatrixScale {
    ordinal: u16,
    exponent: i16,
    mantissas: Vec<u16>,
}
impl MatrixScale {
    /// Physical record id; a tied GPT-2 head uses record zero.
    pub fn ordinal(&self) -> u16 {
        self.ordinal
    }
    /// Shared tensor exponent, including the complete finite-IEEE conversion domain.
    pub fn exponent(&self) -> i16 {
        self.exponent
    }
    /// Positive scale mantissas in complete output-channel order.
    pub fn mantissas(&self) -> &[u16] {
        &self.mantissas
    }
}

/// Complete immutable scale parameters, bound to the full structural Model hash.
/// Source-dependent minimality and outer authority are separate checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scales {
    model_identity: [u8; 32],
    matrices: Vec<MatrixScale>,
    identity: [u8; 32],
    encoded_length: usize,
}
impl Scales {
    /// Derive exact frame length from checked geometry before reading any entry.
    pub fn encoded_length(model: &Model) -> Result<usize, Error> {
        let mut size = (PREFIX.len() + 32) as u64;
        for p in matrices(model) {
            let entry = u64::from(p.dimensions()[0])
                .checked_mul(2)
                .and_then(|n| n.checked_add(4))
                .ok_or(Error::Capacity)?;
            size = size.checked_add(entry).ok_or(Error::Capacity)?;
        }
        if size > LIMIT {
            return Err(Error::Capacity);
        }
        usize::try_from(size).map_err(|_| Error::Capacity)
    }
    /// Validate exact framing and every channel; no source minimality is inferred.
    pub fn decode(model: &Model, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() as u64 > LIMIT {
            return Err(Error::Capacity);
        }
        if raw.len() != Self::encoded_length(model)? {
            return Err(Error::Encoding);
        }
        let mut input = raw;
        Self::read_from(model, |buffer| {
            let n = input.len().min(buffer.len());
            buffer[..n].copy_from_slice(&input[..n]);
            input = &input[n..];
            Ok::<_, core::convert::Infallible>(n)
        })
    }
    /// Complete validation followed by an independently expected Scales hash check.
    pub fn decode_expected(model: &Model, expected: &[u8; 32], raw: &[u8]) -> Result<Self, Error> {
        let scales = Self::decode(model, raw)?;
        if &scales.identity != expected {
            return Err(Error::Identity);
        }
        Ok(scales)
    }
    /// Read a complete Scales stream, including EOF. Short reads are accumulated in
    /// buffers of at most 8192 bytes; storage for checked parameters is fallible.
    /// The callback returns bytes written or zero at EOF. Its errors map to Read.
    /// No result is exposed until every expected byte and channel has been checked.
    pub fn read_from<E>(
        model: &Model,
        read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let encoded_length = Self::encoded_length(model)?;
        let mut entries = reserved(matrices(model).count())?;
        let mut r = Stream {
            read,
            hash: blake3::Hasher::new(),
        };
        let mut prefix = [0; PREFIX.len()];
        r.exact(&mut prefix)?;
        if prefix != PREFIX {
            return Err(Error::Encoding);
        }
        let mut model_identity = [0; 32];
        r.exact(&mut model_identity)?;
        if model_identity != model.identity() {
            return Err(Error::Identity);
        }
        let mut buffer = [0; 8192];
        for p in matrices(model) {
            let mut header = [0; 4];
            r.exact(&mut header)?;
            let ordinal = u16::from_le_bytes([header[0], header[1]]);
            let exponent = i16::from_le_bytes([header[2], header[3]]);
            if ordinal != p.ordinal() {
                return Err(Error::Physical);
            }
            if !(-1099..=1024).contains(&exponent) {
                return Err(Error::ScaleExponent);
            }
            let channels = usize::try_from(p.dimensions()[0]).map_err(|_| Error::Capacity)?;
            let mut mantissas = reserved(channels)?;
            while mantissas.len() < channels {
                let count = (channels - mantissas.len()).min(buffer.len() / 2);
                let bytes = &mut buffer[..2 * count];
                r.exact(bytes)?;
                for word in bytes.chunks_exact(2) {
                    let m = u16::from_le_bytes([word[0], word[1]]);
                    if m == 0 {
                        return Err(Error::ScaleMantissa);
                    }
                    mantissas.push(m);
                }
            }
            entries.push(MatrixScale {
                ordinal,
                exponent,
                mantissas,
            });
        }
        if r.read(&mut [0])? != 0 {
            return Err(Error::Encoding);
        }
        Ok(Self {
            model_identity,
            matrices: entries,
            identity: *r.hash.finalize().as_bytes(),
            encoded_length,
        })
    }
    /// Exact canonical bytes of all public parameters, with fallible allocation.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(self.encoded_length)?;
        w.push(PREFIX)?;
        w.push(&self.model_identity)?;
        for entry in &self.matrices {
            w.push(&entry.ordinal.to_le_bytes())?;
            w.push(&entry.exponent.to_le_bytes())?;
            for m in &entry.mantissas {
                w.push(&m.to_le_bytes())?;
            }
        }
        Ok(w.finish())
    }
    /// Complete Scales hash; it does not authenticate its own expected value.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Complete Model hash, including numerical fields unrelated to physical shape.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// Every matrix in physical order, with no vector records.
    pub fn matrices(&self) -> &[MatrixScale] {
        &self.matrices
    }
    /// Resolve an actual physical id; vectors and out-of-domain ids have no entry.
    pub fn matrix(&self, ordinal: u16) -> Option<&MatrixScale> {
        self.matrices
            .binary_search_by_key(&ordinal, |m| m.ordinal)
            .ok()
            .and_then(|i| self.matrices.get(i))
    }
}

struct Stream<F> {
    read: F,
    hash: blake3::Hasher,
}
impl<E, F: FnMut(&mut [u8]) -> Result<usize, E>> Stream<F> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        let n = (self.read)(buffer).map_err(|_| Error::Read)?;
        if n > buffer.len() {
            return Err(Error::Read);
        }
        Ok(n)
    }
    fn exact(&mut self, buffer: &mut [u8]) -> Result<(), Error> {
        let mut offset = 0;
        while offset < buffer.len() {
            let n = self.read(&mut buffer[offset..])?;
            if n == 0 {
                return Err(Error::Encoding);
            }
            offset += n;
        }
        self.hash.update(buffer);
        Ok(())
    }
}
