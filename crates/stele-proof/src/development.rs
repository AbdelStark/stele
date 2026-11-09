//! `stele-dev-e2e-v1`, the development-profile proof container (RFC-0026 §4.1).
//!
//! Byte layout, every integer little endian:
//! - header: the 16-byte magic `stele-dev-e2e-v1`, a `u16` version (1), the 32-byte `cqis_id`;
//! - the 32-byte statement digest;
//! - six section lists in RFC-0026 §4 order: group certificates, multiplicity
//!   certificates, zerochecks (one per identity domain size), lookups, matmuls,
//!   source openings. Each list is a `u32` count, then each section as a `u32`
//!   length and its bytes.
//!
//! There is no compression and no optional section. [`decode`] reads exactly one
//! container and rejects any trailing byte with [`Error::ProofShape`]. Section counts
//! and contents are the verifier's to check against the plan-derived relation.
use alloc::vec::Vec;

pub const MAGIC: &[u8; 16] = b"stele-dev-e2e-v1";
pub const VERSION: u16 = 1;

/// A container that does not parse exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong magic or version.
    Header,
    /// Truncated, over-long or trailing bytes, or a length past the end.
    ProofShape,
}

/// The decoded sections of one development proof, in RFC-0026 §4.1 order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Container {
    pub cqis_id: [u8; 32],
    pub statement: [u8; 32],
    pub groups: Vec<Vec<u8>>,
    pub multiplicities: Vec<Vec<u8>>,
    pub identities: Vec<Vec<u8>>,
    pub lookups: Vec<Vec<u8>>,
    pub matmuls: Vec<Vec<u8>>,
    pub openings: Vec<Vec<u8>>,
}

impl Container {
    fn lists(&self) -> [&Vec<Vec<u8>>; 6] {
        [
            &self.groups,
            &self.multiplicities,
            &self.identities,
            &self.lookups,
            &self.matmuls,
            &self.openings,
        ]
    }

    /// Canonical bytes; [`decode`] inverts this exactly.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.cqis_id);
        out.extend_from_slice(&self.statement);
        for list in self.lists() {
            out.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for section in list {
                out.extend_from_slice(&(section.len() as u32).to_le_bytes());
                out.extend_from_slice(section);
            }
        }
        out
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::ProofShape);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<usize, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    fn digest(&mut self) -> Result<[u8; 32], Error> {
        let mut out = [0; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    fn list(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let count = self.u32()?;
        // Every section costs at least its 4-byte length, so a count past the rest is short.
        if count > self.0.len() / 4 {
            return Err(Error::ProofShape);
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.u32()?;
            out.push(self.take(len)?.to_vec());
        }
        Ok(out)
    }
}

/// Parse one container; the whole input must be consumed.
pub fn decode(bytes: &[u8]) -> Result<Container, Error> {
    let mut r = Reader(bytes);
    if r.take(MAGIC.len()).map_err(|_| Error::Header)? != MAGIC {
        return Err(Error::Header);
    }
    let version = r.take(2).map_err(|_| Error::Header)?;
    if u16::from_le_bytes([version[0], version[1]]) != VERSION {
        return Err(Error::Header);
    }
    let container = Container {
        cqis_id: r.digest()?,
        statement: r.digest()?,
        groups: r.list()?,
        multiplicities: r.list()?,
        identities: r.list()?,
        lookups: r.list()?,
        matmuls: r.list()?,
        openings: r.list()?,
    };
    if !r.0.is_empty() {
        return Err(Error::ProofShape);
    }
    Ok(container)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> Container {
        Container {
            cqis_id: [1; 32],
            statement: [2; 32],
            groups: vec![vec![3, 4], vec![]],
            multiplicities: vec![vec![5]],
            identities: vec![],
            lookups: vec![vec![6, 7, 8]],
            matmuls: vec![vec![9]],
            openings: vec![vec![10, 11]],
        }
    }

    #[test]
    fn accepts_round_trip() {
        let c = sample();
        assert_eq!(decode(&c.encode()), Ok(c));
    }

    #[test]
    fn rejects_trailing_truncated_and_header_changes() {
        let bytes = sample().encode();
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(decode(&long), Err(Error::ProofShape));
        for n in 50..bytes.len() {
            assert_eq!(decode(&bytes[..n]), Err(Error::ProofShape), "{n}");
        }
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert_eq!(decode(&magic), Err(Error::Header));
        let mut version = bytes;
        version[16] = 2;
        assert_eq!(decode(&version), Err(Error::Header));
    }
}
