//! `stele-dev-e2e-v1` and `stele-dev-e2e-v2`, the development-profile proof containers
//! (RFC-0026 §4.1 and A26).
//!
//! Byte layout of `stele-dev-e2e-v1`, every integer little endian:
//! - header: the 16-byte magic `stele-dev-e2e-v1`, a `u16` version (1), the 32-byte `cqis_id`;
//! - the 32-byte statement digest;
//! - six section lists in RFC-0026 §4 order: group certificates, multiplicity
//!   certificates, zerochecks (one per identity domain size), lookups, matmuls,
//!   source openings. Each list is a `u32` count, then each section as a `u32`
//!   length and its bytes.
//!
//! Byte layout of `stele-dev-e2e-v2` (segmented development proofs, RFC-0026 A26):
//! - header: the 16-byte magic `stele-dev-e2e-v2`, a `u16` version (2), the 32-byte `cqis_id`;
//! - the 32-byte statement digest;
//! - `u32` segment count (`>= 1`), then for each segment in order: seven section lists
//!   (`groups`, `multiplicities`, `identities`, `lookups`, `matmuls`, `reductions`,
//!   `openings`);
//! - one section list `model_openings` (model-source openings, after all segments).
//!
//! There is no compression and no optional section. [`decode`] / [`decode_v2`] / [`decode_any`]
//! read exactly one container and reject any trailing byte with [`Error::ProofShape`]. Section
//! counts and contents are the verifier's to check against the plan-derived relation.
use alloc::vec::Vec;

pub const MAGIC: &[u8; 16] = b"stele-dev-e2e-v1";
pub const VERSION: u16 = 1;
pub const MAGIC_V2: &[u8; 16] = b"stele-dev-e2e-v2";
pub const VERSION_V2: u16 = 2;

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

/// Per-segment sections of a `stele-dev-e2e-v2` segmented development proof (RFC-0026 A26).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SegmentSections {
    pub groups: Vec<Vec<u8>>,
    pub multiplicities: Vec<Vec<u8>>,
    pub identities: Vec<Vec<u8>>,
    pub lookups: Vec<Vec<u8>>,
    pub matmuls: Vec<Vec<u8>>,
    pub reductions: Vec<Vec<u8>>,
    pub openings: Vec<Vec<u8>>,
}

impl SegmentSections {
    fn lists(&self) -> [&Vec<Vec<u8>>; 7] {
        [
            &self.groups,
            &self.multiplicities,
            &self.identities,
            &self.lookups,
            &self.matmuls,
            &self.reductions,
            &self.openings,
        ]
    }
}

/// The decoded sections of one segmented development proof (`stele-dev-e2e-v2`, RFC-0026 A26).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerV2 {
    pub cqis_id: [u8; 32],
    pub statement: [u8; 32],
    pub segments: Vec<SegmentSections>,
    pub model_openings: Vec<Vec<u8>>,
}

/// Either a `stele-dev-e2e-v1` or `stele-dev-e2e-v2` proof container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    V1(Container),
    V2(ContainerV2),
}

impl Decoded {
    pub fn cqis_id(&self) -> [u8; 32] {
        match self {
            Self::V1(c) => c.cqis_id,
            Self::V2(c) => c.cqis_id,
        }
    }

    pub fn statement(&self) -> [u8; 32] {
        match self {
            Self::V1(c) => c.statement,
            Self::V2(c) => c.statement,
        }
    }

    pub fn set_statement(&mut self, statement: [u8; 32]) {
        match self {
            Self::V1(c) => c.statement = statement,
            Self::V2(c) => c.statement = statement,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::V1(c) => c.encode(),
            Self::V2(c) => c.encode(),
        }
    }
}

fn write_list(out: &mut Vec<u8>, list: &[Vec<u8>]) {
    let count = u32::try_from(list.len()).expect("section list count fits u32");
    out.extend_from_slice(&count.to_le_bytes());
    for section in list {
        let len = u32::try_from(section.len()).expect("section byte length fits u32");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(section);
    }
}

impl ContainerV2 {
    /// Canonical bytes; [`decode_v2`] inverts this exactly (for non-empty `segments`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_V2);
        out.extend_from_slice(&VERSION_V2.to_le_bytes());
        out.extend_from_slice(&self.cqis_id);
        out.extend_from_slice(&self.statement);
        let seg_count = u32::try_from(self.segments.len()).expect("segment count fits u32");
        out.extend_from_slice(&seg_count.to_le_bytes());
        for seg in &self.segments {
            for list in seg.lists() {
                write_list(&mut out, list);
            }
        }
        write_list(&mut out, &self.model_openings);
        out
    }
}

/// Parse one `stele-dev-e2e-v2` container; the whole input must be consumed.
pub fn decode_v2(bytes: &[u8]) -> Result<ContainerV2, Error> {
    let mut r = Reader(bytes);
    if r.take(MAGIC_V2.len()).map_err(|_| Error::Header)? != MAGIC_V2 {
        return Err(Error::Header);
    }
    let version = r.take(2).map_err(|_| Error::Header)?;
    if u16::from_le_bytes([version[0], version[1]]) != VERSION_V2 {
        return Err(Error::Header);
    }
    let cqis_id = r.digest()?;
    let statement = r.digest()?;
    let seg_count = r.u32()?;
    // Every segment encodes 7 section-list u32 counts (28 bytes), followed by model_openings' u32 count (4 bytes).
    if r.0.len() < 4 || seg_count == 0 || seg_count > (r.0.len() - 4) / 28 {
        return Err(Error::ProofShape);
    }
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(seg_count)
        .map_err(|_| Error::ProofShape)?;
    for _ in 0..seg_count {
        let groups = r.list()?;
        let multiplicities = r.list()?;
        let identities = r.list()?;
        let lookups = r.list()?;
        let matmuls = r.list()?;
        let reductions = r.list()?;
        let openings = r.list()?;
        segments.push(SegmentSections {
            groups,
            multiplicities,
            identities,
            lookups,
            matmuls,
            reductions,
            openings,
        });
    }
    let model_openings = r.list()?;
    if !r.0.is_empty() {
        return Err(Error::ProofShape);
    }
    Ok(ContainerV2 {
        cqis_id,
        statement,
        segments,
        model_openings,
    })
}

/// Parse either a `stele-dev-e2e-v1` or `stele-dev-e2e-v2` container.
pub fn decode_any(bytes: &[u8]) -> Result<Decoded, Error> {
    let magic = bytes.get(..16).ok_or(Error::Header)?;
    if magic == MAGIC {
        decode(bytes).map(Decoded::V1)
    } else if magic == MAGIC_V2 {
        decode_v2(bytes).map(Decoded::V2)
    } else {
        Err(Error::Header)
    }
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

    fn sample_v2() -> ContainerV2 {
        ContainerV2 {
            cqis_id: [1; 32],
            statement: [2; 32],
            segments: vec![
                SegmentSections {
                    groups: vec![vec![3, 4], vec![]],
                    multiplicities: vec![vec![5]],
                    identities: vec![vec![6]],
                    lookups: vec![vec![7, 8]],
                    matmuls: vec![vec![9]],
                    reductions: vec![vec![10]],
                    openings: vec![vec![11, 12]],
                },
                SegmentSections {
                    groups: vec![],
                    multiplicities: vec![],
                    identities: vec![],
                    lookups: vec![],
                    matmuls: vec![vec![13]],
                    reductions: vec![],
                    openings: vec![],
                },
            ],
            model_openings: vec![vec![14, 15], vec![16]],
        }
    }

    #[test]
    fn accepts_round_trip() {
        let c = sample();
        let bytes = c.encode();
        assert_eq!(decode(&bytes), Ok(c.clone()));
        assert_eq!(decode_v2(&bytes), Err(Error::Header));
        let mut decoded = decode_any(&bytes).expect("v1 decodes");
        assert_eq!(decoded, Decoded::V1(c));
        assert_eq!(decoded.cqis_id(), [1; 32]);
        assert_eq!(decoded.statement(), [2; 32]);
        decoded.set_statement([8; 32]);
        assert_eq!(decoded.statement(), [8; 32]);
        assert_eq!(decode_any(&decoded.encode()), Ok(decoded));
    }

    #[test]
    fn accepts_v2_round_trip() {
        let c = sample_v2();
        let bytes = c.encode();
        assert_eq!(decode_v2(&bytes), Ok(c.clone()));
        assert_eq!(decode_any(&bytes), Ok(Decoded::V2(c.clone())));
        assert_eq!(decode(&bytes), Err(Error::Header));
        let mut decoded = Decoded::V2(c);
        decoded.set_statement([9; 32]);
        assert_eq!(decoded.statement(), [9; 32]);
        assert_eq!(decoded.cqis_id(), [1; 32]);
        assert_eq!(decode_any(&decoded.encode()), Ok(decoded));

        // Exact minimal 1-segment empty v2 container: 82B header + 4B seg_count + 28B segment + 4B model_openings = 118B.
        let minimal = ContainerV2 {
            cqis_id: [3; 32],
            statement: [4; 32],
            segments: vec![SegmentSections::default()],
            model_openings: vec![],
        };
        let min_bytes = minimal.encode();
        assert_eq!(min_bytes.len(), 118);
        assert_eq!(decode_v2(&min_bytes), Ok(minimal.clone()));
        assert_eq!(decode_any(&min_bytes), Ok(Decoded::V2(minimal)));
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
        assert_eq!(decode_any(&magic), Err(Error::Header));
        assert_eq!(decode_any(&bytes[..15]), Err(Error::Header));
        assert_eq!(decode_any(&bytes[..16]), Err(Error::Header));
        assert_eq!(decode_any(&bytes[..17]), Err(Error::Header));
        let mut version = bytes.clone();
        version[16] = 2;
        assert_eq!(decode(&version), Err(Error::Header));
        assert_eq!(decode_any(&version), Err(Error::Header));
        let mut version_hi = bytes;
        version_hi[17] = 1;
        assert_eq!(decode(&version_hi), Err(Error::Header));
        assert_eq!(decode_any(&version_hi), Err(Error::Header));
    }

    #[test]
    fn rejects_v2_malformed_zero_segments_and_header_changes() {
        let bytes = sample_v2().encode();
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(decode_v2(&long), Err(Error::ProofShape));
        assert_eq!(decode_any(&long), Err(Error::ProofShape));
        for n in 0..18 {
            assert_eq!(decode_v2(&bytes[..n]), Err(Error::Header), "{n}");
            assert_eq!(decode_any(&bytes[..n]), Err(Error::Header), "{n}");
        }
        for n in 18..bytes.len() {
            assert_eq!(decode_v2(&bytes[..n]), Err(Error::ProofShape), "{n}");
        }
        let mut magic = bytes.clone();
        magic[15] = b'1';
        assert_eq!(decode_v2(&magic), Err(Error::Header));
        let mut version = bytes.clone();
        version[16] = 1;
        assert_eq!(decode_v2(&version), Err(Error::Header));
        assert_eq!(decode_any(&version), Err(Error::Header));
        let mut version_hi = bytes.clone();
        version_hi[17] = 1;
        assert_eq!(decode_v2(&version_hi), Err(Error::Header));
        assert_eq!(decode_any(&version_hi), Err(Error::Header));
        // Zero segments must be rejected.
        let zero = ContainerV2 {
            cqis_id: [1; 32],
            statement: [2; 32],
            segments: vec![],
            model_openings: vec![],
        }
        .encode();
        assert_eq!(decode_v2(&zero), Err(Error::ProofShape));
        assert_eq!(decode_any(&zero), Err(Error::ProofShape));
        // Inflated segment count rejected before allocation (both u32::MAX and tight boundary + 1).
        let mut inflated = bytes.clone();
        inflated[82..86].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_v2(&inflated), Err(Error::ProofShape));
        let max_segs = (bytes.len() - 86 - 4) / 28;
        let mut tight = bytes.clone();
        tight[82..86].copy_from_slice(&((max_segs + 1) as u32).to_le_bytes());
        assert_eq!(decode_v2(&tight), Err(Error::ProofShape));
        // Inflated inner list count (segment 0 groups count at byte 86..90) and section byte length (byte 90..94).
        let mut bad_list_count = bytes.clone();
        bad_list_count[86..90].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_v2(&bad_list_count), Err(Error::ProofShape));
        let mut bad_section_len = bytes;
        bad_section_len[90..94].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_v2(&bad_section_len), Err(Error::ProofShape));
    }
}
