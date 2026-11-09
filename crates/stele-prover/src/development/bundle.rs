//! `stele-dev-public-v1`: the verifier's input file (RFC-0026 §1.1 as amended by A2).
//!
//! Layout, integers little endian, `blob` = `u32` length then bytes:
//! magic; blob Model; blob Scales; blob Preparation; `u32` count of 1-D records, each
//! `u16` ordinal and blob of int16 codes; `u32` count of weight sources, each 32-byte
//! root and blob certificate; `u32 T`, tokens as `u32`; `u32 r`, `u32 e`; `u8` 0/1 and,
//! when 1, `u32 y`. Trailing bytes reject.
use super::{Error, Public, Statement};
use alloc::vec::Vec;

const MAGIC: &[u8] = b"stele-dev-public-v1";

fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical bytes of the verifier's input.
pub fn encode(public: &Public, statement: &Statement) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    blob(&mut out, &public.model);
    blob(&mut out, &public.scales);
    blob(&mut out, &public.preparation);
    out.extend_from_slice(&(public.vectors.len() as u32).to_le_bytes());
    for (ordinal, codes) in &public.vectors {
        out.extend_from_slice(&ordinal.to_le_bytes());
        let raw: Vec<u8> = codes.iter().flat_map(|c| c.to_le_bytes()).collect();
        blob(&mut out, &raw);
    }
    out.extend_from_slice(&(public.commitment.len() as u32).to_le_bytes());
    for (root, certificate) in &public.commitment {
        out.extend_from_slice(root);
        blob(&mut out, certificate);
    }
    out.extend_from_slice(&(statement.tokens.len() as u32).to_le_bytes());
    for x in &statement.tokens {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.extend_from_slice(&statement.start.to_le_bytes());
    out.extend_from_slice(&statement.end.to_le_bytes());
    match statement.next {
        Some(y) => {
            out.push(1);
            out.extend_from_slice(&y.to_le_bytes());
        }
        None => out.push(0),
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::StatementMismatch);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// A count whose items each take at least `min` bytes.
    fn count(&mut self, min: usize) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        (n <= self.0.len() / min)
            .then_some(n)
            .ok_or(Error::StatementMismatch)
    }
}

/// Parse the verifier's input; malformed bytes reject with `StatementMismatch`.
pub fn decode(bytes: &[u8]) -> Result<(Public, Statement), Error> {
    let mut r = Reader(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(Error::StatementMismatch);
    }
    let model = r.blob()?.to_vec();
    let scales = r.blob()?.to_vec();
    let preparation = r.blob()?.to_vec();
    let mut vectors = Vec::new();
    for _ in 0..r.count(6)? {
        let o = r.take(2)?;
        let raw = r.blob()?;
        if raw.len() % 2 != 0 {
            return Err(Error::StatementMismatch);
        }
        let codes = raw
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        vectors.push((u16::from_le_bytes([o[0], o[1]]), codes));
    }
    let mut commitment = Vec::new();
    for _ in 0..r.count(36)? {
        let mut root = [0; 32];
        root.copy_from_slice(r.take(32)?);
        commitment.push((root, r.blob()?.to_vec()));
    }
    let mut tokens = Vec::new();
    for _ in 0..r.count(4)? {
        tokens.push(r.u32()?);
    }
    let (start, end) = (r.u32()?, r.u32()?);
    let next = match r.take(1)?[0] {
        0 => None,
        1 => Some(r.u32()?),
        _ => return Err(Error::StatementMismatch),
    };
    if !r.0.is_empty() {
        return Err(Error::StatementMismatch);
    }
    let public = Public {
        model,
        scales,
        preparation,
        vectors,
        commitment,
    };
    Ok((
        public,
        Statement {
            tokens,
            start,
            end,
            next,
        },
    ))
}
