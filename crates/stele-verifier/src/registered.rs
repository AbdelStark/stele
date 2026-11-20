//! RFC-0026 A16 — byte-5 replay with a trusted plan registry and independent request
//! columns. Development: no security level. No new commitments, virtual columns,
//! challenges or output-uniqueness lemma: static declarations remain trusted.
//!
//! Written from Accepted A16 and this crate's independent A15 replay (ADR-128/131).
//! The registry authenticates the static plan; this module checks the exact request
//! columns before replaying the original relation. It does not derive the model.

use crate::development::{self, reserve, Error, Public, Reader};
use crate::relation::{Kind, Relation};
use alloc::vec::Vec;
use core::fmt;
use stele_hash::blake3_digest;

const ENTRY_MAGIC: &[u8] = b"stele-dev-plan-v1";
const STATIC_TAG: &[u8] = b"stele/v0.1/dev-e2e/plan-static/v1";
const TEMPLATE_TAG: &[u8] = b"stele/v0.1/dev-e2e/plan-template/v1";
const MODEL_TAG: &[u8] = b"stele/v0.1/dev-e2e/model";
const EMBEDDING: &[u8] = b"G/embedding/O";

/// Acceptance under a trusted plan registry; development: no security level.
///
/// This proves the request decoded from the supplied public file. Callers must
/// compare its tokens, checked range and `y` with their own expected request.
/// It grants neither independent model/plan derivation, ZK nor profile admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Verified(());

impl fmt::Display for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("trusted plan registry; development: no security level")
    }
}
impl fmt::Debug for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

struct Entry {
    cqis: [u8; 32],
    model: [u8; 32],
    tokens: u32,
    static_digest: [u8; 32],
    template: [u8; 32],
    relation_len: u64,
    vocabulary: u32,
    shift: i32,
    mantissas: Vec<u16>,
    lt: u32,
    lv: u32,
    lb: u32,
}
fn ceil_log2(n: u32) -> u32 {
    u32::BITS - (n - 1).leading_zeros()
}
impl Entry {
    /// A16 §1: all metadata and counts are checked before use or allocation.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bad = Error::RegistryEncoding;
        let r = &mut Reader::new(bytes, bad);
        if r.take(ENTRY_MAGIC.len())? != ENTRY_MAGIC {
            return Err(bad);
        }
        let cqis = r.array()?;
        let model = r.array()?;
        let tokens = r.u32()?;
        if r.u8()? != 5 || !tokens.is_power_of_two() {
            return Err(bad);
        }
        let static_digest = r.array()?;
        let template = r.array()?;
        let relation_len = u64::from_le_bytes(r.array()?);
        let vocabulary = r.u32()?;
        let width = u16::from_le_bytes(r.array()?);
        let exponent = i16::from_le_bytes(r.array()?);
        let fraction = r.u8()?;
        if vocabulary == 0 || width == 0 || relation_len < 63 {
            return Err(bad);
        }
        let (lt, lv, ld) = (
            tokens.trailing_zeros(),
            ceil_log2(vocabulary),
            ceil_log2(u32::from(width)),
        );
        if lt + lv > 30 || lt + ld > 30 || ld + lv > 30 {
            return Err(bad);
        }
        let count = r.count(2)?;
        if count as u64 != u64::from(vocabulary) {
            return Err(bad);
        }
        let mut mantissas = reserve(count)?;
        for _ in 0..count {
            let m = u16::from_le_bytes(r.array()?);
            if m == 0 {
                return Err(bad);
            }
            mantissas.push(m);
        }
        r.end()?;
        Ok(Self {
            cqis,
            model,
            tokens,
            static_digest,
            template,
            relation_len,
            vocabulary,
            shift: i32::from(exponent) + i32::from(fraction),
            mantissas,
            lt,
            lv,
            lb: lt.min(30 - ld - lv),
        })
    }
    fn mantissa(&self, token: u32) -> Result<i64, Error> {
        let m = i64::from(
            *self
                .mantissas
                .get(token as usize)
                .ok_or(Error::StatementMismatch)?,
        );
        Ok(if self.shift < 0 {
            m
        } else if self.shift >= 17 {
            65536
        } else {
            (m << self.shift).min(65536)
        })
    }
}

struct Request {
    tokens: Vec<u32>,
    begin: usize,
    end: usize,
    next: Option<u32>,
}
impl Request {
    /// A16 §2: A15 parsing has already checked the range and presence flag.
    fn decode(file: &Public<'_>, vocabulary: u32) -> Result<Self, Error> {
        let r = &mut Reader::new(file.statement, Error::StatementMismatch);
        let n = r.count(4)?;
        let mut tokens = reserve(n)?;
        for _ in 0..n {
            let x = r.u32()?;
            if x >= vocabulary {
                return Err(Error::StatementMismatch);
            }
            tokens.push(x);
        }
        let (begin, end) = (r.u32()? as usize, r.u32()? as usize);
        let next = if r.u8()? == 1 {
            let y = r.u32()?;
            if y >= vocabulary {
                return Err(Error::StatementMismatch);
            }
            Some(y)
        } else {
            None
        };
        r.end()?;
        Ok(Self {
            tokens,
            begin,
            end,
            next,
        })
    }
    fn token(&self, i: usize) -> Result<u32, Error> {
        self.tokens.get(i).copied().ok_or(Error::StatementMismatch)
    }
}

/// A16 §2: key before static data. Record blob byte lengths become code counts.
fn bind_public(file: &Public<'_>, request: &Request, entry: &Entry) -> Result<(), Error> {
    let roots_len = file
        .roots
        .len()
        .checked_mul(32)
        .and_then(|n| n.checked_add(4))
        .ok_or(Error::Capacity)?;
    let capacity = file
        .data
        .len()
        .checked_add(roots_len)
        .and_then(|n| n.checked_add(64))
        .ok_or(Error::Capacity)?;
    let mut bytes = reserve(capacity)?;
    bytes.extend_from_slice(MODEL_TAG);
    bytes.extend_from_slice(&entry.cqis);
    bytes.extend_from_slice(&(file.roots.len() as u32).to_le_bytes());
    for root in &file.roots {
        bytes.extend_from_slice(root);
    }
    let r = &mut Reader::new(file.data, Error::StatementMismatch);
    for _ in 0..3 {
        r.blob()?;
    }
    let n = r.count(6)?;
    bytes.extend_from_slice(&(n as u32).to_le_bytes());
    for _ in 0..n {
        bytes.extend_from_slice(r.take(2)?);
        let codes = r.blob()?;
        bytes.extend_from_slice(&((codes.len() / 2) as u32).to_le_bytes());
        bytes.extend_from_slice(codes);
    }
    if blake3_digest(&bytes) != entry.model
        || request.tokens.len() as u64 != u64::from(entry.tokens)
    {
        return Err(Error::RegistryKeyMismatch);
    }
    bytes.clear();
    bytes.extend_from_slice(STATIC_TAG);
    bytes.extend_from_slice(&(file.data.len() as u64).to_le_bytes());
    bytes.extend_from_slice(file.data);
    bytes.extend_from_slice(&(file.roots.len() as u32).to_le_bytes());
    for root in &file.roots {
        bytes.extend_from_slice(root);
    }
    if blake3_digest(&bytes) != entry.static_digest {
        return Err(Error::RegistryStaticMismatch);
    }
    Ok(())
}

/// A16 §3: the namespace is reserved even for wrong kinds and noncanonical suffixes.
fn request_id(name: &[u8], blocks: usize, shift: i32) -> Result<Option<usize>, Error> {
    let bad = Error::RegistryRequestMismatch;
    if let Some(suffix) = name.strip_prefix(EMBEDDING) {
        if suffix.is_empty() || (suffix.len() > 1 && suffix[0] == b'0') {
            return Err(bad);
        }
        let mut block = 0usize;
        for &digit in suffix {
            if !digit.is_ascii_digit() {
                return Err(bad);
            }
            block = block
                .checked_mul(10)
                .and_then(|b| b.checked_add(usize::from(digit - b'0')))
                .ok_or(bad)?;
        }
        return if block < blocks {
            Ok(Some(block))
        } else {
            Err(bad)
        };
    }
    Ok(Some(
        blocks
            + match name {
                b"G/embedding/m" if shift < 0 => 0,
                b"G/embedding/mm" if shift >= 0 => 0,
                b"G/embedding/m" | b"G/embedding/mm" => return Err(bad),
                b"G/argmax/onehot" => 1,
                b"G/argmax/below" => 2,
                b"G/argmax/rows" => 3,
                _ => return Ok(None),
            },
    ))
}

/// A16 §§3–4: decode completely before request checks, and never expand a domain.
fn bind_relation(bytes: &[u8], request: &Request, entry: &Entry) -> Result<(), Error> {
    if bytes.len() as u64 != entry.relation_len {
        return Err(Error::RegistryTemplateMismatch);
    }
    let relation = Relation::decode(bytes)?;
    let (block_rows, vp) = (1usize << entry.lb, 1usize << entry.lv);
    let blocks = (entry.tokens as usize) / block_rows;
    let count = blocks.checked_add(4).ok_or(Error::Capacity)?;
    let bad = Error::RegistryRequestMismatch;
    if count > relation.columns.len() {
        return Err(bad);
    }
    let mut seen = reserve(count)?;
    seen.resize(count, false);
    let max_mantissa = request
        .tokens
        .iter()
        .try_fold(0i64, |m, &x| Ok::<_, Error>(m.max(entry.mantissa(x)?)))?;
    let mantissa_bits = (i64::BITS - max_mantissa.leading_zeros()).max(1) as u8;
    let mut substitutions = reserve(count)?;
    // The canonical decoder above checked every field; scan only names and byte offsets.
    let r = &mut Reader::new(bytes, Error::StatementMismatch);
    let magic = r.take(31)?;
    let v2 = magic == b"stele/v0.1/relation/encoding/v2";
    let skip_ref = |r: &mut Reader<'_>| -> Result<(), Error> {
        r.take(4)?;
        let n = usize::from(r.u8()?);
        r.take(n)?;
        Ok(())
    };
    for _ in 0..r.count(if v2 { 9 } else { 5 })? {
        r.blob()?;
        r.u8()?;
        if v2 {
            r.take(4)?;
        }
    }
    r.u32()?;
    for column in &relation.columns {
        let name = r.blob()?;
        let mut value_start = r.position();
        let mut value_end = value_start;
        match r.u8()? {
            0 => {
                r.take(4)?;
            }
            1 => {}
            2 => {
                let n = r.count(8)?;
                value_start = r.position();
                r.take(n.checked_mul(8).ok_or(Error::Capacity)?)?;
                value_end = r.position();
            }
            3 if v2 => {
                match r.u8()? {
                    0 => {
                        r.take(8)?;
                        for _ in 0..r.count(13)? {
                            r.take(8)?;
                            skip_ref(r)?;
                        }
                    }
                    1 => {
                        for _ in 0..r.count(9)? {
                            r.take(8)?;
                            for _ in 0..usize::from(r.u8()?) {
                                skip_ref(r)?;
                            }
                        }
                    }
                    2 => {
                        r.take(2)?;
                        skip_ref(r)?;
                        skip_ref(r)?;
                    }
                    _ => return Err(Error::StatementMismatch),
                }
                match r.u8()? {
                    0 => {}
                    1 => {
                        r.take(4)?;
                    }
                    _ => return Err(Error::StatementMismatch),
                }
            }
            _ => return Err(Error::StatementMismatch),
        }
        let width_at = r.position();
        r.take(3)?;
        if v2 {
            r.take(1)?;
        }
        let Some(id) = request_id(name, blocks, entry.shift)? else {
            continue;
        };
        let visited = seen.get_mut(id).ok_or(bad)?;
        if *visited {
            return Err(bad);
        }
        *visited = true;
        let (log, bits) = if id < blocks {
            (entry.lb + entry.lv, 1)
        } else if id == blocks {
            (entry.lt, mantissa_bits)
        } else if id == blocks + 3 {
            (entry.lt, 1)
        } else {
            (entry.lt + entry.lv, 1)
        };
        let Kind::Public(values) = &column.kind else {
            return Err(bad);
        };
        if column.width.signed
            || column.width.bits != bits
            || u32::from(column.log_len) != log
            || values.len() != 1usize << log
        {
            return Err(bad);
        }
        for (j, &value) in values.iter().enumerate() {
            let expected = if id < blocks {
                i64::from(j % vp == request.token(id * block_rows + j / vp)? as usize)
            } else if id == blocks {
                entry.mantissa(request.token(j)?)?
            } else {
                let row = if id == blocks + 3 { j } else { j / vp };
                let checked = request.begin <= row && row < request.end;
                if id == blocks + 3 {
                    i64::from(checked)
                } else if !checked || j % vp >= entry.vocabulary as usize {
                    0
                } else {
                    let next = if row + 1 == request.tokens.len() {
                        request.next.ok_or(Error::StatementMismatch)?
                    } else {
                        request.token(row + 1)?
                    } as usize;
                    i64::from(if id == blocks + 1 {
                        j % vp == next
                    } else {
                        j % vp < next
                    })
                }
            };
            if value != expected {
                return Err(bad);
            }
        }
        substitutions.push((value_start, value_end, width_at));
    }
    if seen.iter().any(|&s| !s) {
        return Err(bad);
    }
    // A16 §4: normalization starts only after every request column is checked.
    let prefix = TEMPLATE_TAG.len() + 8;
    let mut normalized = reserve(prefix.checked_add(bytes.len()).ok_or(Error::Capacity)?)?;
    normalized.extend_from_slice(TEMPLATE_TAG);
    normalized.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    normalized.extend_from_slice(bytes);
    for (start, end, width) in substitutions {
        normalized
            .get_mut(prefix + start..prefix + end)
            .ok_or(bad)?
            .fill(0);
        normalized
            .get_mut(prefix + width..prefix + width + 2)
            .ok_or(bad)?
            .copy_from_slice(&[0, 1]);
    }
    if blake3_digest(&normalized) != entry.template {
        return Err(Error::RegistryTemplateMismatch);
    }
    Ok(())
}

/// Verify byte 5 using a **trusted plan registry**; **development: no security level**.
///
/// RFC-0026 A16: `trusted_entry` must be pinned independently of the prover's files.
/// A prover-supplied matching entry is not authentication. The publisher's model
/// metadata and static declaration remain trusted. `public`, `proof` and `relation`
/// are untrusted; no proof byte is read before all registry preflight checks pass.
/// On success, compare the public tokens, checked range and `y` with your expected
/// request. This API does not authenticate that expectation or grant independent
/// model/plan derivation, ZK replay or profile admission.
pub fn verify(
    public: &[u8],
    proof: &[u8],
    relation: &[u8],
    trusted_entry: &[u8],
) -> Result<Verified, Error> {
    let entry = Entry::decode(trusted_entry)?;
    let file = Public::decode(public)?;
    let request = Request::decode(&file, entry.vocabulary)?;
    bind_public(&file, &request, &entry)?;
    bind_relation(relation, &request, &entry)?;
    // A16 §4: original bytes and original widths, including their original digest.
    development::verify(public, proof, relation, &entry.cqis)?;
    Ok(Verified(()))
}

#[cfg(test)]
mod tests;
