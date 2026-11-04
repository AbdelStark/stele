//! RFC-0025 source §§1,3: exact File metadata and bounded sorted file lists.
use crate::model::{
    codec::{reserved, Reader},
    Error,
};
use alloc::vec::Vec;

/// One canonical File descriptor; its declared SHA-256 does not validate a file.
/// Names are labels only and do not authorize filesystem access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFile<'a> {
    name: &'a str,
    length: u64,
    sha256: &'a [u8; 32],
}
impl<'a> SourceFile<'a> {
    pub(super) fn read(r: &mut Reader<'a>) -> Result<Self, Error> {
        let n = usize::from(r.u16()?);
        if n == 0 {
            return Err(Error::FileName);
        }
        let name = core::str::from_utf8(r.take(n)?).map_err(|_| Error::FileName)?;
        if matches!(name, "." | "..")
            || name
                .as_bytes()
                .iter()
                .any(|b| matches!(b, 0 | b'/' | b'\\'))
        {
            return Err(Error::FileName);
        }
        let length = r.u64()?;
        let sha256 = r.take(32)?.try_into().map_err(|_| Error::Encoding)?;
        Ok(Self {
            name,
            length,
            sha256,
        })
    }
    /// Exact nonempty UTF-8 basename, without normalization.
    pub fn name(&self) -> &'a str {
        self.name
    }
    /// Declared complete original-file length, retaining the full u64 domain.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// Declared SHA-256 of every original byte, including all headers and padding.
    pub fn sha256(&self) -> [u8; 32] {
        *self.sha256
    }
}

pub(super) fn files<'a>(
    r: &mut Reader<'a>,
    maximum: Option<u64>,
    names_limit: Option<u64>,
) -> Result<(Vec<SourceFile<'a>>, u64), Error> {
    let count = usize::try_from(r.u32()?).map_err(|_| Error::Capacity)?;
    // A File needs 42 fixed bytes and at least one name byte. The Source index
    // adds its independent count bound before this allocation (source §1).
    if count > r.0.len() / 43 || maximum.is_some_and(|n| count as u64 > n) {
        return Err(Error::Capacity);
    }
    let mut files = reserved(count)?;
    let mut total = 0u64;
    let mut names = 0u64;
    let mut previous: Option<&str> = None;
    for _ in 0..count {
        let file = SourceFile::read(r)?;
        if let Some(prior) = previous {
            if prior == file.name() {
                return Err(Error::FileSet);
            }
            if prior.as_bytes() > file.name().as_bytes() {
                return Err(Error::FileOrder);
            }
        }
        previous = Some(file.name());
        total = total.checked_add(file.length()).ok_or(Error::FileLength)?;
        names = names
            .checked_add(file.name().len() as u64)
            .ok_or(Error::Capacity)?;
        if names_limit.is_some_and(|n| names > n) {
            return Err(Error::Capacity);
        }
        files.push(file);
    }
    Ok((files, total))
}
