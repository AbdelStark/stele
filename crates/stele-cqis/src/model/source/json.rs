//! RFC-0025 source §2: nonrecursive JSON primitives and explicit metadata admission.
use super::{reserved, Error};
use alloc::{string::String, vec::Vec};

/// Conservative sum of requested metadata allocations; freed temporaries do not
/// restore the allowance. Allocator rounding/bookkeeping is outside this budget.
pub(super) struct Budget(usize);
impl Budget {
    pub fn new(bytes: usize) -> Self {
        Self(bytes)
    }
    pub(super) fn spend(&mut self, bytes: usize) -> Result<(), Error> {
        self.0 = self.0.checked_sub(bytes).ok_or(Error::Capacity)?;
        Ok(())
    }
    pub fn bytes(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        self.spend(length)?;
        let mut out = reserved(length)?;
        out.resize(length, 0);
        Ok(out)
    }
    pub fn vector<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        self.spend(
            count
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Capacity)?,
        )?;
        reserved(count)
    }
    pub fn push<T>(&mut self, values: &mut Vec<T>, value: T) -> Result<(), Error> {
        if values.len() == values.capacity() {
            let size = core::mem::size_of::<T>().max(1);
            let capacity = values.capacity();
            let available = capacity.saturating_add(self.0 / size);
            let next = capacity.saturating_mul(2).max(4).min(available);
            if next <= capacity {
                return Err(Error::Capacity);
            }
            self.spend((next - capacity).checked_mul(size).ok_or(Error::Capacity)?)?;
            values
                .try_reserve_exact(next - values.len())
                .map_err(|_| Error::Capacity)?;
        }
        values.push(value);
        Ok(())
    }
}

pub(super) struct Json<'a> {
    raw: &'a [u8],
    position: usize,
}
impl<'a> Json<'a> {
    pub fn new(raw: &'a [u8]) -> Result<Self, Error> {
        core::str::from_utf8(raw).map_err(|_| Error::SourceJson)?;
        Ok(Self { raw, position: 0 })
    }
    fn whitespace(&mut self) {
        while self
            .raw
            .get(self.position)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }
    pub fn peek(&mut self) -> Option<u8> {
        self.whitespace();
        self.raw.get(self.position).copied()
    }
    /// Borrow an unquoted scalar token; the caller validates its closed grammar.
    pub fn atom(&mut self) -> &'a [u8] {
        self.whitespace();
        let start = self.position;
        while self
            .raw
            .get(self.position)
            .is_some_and(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}'))
        {
            self.position += 1;
        }
        &self.raw[start..self.position]
    }
    pub fn byte(&mut self, expected: u8) -> Result<(), Error> {
        self.whitespace();
        if self.raw.get(self.position) != Some(&expected) {
            return Err(Error::SourceJson);
        }
        self.position += 1;
        Ok(())
    }
    /// Opening delimiter was consumed by the fixed caller grammar. A trailing
    /// comma cannot close a sequence: its next required value must parse first.
    pub fn next(&mut self, first: &mut bool, end: u8) -> Result<bool, Error> {
        self.whitespace();
        if self.raw.get(self.position) == Some(&end) {
            self.position += 1;
            return Ok(false);
        }
        if !*first {
            self.byte(b',')?;
        }
        *first = false;
        Ok(true)
    }
    pub fn key(&mut self, budget: &mut Budget) -> Result<String, Error> {
        let key = self.string(budget)?;
        self.byte(b':')?;
        Ok(key)
    }
    pub fn string(&mut self, budget: &mut Budget) -> Result<String, Error> {
        self.byte(b'"')?;
        let start = self.position;
        loop {
            match self
                .raw
                .get(self.position)
                .copied()
                .ok_or(Error::SourceJson)?
            {
                b'"' => break,
                b'\\' => {
                    self.position += 1;
                    self.raw.get(self.position).ok_or(Error::SourceJson)?;
                }
                0..=31 => return Err(Error::SourceJson),
                _ => (),
            }
            self.position += 1;
        }
        let content =
            core::str::from_utf8(&self.raw[start..self.position]).map_err(|_| Error::SourceJson)?;
        self.position += 1;
        // Decoded UTF-8 is never longer than its original JSON string contents.
        budget.spend(content.len())?;
        let mut out = String::new();
        out.try_reserve_exact(content.len())
            .map_err(|_| Error::Capacity)?;
        let mut chars = content.chars();
        while let Some(c) = chars.next() {
            let decoded = if c == '\\' {
                match chars.next().ok_or(Error::SourceJson)? {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        let first = hex(&mut chars)?;
                        let value = if (0xd800..=0xdbff).contains(&first) {
                            if chars.next() != Some('\\') || chars.next() != Some('u') {
                                return Err(Error::SourceJson);
                            }
                            let second = hex(&mut chars)?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err(Error::SourceJson);
                            }
                            0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                        } else {
                            first
                        };
                        char::from_u32(value).ok_or(Error::SourceJson)?
                    }
                    _ => return Err(Error::SourceJson),
                }
            } else {
                if c < ' ' {
                    return Err(Error::SourceJson);
                }
                c
            };
            out.push(decoded);
        }
        Ok(out)
    }
    pub fn unsigned(&mut self) -> Result<u64, Error> {
        self.whitespace();
        let negative = self.raw.get(self.position) == Some(&b'-');
        self.position += usize::from(negative);
        let start = self.position;
        let mut value = 0u64;
        while let Some(b @ b'0'..=b'9') = self.raw.get(self.position) {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b - b'0')))
                .ok_or(Error::SourceJson)?;
            self.position += 1;
        }
        if self.position == start
            || (self.position - start > 1 && self.raw[start] == b'0')
            || (negative && value != 0)
        {
            return Err(Error::SourceJson);
        }
        // Python's integer JSON policy admits -0, but never 0.0 or 0e0.
        if self
            .raw
            .get(self.position)
            .is_some_and(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}'))
        {
            return Err(Error::SourceJson);
        }
        Ok(value)
    }
    pub fn end(mut self) -> Result<(), Error> {
        self.whitespace();
        if self.position != self.raw.len() {
            return Err(Error::SourceJson);
        }
        Ok(())
    }
}
fn hex(chars: &mut core::str::Chars<'_>) -> Result<u32, Error> {
    let mut value = 0;
    for _ in 0..4 {
        value = (value << 4)
            | chars
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or(Error::SourceJson)?;
    }
    Ok(value)
}
