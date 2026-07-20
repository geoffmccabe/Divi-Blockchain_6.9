//! Canonical LEB128 unsigned varints + a bounds-checked read cursor.
//!
//! Canonicality is enforced on read: a value that could have been encoded in
//! fewer bytes is rejected. Two encodings of the same number must never both be
//! accepted, or "no trailing bytes after a record" becomes ambiguous and two
//! implementations can disagree about where a record ends. Nothing panics.

pub const MAX_VARINT_BYTES: usize = 10; // ceil(64 / 7)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// Ran off the end of the buffer mid-value.
    Truncated,
    /// Would not fit in a u64.
    Overflow,
    /// Non-canonical: encodable in fewer bytes.
    Overlong,
}

/// Append `value` as a canonical LEB128 varint.
pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read cursor over a record body. Every read is bounds-checked.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn read_u8(&mut self) -> Result<u8, VarintError> {
        let b = *self.buf.get(self.pos).ok_or(VarintError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], VarintError> {
        let end = self.pos.checked_add(n).ok_or(VarintError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(VarintError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read one canonical LEB128 unsigned varint.
    pub fn read_varint(&mut self) -> Result<u64, VarintError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        let mut count = 0usize;
        loop {
            let byte = self.read_u8()?;
            count += 1;
            if count > MAX_VARINT_BYTES {
                return Err(VarintError::Overflow);
            }
            let payload = (byte & 0x7f) as u64;
            // guard the final byte against shifting bits out of a u64
            if shift >= 64 || (shift == 63 && payload > 1) {
                return Err(VarintError::Overflow);
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                // canonical: a multi-byte encoding must not end in a 0 continuation
                if count > 1 && byte == 0 {
                    return Err(VarintError::Overlong);
                }
                return Ok(value);
            }
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_canonically() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let mut c = Cursor::new(&out);
            assert_eq!(c.read_varint().unwrap(), v);
            assert!(c.is_empty(), "no trailing bytes for {v}");
        }
    }

    #[test]
    fn rejects_overlong_and_truncated() {
        // 0x80 0x00 encodes 0 in two bytes -> overlong
        assert_eq!(Cursor::new(&[0x80, 0x00]).read_varint(), Err(VarintError::Overlong));
        // continuation bit set but no next byte
        assert_eq!(Cursor::new(&[0x80]).read_varint(), Err(VarintError::Truncated));
    }

    #[test]
    fn read_bytes_is_bounds_checked() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.read_bytes(2).unwrap(), &[1, 2]);
        assert_eq!(c.read_bytes(2), Err(VarintError::Truncated));
    }
}
