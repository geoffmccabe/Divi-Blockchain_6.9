//! LEB128 unsigned varints and a byte cursor (spec §4.4).
//!
//! Canonicality is enforced: a value that could have been encoded in fewer bytes
//! is rejected. Two encodings of the same number must never both be accepted, or
//! the "no trailing bytes" rule (§8) becomes ambiguous and implementations can
//! disagree about where a record ends.

/// ceil(64 / 7) -- the most bytes a u64 can occupy.
pub const MAX_VARINT_BYTES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// Ran off the end of the buffer mid-value.
    Truncated,
    /// Would not fit in a u64.
    Overflow,
    /// Non-canonical: encodable in fewer bytes.
    Overlong,
}

/// Read cursor over a record body. Every read is bounds-checked; nothing panics.
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

    /// Read one LEB128 unsigned varint.
    pub fn read_varint(&mut self) -> Result<u64, VarintError> {
        let mut value: u64 = 0u64;
        let mut shift = 0u32;
        let mut count = 0usize;

        loop {
            if count >= MAX_VARINT_BYTES {
                return Err(VarintError::Overflow);
            }
            let byte = self.read_u8()?;
            count += 1;

            let payload = u64::from(byte & 0x7f);
            // The final byte of a 10-byte encoding may only carry one bit.
            if shift >= 64 || (shift == 63 && payload > 1) {
                return Err(VarintError::Overflow);
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                // Canonical form: a multi-byte encoding must not end in a
                // zero payload, since that byte adds nothing.
                if count > 1 && payload == 0 {
                    return Err(VarintError::Overlong);
                }
                return Ok(value);
            }
            shift += 7;
        }
    }

    /// Read a varint that must fit a u32 (used for transaction indices).
    pub fn read_varint_u32(&mut self) -> Result<u32, VarintError> {
        u32::try_from(self.read_varint()?).map_err(|_| VarintError::Overflow)
    }
}

/// Encode a u64 as canonical LEB128. Used by tests and by record builders.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        encode_varint(v, &mut o);
        o
    }

    #[test]
    fn roundtrips_across_boundaries() {
        for v in [0u64, 1, 127, 128, 255, 16_383, 16_384, u32::MAX as u64, u64::MAX] {
            let bytes = enc(v);
            let mut c = Cursor::new(&bytes);
            assert_eq!(c.read_varint().unwrap(), v, "value {v}");
            assert!(c.is_empty(), "cursor should be drained for {v}");
        }
    }

    #[test]
    fn rejects_overlong_encoding() {
        // 0 encoded in two bytes -- canonical form is a single 0x00.
        let mut c = Cursor::new(&[0x80, 0x00]);
        assert_eq!(c.read_varint(), Err(VarintError::Overlong));
        // 1 encoded in two bytes.
        let mut c = Cursor::new(&[0x81, 0x00]);
        assert_eq!(c.read_varint(), Err(VarintError::Overlong));
    }

    #[test]
    fn rejects_truncated_and_overflow() {
        let mut c = Cursor::new(&[0x80]); // continuation bit set, nothing follows
        assert_eq!(c.read_varint(), Err(VarintError::Truncated));

        // 11 continuation bytes cannot be a u64.
        let too_long = [0x80u8; 11];
        let mut c = Cursor::new(&too_long);
        assert_eq!(c.read_varint(), Err(VarintError::Overflow));

        // u64::MAX + 1 -- final byte carries more than the one legal bit.
        let mut c = Cursor::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
        assert_eq!(c.read_varint(), Err(VarintError::Overflow));
    }

    #[test]
    fn u64_max_is_accepted() {
        let bytes = enc(u64::MAX);
        assert_eq!(bytes.len(), MAX_VARINT_BYTES);
        let mut c = Cursor::new(&bytes);
        assert_eq!(c.read_varint().unwrap(), u64::MAX);
    }

    #[test]
    fn reads_are_bounds_checked() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert!(c.read_bytes(4).is_err());
        assert_eq!(c.read_bytes(3).unwrap(), &[1, 2, 3]);
        assert!(c.read_u8().is_err());
    }
}
