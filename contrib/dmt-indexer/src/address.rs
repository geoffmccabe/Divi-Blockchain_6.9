//! Packed 21-byte addresses carried inside record payloads (spec §4.2).
//!
//! Recipients travel in the payload rather than as transaction outputs, so a
//! transfer creates nothing spendable -- which is what keeps staking away from
//! token state entirely (spec §1).

pub const PACKED_LEN: usize = 21;
pub const P2PKH: u8 = 0x00;
pub const P2SH: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub kind: u8,
    pub hash: [u8; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    WrongLength,
    UnknownKind(u8),
}

impl Address {
    pub fn parse(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.len() != PACKED_LEN {
            return Err(AddressError::WrongLength);
        }
        let kind = bytes[0];
        if kind != P2PKH && kind != P2SH {
            return Err(AddressError::UnknownKind(kind));
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[1..]);
        Ok(Self { kind, hash })
    }

    pub fn to_bytes(self) -> [u8; PACKED_LEN] {
        let mut out = [0u8; PACKED_LEN];
        out[0] = self.kind;
        out[1..].copy_from_slice(&self.hash);
        out
    }

    /// Stable lowercase hex, used in the state fingerprint and in logs.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(2 + 40);
        s.push_str(if self.kind == P2SH { "1:" } else { "0:" });
        for b in self.hash {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed(kind: u8) -> Vec<u8> {
        let mut v = vec![kind];
        v.extend_from_slice(&[0xabu8; 20]);
        v
    }

    #[test]
    fn parses_both_kinds_and_roundtrips() {
        for kind in [P2PKH, P2SH] {
            let raw = packed(kind);
            let a = Address::parse(&raw).unwrap();
            assert_eq!(a.kind, kind);
            assert_eq!(a.to_bytes().to_vec(), raw);
        }
    }

    #[test]
    fn rejects_bad_length_and_unknown_kind() {
        assert_eq!(Address::parse(&[0u8; 20]), Err(AddressError::WrongLength));
        assert_eq!(Address::parse(&[0u8; 22]), Err(AddressError::WrongLength));
        assert_eq!(
            Address::parse(&packed(0x09)),
            Err(AddressError::UnknownKind(0x09))
        );
    }

    #[test]
    fn hex_distinguishes_kinds_with_identical_hashes() {
        let a = Address::parse(&packed(P2PKH)).unwrap();
        let b = Address::parse(&packed(P2SH)).unwrap();
        assert_ne!(a.to_hex(), b.to_hex());
    }
}
