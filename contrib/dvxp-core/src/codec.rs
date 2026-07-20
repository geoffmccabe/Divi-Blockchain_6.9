//! Shared payload encodings every overlay protocol uses identically.
//!
//! * [`Address`] — a Divi address inside a record body (21 bytes), so recipients
//!   ride in the payload, never as a spendable output that staking could eat.
//! * [`ObjectId`] — the permanent id of an on-chain object (a DMT token, an NFD)
//!   = the (block height, transaction index) of the record that created it.
//!   Deterministic, compact, collision-free, assigned by chain position.

use crate::varint::{write_varint, Cursor, VarintError};

/// A Divi address as it appears in a record body: 1 type byte + 20-byte hash160.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    /// 0x00 = P2PKH, 0x01 = P2SH.
    pub kind: u8,
    pub hash160: [u8; 20],
}

pub const ADDRESS_P2PKH: u8 = 0x00;
pub const ADDRESS_P2SH: u8 = 0x01;
pub const ADDRESS_LEN: usize = 21;

impl Address {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.hash160);
    }

    pub fn read(c: &mut Cursor) -> Result<Address, VarintError> {
        let kind = c.read_u8()?;
        let hash = c.read_bytes(20)?;
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(hash);
        Ok(Address { kind, hash160 })
    }
}

/// Permanent object id: (block height, tx index within that block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub height: u64,
    pub tx_index: u32,
}

impl ObjectId {
    pub fn write(&self, out: &mut Vec<u8>) {
        write_varint(out, self.height);
        write_varint(out, self.tx_index as u64);
    }

    pub fn read(c: &mut Cursor) -> Result<ObjectId, VarintError> {
        let height = c.read_varint()?;
        let tx_index = c.read_varint()?;
        if tx_index > u32::MAX as u64 {
            return Err(VarintError::Overflow);
        }
        Ok(ObjectId { height, tx_index: tx_index as u32 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrips() {
        let a = Address { kind: ADDRESS_P2SH, hash160: [7u8; 20] };
        let mut buf = Vec::new();
        a.write(&mut buf);
        assert_eq!(buf.len(), ADDRESS_LEN);
        assert_eq!(Address::read(&mut Cursor::new(&buf)).unwrap(), a);
    }

    #[test]
    fn object_id_roundtrips() {
        let id = ObjectId { height: 4_120_000, tx_index: 3 };
        let mut buf = Vec::new();
        id.write(&mut buf);
        let mut c = Cursor::new(&buf);
        assert_eq!(ObjectId::read(&mut c).unwrap(), id);
        assert!(c.is_empty());
    }
}
