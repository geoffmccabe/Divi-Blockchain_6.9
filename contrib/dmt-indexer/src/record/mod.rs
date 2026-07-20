//! Record types and subtype dispatch (spec §5).
//!
//! ## Adding a new record type later
//!
//! This layer is deliberately shaped so a new idea is a local change:
//!   1. add a `SUB_*` constant below,
//!   2. add a variant to `Record`,
//!   3. write `parse` in its own module,
//!   4. add one arm to the `match` in `Record::parse`.
//!
//! Nothing else in the indexer needs editing to *parse* a new record. Applying
//! it to state is a separate, equally local change in `ledger`. Per spec §8, a
//! new subtype also requires a version bump and a published activation height --
//! it must never appear silently, or two indexers will disagree.

pub mod issue;
pub mod simple;
pub mod transfer;

use crate::address::Address;
use crate::envelope::{Envelope, Ignored};
use crate::varint::{Cursor, VarintError};

pub const SUB_ISSUE: u8 = 0x01;
pub const SUB_TRANSFER: u8 = 0x02;
pub const SUB_MINT: u8 = 0x03;
pub const SUB_NAME_COMMIT: u8 = 0x04;
pub const SUB_BURN: u8 = 0x05;
pub const SUB_LOCK_SUPPLY: u8 = 0x06;
pub const SUB_ISSUER_TRANSFER: u8 = 0x07;
pub const SUB_TICKER_TRANSFER: u8 = 0x08;

/// A token's permanent identity: where its ISSUE was mined (spec §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId {
    pub block: u64,
    pub tx_index: u32,
}

impl TokenId {
    pub fn to_hex(self) -> String {
        format!("{:x}:{:x}", self.block, self.tx_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Issue(issue::Issue),
    Transfer(transfer::Transfer),
    Mint(simple::Mint),
    NameCommit(simple::NameCommit),
    Burn(simple::Burn),
    LockSupply(simple::TokenRef),
    IssuerTransfer(simple::IssuerTransfer),
    TickerTransfer(simple::TickerTransfer),
}

impl Record {
    pub fn parse(env: &Envelope<'_>) -> Result<Record, Ignored> {
        match env.subtype {
            SUB_ISSUE => issue::parse(env.body).map(Record::Issue),
            SUB_TRANSFER => transfer::parse(env.body).map(Record::Transfer),
            SUB_MINT => simple::parse_mint(env.body).map(Record::Mint),
            SUB_NAME_COMMIT => simple::parse_name_commit(env.body).map(Record::NameCommit),
            SUB_BURN => simple::parse_burn(env.body).map(Record::Burn),
            SUB_LOCK_SUPPLY => simple::parse_lock_supply(env.body).map(Record::LockSupply),
            SUB_ISSUER_TRANSFER => {
                simple::parse_issuer_transfer(env.body).map(Record::IssuerTransfer)
            }
            SUB_TICKER_TRANSFER => {
                simple::parse_ticker_transfer(env.body).map(Record::TickerTransfer)
            }
            other => Err(Ignored::UnknownSubtype(other)),
        }
    }
}

// ---- shared reader helpers -------------------------------------------------

pub(crate) fn malformed(_e: VarintError) -> Ignored {
    Ignored::Malformed("bad integer or truncated body")
}

pub(crate) fn read_token_id(c: &mut Cursor<'_>) -> Result<TokenId, Ignored> {
    let block = c.read_varint().map_err(malformed)?;
    let tx_index = c.read_varint_u32().map_err(malformed)?;
    Ok(TokenId { block, tx_index })
}

pub(crate) fn read_address(c: &mut Cursor<'_>) -> Result<Address, Ignored> {
    let bytes = c
        .read_bytes(crate::address::PACKED_LEN)
        .map_err(malformed)?;
    Address::parse(bytes).map_err(|_| Ignored::Malformed("bad packed address"))
}

/// Every record must consume its body exactly. Trailing bytes are ignored
/// rather than tolerated, so a record has one unambiguous encoding (spec §8).
pub(crate) fn ensure_drained(c: &Cursor<'_>) -> Result<(), Ignored> {
    if c.is_empty() {
        Ok(())
    } else {
        Err(Ignored::TrailingBytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope;

    fn env(subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = envelope::MAGIC.to_vec();
        v.extend_from_slice(&[envelope::SUPPORTED_VERSION, envelope::TYPE_DMT, subtype]);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn unknown_subtype_is_ignored_not_fatal() {
        for sub in [0x00u8, 0x09, 0x7f, 0xff] {
            let raw = env(sub, &[]);
            let e = envelope::classify(&raw).unwrap().unwrap();
            assert_eq!(Record::parse(&e), Err(Ignored::UnknownSubtype(sub)));
        }
    }

    #[test]
    fn token_id_hex_is_stable() {
        let id = TokenId { block: 255, tx_index: 16 };
        assert_eq!(id.to_hex(), "ff:10");
    }
}
