//! DMT record types and subtype dispatch (spec §5).
//!
//! The envelope, varints, addresses and object ids all come from `dvxp-core`,
//! which PoE, NFD and DMT share. That sharing is the point: one classifier and
//! one set of codecs means two indexers cannot disagree about what a record
//! *is* — only about what it *means*, and the meaning lives here.
//!
//! ## Adding a new record type later
//!
//!   1. add a `SUB_*` constant,
//!   2. add a variant to [`Record`],
//!   3. write `parse` in its own module,
//!   4. add one arm to the `match` in [`Record::parse`].
//!
//! Nothing else in the parser changes. Per spec §8, a new subtype also needs a
//! version bump and a published activation height — it must never appear
//! silently, or two indexers will disagree.

pub mod issue;
pub mod simple;
pub mod transfer;

use dvxp_core::codec::{Address, ObjectId};
use dvxp_core::varint::{Cursor, VarintError};
use dvxp_core::Ignored;

pub const SUB_ISSUE: u8 = 0x01;
pub const SUB_TRANSFER: u8 = 0x02;
pub const SUB_MINT: u8 = 0x03;
pub const SUB_NAME_COMMIT: u8 = 0x04;
pub const SUB_BURN: u8 = 0x05;
pub const SUB_LOCK_SUPPLY: u8 = 0x06;
pub const SUB_ISSUER_TRANSFER: u8 = 0x07;
pub const SUB_TICKER_TRANSFER: u8 = 0x08;

/// A token's permanent identity: where its ISSUE was mined (spec §4.3).
/// Shared with every other DVXP protocol, so a token and an NFD are named the
/// same way.
pub type TokenId = ObjectId;

/// Sort key for canonical group ordering. `ObjectId` is deliberately not `Ord`
/// in the shared crate, so the comparison is spelled out once here rather than
/// re-derived (differently) in each protocol.
pub(crate) fn order_key(id: TokenId) -> (u64, u32) {
    (id.height, id.tx_index)
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
    /// Parse a DMT body. The caller has already established that this is a
    /// well-formed DVXP envelope of a supported version, of type `TYPE_DMT`.
    pub fn parse(subtype: u8, body: &[u8]) -> Result<Record, Ignored> {
        match subtype {
            SUB_ISSUE => issue::parse(body).map(Record::Issue),
            SUB_TRANSFER => transfer::parse(body).map(Record::Transfer),
            SUB_MINT => simple::parse_mint(body).map(Record::Mint),
            SUB_NAME_COMMIT => simple::parse_name_commit(body).map(Record::NameCommit),
            SUB_BURN => simple::parse_burn(body).map(Record::Burn),
            SUB_LOCK_SUPPLY => simple::parse_lock_supply(body).map(Record::LockSupply),
            SUB_ISSUER_TRANSFER => simple::parse_issuer_transfer(body).map(Record::IssuerTransfer),
            SUB_TICKER_TRANSFER => simple::parse_ticker_transfer(body).map(Record::TickerTransfer),
            other => Err(Ignored::UnknownSubtype(other)),
        }
    }
}

// ---- shared reader helpers -------------------------------------------------

pub(crate) fn malformed(_e: VarintError) -> Ignored {
    Ignored::Malformed("bad integer or truncated body")
}

pub(crate) fn read_token_id(c: &mut Cursor<'_>) -> Result<TokenId, Ignored> {
    ObjectId::read(c).map_err(malformed)
}

pub(crate) fn read_address(c: &mut Cursor<'_>) -> Result<Address, Ignored> {
    Address::read(c).map_err(malformed)
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

    #[test]
    fn unknown_subtype_is_ignored_not_fatal() {
        for sub in [0x00u8, 0x09, 0x7f, 0xff] {
            assert_eq!(Record::parse(sub, &[]), Err(Ignored::UnknownSubtype(sub)));
        }
    }

    #[test]
    fn order_key_sorts_by_height_then_index() {
        let a = order_key(TokenId { height: 1, tx_index: 9 });
        let b = order_key(TokenId { height: 2, tx_index: 0 });
        let c = order_key(TokenId { height: 1, tx_index: 10 });
        assert!(a < b);
        assert!(a < c);
        assert!(c < b);
    }
}
