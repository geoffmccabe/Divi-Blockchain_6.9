//! The small fixed-shape records: MINT, NAME COMMIT, BURN, LOCK SUPPLY,
//! ISSUER TRANSFER, TICKER TRANSFER (spec §5.3–§5.7, §7.5).
//!
//! Grouped because each is two or three fields. A record that grows beyond that
//! should move to its own module.

use super::{ensure_drained, malformed, read_address, read_token_id, TokenId};
use crate::address::Address;
use crate::envelope::Ignored;
use crate::ticker;
use crate::varint::Cursor;

pub const COMMITMENT_LEN: usize = 20;

/// MINT (0x03). Amount comes from the issuance terms, so it is not carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mint {
    pub token: TokenId,
    /// Absent means "credit the sender".
    pub recipient: Option<Address>,
}

/// NAME COMMIT (0x04) -- `Hash160(salt ‖ ticker)` (spec §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCommit {
    pub commitment: [u8; COMMITMENT_LEN],
}

/// BURN (0x05) -- the only record that ever destroys units (spec §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burn {
    pub token: TokenId,
    pub amount: u64,
}

/// LOCK SUPPLY (0x06) -- issuer-only, irreversible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRef {
    pub token: TokenId,
}

/// ISSUER TRANSFER (0x07) -- hand over issuer rights, ticker included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerTransfer {
    pub token: TokenId,
    pub new_issuer: Address,
}

/// TICKER TRANSFER (0x08) -- only valid while the ticker is unused (spec §7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickerTransfer {
    pub ticker: Vec<u8>,
    pub new_owner: Address,
}

pub fn parse_mint(body: &[u8]) -> Result<Mint, Ignored> {
    let mut c = Cursor::new(body);
    let token = read_token_id(&mut c)?;
    let recipient = if c.is_empty() { None } else { Some(read_address(&mut c)?) };
    ensure_drained(&c)?;
    Ok(Mint { token, recipient })
}

pub fn parse_name_commit(body: &[u8]) -> Result<NameCommit, Ignored> {
    let mut c = Cursor::new(body);
    let mut commitment = [0u8; COMMITMENT_LEN];
    commitment.copy_from_slice(c.read_bytes(COMMITMENT_LEN).map_err(malformed)?);
    ensure_drained(&c)?;
    Ok(NameCommit { commitment })
}

pub fn parse_burn(body: &[u8]) -> Result<Burn, Ignored> {
    let mut c = Cursor::new(body);
    let token = read_token_id(&mut c)?;
    let amount = c.read_varint().map_err(malformed)?;
    if amount == 0 {
        return Err(Ignored::RuleViolation("zero-amount burn"));
    }
    ensure_drained(&c)?;
    Ok(Burn { token, amount })
}

pub fn parse_lock_supply(body: &[u8]) -> Result<TokenRef, Ignored> {
    let mut c = Cursor::new(body);
    let token = read_token_id(&mut c)?;
    ensure_drained(&c)?;
    Ok(TokenRef { token })
}

pub fn parse_issuer_transfer(body: &[u8]) -> Result<IssuerTransfer, Ignored> {
    let mut c = Cursor::new(body);
    let token = read_token_id(&mut c)?;
    let new_issuer = read_address(&mut c)?;
    ensure_drained(&c)?;
    Ok(IssuerTransfer { token, new_issuer })
}

pub fn parse_ticker_transfer(body: &[u8]) -> Result<TickerTransfer, Ignored> {
    let mut c = Cursor::new(body);
    let len = c.read_u8().map_err(malformed)? as usize;
    let ticker = c.read_bytes(len).map_err(malformed)?.to_vec();
    // Charset only: a reserved name can never have been registered, so it can
    // never be transferred either, and reporting "invalid" is the honest reason.
    ticker::validate_charset(&ticker).map_err(|_| Ignored::RuleViolation("invalid ticker"))?;
    let new_owner = read_address(&mut c)?;
    ensure_drained(&c)?;
    Ok(TickerTransfer { ticker, new_owner })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_varint;

    fn addr_bytes() -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(&[0x77; 20]);
        v
    }

    fn token_bytes(block: u64, idx: u32) -> Vec<u8> {
        let mut v = Vec::new();
        encode_varint(block, &mut v);
        encode_varint(idx as u64, &mut v);
        v
    }

    #[test]
    fn mint_recipient_is_optional() {
        let bare = token_bytes(10, 1);
        let m = parse_mint(&bare).unwrap();
        assert_eq!(m.token, TokenId { block: 10, tx_index: 1 });
        assert!(m.recipient.is_none(), "absent recipient means credit the sender");

        let mut with = token_bytes(10, 1);
        with.extend_from_slice(&addr_bytes());
        assert!(parse_mint(&with).unwrap().recipient.is_some());

        // A partial address is truncation, not "no recipient".
        let mut partial = token_bytes(10, 1);
        partial.extend_from_slice(&addr_bytes()[..10]);
        assert!(parse_mint(&partial).is_err());
    }

    #[test]
    fn name_commit_is_exactly_twenty_bytes() {
        let ok = [0x5au8; COMMITMENT_LEN];
        assert_eq!(parse_name_commit(&ok).unwrap().commitment, ok);
        assert!(parse_name_commit(&[0u8; 19]).is_err());
        assert_eq!(parse_name_commit(&[0u8; 21]), Err(Ignored::TrailingBytes));
    }

    #[test]
    fn burn_rejects_zero() {
        let mut v = token_bytes(3, 0);
        encode_varint(0, &mut v);
        assert!(matches!(parse_burn(&v), Err(Ignored::RuleViolation(_))));

        let mut ok = token_bytes(3, 0);
        encode_varint(42, &mut ok);
        assert_eq!(parse_burn(&ok).unwrap().amount, 42);
    }

    #[test]
    fn lock_supply_and_issuer_transfer_roundtrip() {
        assert_eq!(
            parse_lock_supply(&token_bytes(9, 4)).unwrap().token,
            TokenId { block: 9, tx_index: 4 }
        );

        let mut v = token_bytes(9, 4);
        v.extend_from_slice(&addr_bytes());
        let it = parse_issuer_transfer(&v).unwrap();
        assert_eq!(it.token, TokenId { block: 9, tx_index: 4 });
        assert_eq!(it.new_issuer.hash, [0x77; 20]);
        // Missing the address is truncation.
        assert!(parse_issuer_transfer(&token_bytes(9, 4)).is_err());
    }

    #[test]
    fn ticker_transfer_validates_the_name() {
        let mut ok = vec![4u8];
        ok.extend_from_slice(b"GOLD");
        ok.extend_from_slice(&addr_bytes());
        assert_eq!(parse_ticker_transfer(&ok).unwrap().ticker, b"GOLD");

        let mut bad = vec![4u8];
        bad.extend_from_slice(b"gold");
        bad.extend_from_slice(&addr_bytes());
        assert!(matches!(parse_ticker_transfer(&bad), Err(Ignored::RuleViolation(_))));

        // Declared length longer than the body must truncate, not panic.
        let mut lying = vec![200u8];
        lying.extend_from_slice(b"GOLD");
        assert!(parse_ticker_transfer(&lying).is_err());
    }

    #[test]
    fn every_parser_rejects_trailing_bytes() {
        let mut m = token_bytes(1, 1);
        m.push(0xff);
        // A single trailing byte is not a valid address either.
        assert!(parse_mint(&m).is_err());

        let mut l = token_bytes(1, 1);
        l.push(0x00);
        assert_eq!(parse_lock_supply(&l), Err(Ignored::TrailingBytes));
    }
}
