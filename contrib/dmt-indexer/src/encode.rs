//! Building records, rather than reading them.
//!
//! `DMT-WALLET-INTERFACE.md` §3 asks for exactly this split: **the crate that
//! defines a record's meaning owns its encoding, and the wallet owns funding and
//! signing.** The alternative is the wallet reimplementing these layouts, which
//! is two implementations of one format and therefore, eventually, two formats.
//! `dvxp-core` exists to prevent that between indexers; this module prevents it
//! between the indexer and the wallet.
//!
//! ## What a caller does with the result
//!
//! These return the **payload** only: the DVXP envelope plus the record body.
//! The caller wraps it in an `OP_META` output, selects inputs, signs and
//! broadcasts. That is DD69's `dvxp.rs`, which already does the same for Proof of
//! Existence and Divi Names.
//!
//! ## The coin-selection trap (read this before writing a send)
//!
//! **A record's sender is the address that funds `vin[0]`.** Not the wallet, not
//! the change address, not "whoever signed": that one input's previous output.
//! So a wallet that lets ordinary coin selection pick inputs will usually fund a
//! token transfer out of a change address that holds no tokens. The record is
//! then perfectly well formed, gets mined, costs a fee, and is **ignored**,
//! because the sender does not own what it is trying to move. Nothing tells the
//! user. Their balance simply does not change.
//!
//! This is not hypothetical. The first end-to-end run of this encoder against a
//! real chain lost three records exactly that way, with the indexer reporting
//! "insufficient balance" and "only the issuer may lock supply" for a wallet
//! that held plenty of both.
//!
//! So: **coin selection for a token record must be constrained to the address
//! that holds the tokens**, and change must return to that same address or the
//! next record loses its sender too. [`crate::validate`] catches this before the
//! fee is spent, which is most of why it exists.
//!
//! ## Refusing early
//!
//! Every function returns `Result`, and the checks are the ones the indexer
//! itself would apply when reading the record back. A record that would be
//! ignored on the way in is not worth a transaction fee on the way out, and
//! "the network took your money and did nothing" is the worst possible way to
//! learn that a ticker was invalid.
//!
//! This is not the same thing as knowing a record will be **accepted**: that
//! depends on ledger state (does the ticker already exist, is the commit deep
//! enough, was the fee paid) which encoding cannot see. [`crate::validate`]
//! answers that half.

use dvxp_core::codec::Address;
use dvxp_core::varint::write_varint;
use dvxp_core::{MAGIC, SUPPORTED_VERSION, TYPE_DMT};

use crate::record::issue::{
    Issue, FLAG_METADATA, FLAG_OPEN_MINT, FLAG_RISING_PRICE, FLAG_SUPPLY_LOCKED, FLAGS_RESERVED,
    MAX_DECIMALS,
};
use crate::record::simple::COMMITMENT_LEN;
use crate::record::transfer::{Group, Payout, Transfer};
use crate::record::{
    TokenId, SUB_BURN, SUB_ISSUE, SUB_ISSUER_TRANSFER, SUB_LOCK_SUPPLY, SUB_MINT, SUB_NAME_COMMIT,
    SUB_TICKER_TRANSFER, SUB_TRANSFER,
};
use crate::ticker;

/// The payload budget for one `OP_META` output.
///
/// Divi's whole-script limit is 603 bytes, 7.5 times Bitcoin's, which is what
/// makes an airdrop to many recipients fit in one record at all. This is that
/// minus the opcode and a `PUSHDATA1` prefix, with headroom.
pub const MAX_PAYLOAD_BYTES: usize = 596;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// The record is larger than one data output can carry. For a transfer this
    /// is a real limit worth surfacing: an airdrop has a maximum size, and a
    /// caller must split it rather than have the record silently truncated.
    TooLarge { bytes: usize, max: usize },
    /// A field the parser would refuse.
    Invalid(&'static str),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLarge { bytes, max } => {
                write!(f, "record is {bytes} bytes; one output holds {max}")
            }
            EncodeError::Invalid(why) => write!(f, "{why}"),
        }
    }
}

/// Wrap a body in the shared envelope and check it fits.
fn envelope(subtype: u8, body: Vec<u8>) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(body.len() + 7);
    out.extend_from_slice(&MAGIC);
    out.push(SUPPORTED_VERSION);
    out.push(TYPE_DMT);
    out.push(subtype);
    out.extend_from_slice(&body);

    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(EncodeError::TooLarge { bytes: out.len(), max: MAX_PAYLOAD_BYTES });
    }
    Ok(out)
}

fn write_token(out: &mut Vec<u8>, token: TokenId) {
    write_varint(out, token.height);
    write_varint(out, token.tx_index as u64);
}

// ---------------------------------------------------------------------------
// ISSUE
// ---------------------------------------------------------------------------

/// Create a token.
///
/// The flag combinations refused here are the ones the parser refuses, checked
/// in the same order and for the same reasons, so a caller cannot build a
/// record that this crate would then ignore.
pub fn issue(i: &Issue) -> Result<Vec<u8>, EncodeError> {
    if i.flags & FLAGS_RESERVED != 0 {
        return Err(EncodeError::Invalid("reserved flag bit set"));
    }
    // Supply cannot be both frozen and mintable. Refusing rather than picking
    // one keeps the intent with the person who has it.
    if i.flags & FLAG_SUPPLY_LOCKED != 0 && i.has(crate::record::issue::FLAG_ISSUER_MINTABLE) {
        return Err(EncodeError::Invalid("supply cannot be both locked and mintable"));
    }
    let open_mint = i.flags & FLAG_OPEN_MINT != 0;
    if !open_mint && (i.flags & (crate::record::issue::FLAG_PROCEEDS_BURNED | FLAG_RISING_PRICE)) != 0
    {
        return Err(EncodeError::Invalid("mint modifier without an open mint"));
    }
    if i.decimals > MAX_DECIMALS {
        return Err(EncodeError::Invalid("decimals out of range"));
    }
    if open_mint != i.terms.is_some() {
        return Err(EncodeError::Invalid("open mint needs terms, and terms need an open mint"));
    }
    if i.has(FLAG_METADATA) != i.metadata_ptr.is_some() {
        return Err(EncodeError::Invalid("metadata flag and pointer must agree"));
    }

    let mut body = Vec::new();
    body.push(i.flags);
    body.push(i.decimals);

    if i.ticker.is_empty() {
        // No name at all is a legitimate token: it still has a canonical
        // numeric id, and the ticker is separately priced.
        if i.salt.is_some() {
            return Err(EncodeError::Invalid("a salt without a ticker means nothing"));
        }
        body.push(0);
    } else {
        ticker::validate(&i.ticker).map_err(|_| EncodeError::Invalid("invalid or reserved ticker"))?;
        let salt = i.salt.ok_or(EncodeError::Invalid("a ticker needs its commit salt"))?;
        let len = u8::try_from(i.ticker.len())
            .map_err(|_| EncodeError::Invalid("ticker too long"))?;
        body.push(len);
        body.extend_from_slice(&i.ticker);
        body.extend_from_slice(&salt);
    }

    write_varint(&mut body, i.premine);

    if let Some(t) = &i.terms {
        if t.per_mint == 0 {
            return Err(EncodeError::Invalid("per-mint amount must be positive"));
        }
        if t.height_end != 0 && t.height_end < t.height_start {
            return Err(EncodeError::Invalid("the mint window ends before it starts"));
        }
        if i.premine.checked_add(t.cap).is_none() {
            return Err(EncodeError::Invalid("premine plus cap overflows"));
        }
        write_varint(&mut body, t.cap);
        write_varint(&mut body, t.per_mint);
        write_varint(&mut body, t.height_start);
        write_varint(&mut body, t.height_end);
        write_varint(&mut body, t.mint_price);
        if i.flags & FLAG_RISING_PRICE != 0 {
            if t.mint_price == 0 {
                return Err(EncodeError::Invalid("a rising price needs a base price"));
            }
            write_varint(&mut body, t.price_step);
        } else if t.price_step != 0 {
            // Silently dropping it would produce a record that means something
            // other than what the caller asked for.
            return Err(EncodeError::Invalid("a price step needs the rising-price flag"));
        }
    }

    if let Some(p) = i.metadata_ptr {
        body.extend_from_slice(&p);
    }

    envelope(SUB_ISSUE, body)
}

/// The commitment for a ticker: `Hash160(salt ‖ ticker)`.
///
/// Re-exported from the ledger so a wallet computes it exactly as the indexer
/// will when checking the reveal. Two implementations of this would mean a
/// commit that never matches its own issue.
pub use crate::ledger::commitment_of;

/// Reserve a ticker, roughly twelve minutes before revealing it.
///
/// This is front-running protection, not a delay to apologise for: it converts a
/// mempool race, which an attacker wins by paying a higher fee, into a 12-block
/// reorg, which Divi's hard 100-block cap makes impossible.
pub fn name_commit(commitment: &[u8; COMMITMENT_LEN]) -> Result<Vec<u8>, EncodeError> {
    envelope(SUB_NAME_COMMIT, commitment.to_vec())
}

// ---------------------------------------------------------------------------
// TRANSFER
// ---------------------------------------------------------------------------

/// Move units, to one recipient or many.
///
/// Groups must be in strictly ascending token order and each group's height is
/// written as a delta from the previous one. Both are the parser's rules, and
/// both exist to make an airdrop fit: sorting is what lets the delta be small.
/// Rather than make callers do that, this sorts for them and refuses only what
/// is genuinely ambiguous, namely the same token listed twice.
pub fn transfer(t: &Transfer) -> Result<Vec<u8>, EncodeError> {
    if t.groups.is_empty() {
        return Err(EncodeError::Invalid("a transfer with no groups moves nothing"));
    }

    let mut groups = t.groups.clone();
    groups.sort_by_key(|g| (g.token.height, g.token.tx_index));
    for pair in groups.windows(2) {
        if pair[0].token == pair[1].token {
            return Err(EncodeError::Invalid("the same token appears in two groups"));
        }
    }

    let mut body = Vec::new();
    write_varint(&mut body, groups.len() as u64);

    let mut previous: Option<TokenId> = None;
    for g in &groups {
        if g.payouts.is_empty() {
            return Err(EncodeError::Invalid("a group with no recipients"));
        }
        let delta = match previous {
            None => g.token.height,
            Some(p) => g.token.height - p.height, // sorted, so this cannot wrap
        };
        write_varint(&mut body, delta);
        write_varint(&mut body, g.token.tx_index as u64);
        previous = Some(g.token);

        write_varint(&mut body, g.payouts.len() as u64);
        for p in &g.payouts {
            if p.amount == 0 {
                return Err(EncodeError::Invalid("a zero-amount payout"));
            }
            write_varint(&mut body, p.amount);
            p.to.write(&mut body);
        }
    }

    envelope(SUB_TRANSFER, body)
}

/// The common case: send one token to one address.
pub fn send(token: TokenId, amount: u64, to: Address) -> Result<Vec<u8>, EncodeError> {
    transfer(&Transfer { groups: vec![Group { token, payouts: vec![Payout { amount, to }] }] })
}

/// How many recipients still fit in a one-token airdrop of this size.
///
/// Worth asking before building the record rather than after: a caller batching
/// an airdrop needs to know where to split, and finding out by encoding and
/// catching [`EncodeError::TooLarge`] means throwing work away.
pub fn remaining_payout_capacity(t: &Transfer) -> Result<usize, EncodeError> {
    let used = transfer(t)?.len();
    // A payout is an amount varint plus a 21-byte address. Assume the widest
    // plausible amount rather than the current one, so the answer stays true if
    // later payouts are larger.
    const WIDEST_PAYOUT: usize = 10 + 21;
    Ok((MAX_PAYLOAD_BYTES - used) / WIDEST_PAYOUT)
}

// ---------------------------------------------------------------------------
// The simple records
// ---------------------------------------------------------------------------

/// Claim from an open mint. `recipient` absent means credit the sender.
pub fn mint(token: TokenId, recipient: Option<Address>) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    write_token(&mut body, token);
    if let Some(a) = recipient {
        a.write(&mut body);
    }
    envelope(SUB_MINT, body)
}

/// Destroy units. The only record that ever does.
pub fn burn(token: TokenId, amount: u64) -> Result<Vec<u8>, EncodeError> {
    if amount == 0 {
        return Err(EncodeError::Invalid("a zero-amount burn destroys nothing"));
    }
    let mut body = Vec::new();
    write_token(&mut body, token);
    write_varint(&mut body, amount);
    envelope(SUB_BURN, body)
}

/// Freeze the supply permanently. Irreversible, and does not stop a running
/// open mint.
pub fn lock_supply(token: TokenId) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    write_token(&mut body, token);
    envelope(SUB_LOCK_SUPPLY, body)
}

/// Hand over issuer rights, ticker included.
pub fn issuer_transfer(token: TokenId, new_issuer: Address) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    write_token(&mut body, token);
    new_issuer.write(&mut body);
    envelope(SUB_ISSUER_TRANSFER, body)
}

/// Hand over a ticker that does not yet name a token.
///
/// Only valid while unused: once a ticker names a live token it freezes, or
/// whoever held it could rename a token under its holders' feet and every wallet
/// would follow.
pub fn ticker_transfer(name: &[u8], new_owner: Address) -> Result<Vec<u8>, EncodeError> {
    ticker::validate_charset(name).map_err(|_| EncodeError::Invalid("invalid ticker"))?;
    let len = u8::try_from(name.len()).map_err(|_| EncodeError::Invalid("ticker too long"))?;
    let mut body = Vec::new();
    body.push(len);
    body.extend_from_slice(name);
    new_owner.write(&mut body);
    envelope(SUB_TICKER_TRANSFER, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::issue::{MintTerms, METADATA_PTR_LEN, SALT_LEN};
    use crate::{parse_payload, Outcome, Record};

    fn who(tag: u8) -> Address {
        Address { kind: dvxp_core::codec::ADDRESS_P2PKH, hash160: [tag; 20] }
    }

    /// Every encoder is checked by parsing its own output back with the real
    /// parser and comparing. That is the only test that actually proves the two
    /// halves agree; asserting on byte strings would just be this module
    /// restating itself.
    fn round_trip(payload: Vec<u8>) -> Record {
        match parse_payload(&payload).expect("a record we built must not halt the indexer") {
            Outcome::Record(r) => r,
            Outcome::Skip(why) => panic!("our own record was skipped: {why:?}"),
        }
    }

    fn plain_issue(premine: u64) -> Issue {
        Issue {
            flags: 0,
            decimals: 0,
            ticker: Vec::new(),
            salt: None,
            premine,
            terms: None,
            metadata_ptr: None,
        }
    }

    #[test]
    fn an_issue_round_trips() {
        let i = plain_issue(1000);
        assert_eq!(round_trip(issue(&i).unwrap()), Record::Issue(i));
    }

    #[test]
    fn a_named_issue_round_trips_with_its_salt() {
        let mut i = plain_issue(5);
        i.ticker = b"HELLO".to_vec();
        i.salt = Some([0x11; SALT_LEN]);
        assert_eq!(round_trip(issue(&i).unwrap()), Record::Issue(i));
    }

    #[test]
    fn an_open_mint_round_trips_including_a_rising_price() {
        let mut i = plain_issue(0);
        i.flags = FLAG_OPEN_MINT | FLAG_RISING_PRICE;
        i.terms = Some(MintTerms {
            cap: 21_000,
            per_mint: 10,
            height_start: 100,
            height_end: 200,
            mint_price: 5_000,
            price_step: 7,
        });
        assert_eq!(round_trip(issue(&i).unwrap()), Record::Issue(i));
    }

    #[test]
    fn metadata_round_trips_when_the_flag_says_so() {
        let mut i = plain_issue(1);
        i.flags = FLAG_METADATA;
        i.metadata_ptr = Some([0xab; METADATA_PTR_LEN]);
        assert_eq!(round_trip(issue(&i).unwrap()), Record::Issue(i));
    }

    #[test]
    fn contradictory_issues_are_refused_before_they_cost_a_fee() {
        let mut locked_and_mintable = plain_issue(1);
        locked_and_mintable.flags =
            FLAG_SUPPLY_LOCKED | crate::record::issue::FLAG_ISSUER_MINTABLE;
        assert!(issue(&locked_and_mintable).is_err());

        let mut modifier_without_mint = plain_issue(1);
        modifier_without_mint.flags = FLAG_RISING_PRICE;
        assert!(issue(&modifier_without_mint).is_err());

        let mut terms_without_flag = plain_issue(1);
        terms_without_flag.terms = Some(MintTerms {
            cap: 1,
            per_mint: 1,
            height_start: 0,
            height_end: 0,
            mint_price: 0,
            price_step: 0,
        });
        assert!(terms_without_flag.flags & FLAG_OPEN_MINT == 0);
        assert!(issue(&terms_without_flag).is_err());

        let mut too_many_decimals = plain_issue(1);
        too_many_decimals.decimals = MAX_DECIMALS + 1;
        assert!(issue(&too_many_decimals).is_err());

        let mut ticker_without_salt = plain_issue(1);
        ticker_without_salt.ticker = b"HELLO".to_vec();
        assert!(issue(&ticker_without_salt).is_err());

        let mut reserved_ticker = plain_issue(1);
        reserved_ticker.ticker = b"DIVI".to_vec();
        reserved_ticker.salt = Some([0; SALT_LEN]);
        assert!(issue(&reserved_ticker).is_err(), "a reserved ticker cannot be claimed");
    }

    #[test]
    fn a_single_send_round_trips() {
        let token = TokenId { height: 4_131_200, tx_index: 3 };
        let r = round_trip(send(token, 250, who(9)).unwrap());
        match r {
            Record::Transfer(t) => {
                assert_eq!(t.groups.len(), 1);
                assert_eq!(t.groups[0].token, token);
                assert_eq!(t.groups[0].payouts[0].amount, 250);
                assert_eq!(t.groups[0].payouts[0].to, who(9));
            }
            other => panic!("expected a transfer, got {other:?}"),
        }
    }

    /// Groups have to ascend, and the parser refuses them otherwise. Rather
    /// than make every caller sort, the encoder does, so an out-of-order input
    /// produces a valid record instead of a rejected one.
    #[test]
    fn groups_are_sorted_rather_than_refused() {
        let high = TokenId { height: 900, tx_index: 0 };
        let low = TokenId { height: 100, tx_index: 2 };
        let t = Transfer {
            groups: vec![
                Group { token: high, payouts: vec![Payout { amount: 1, to: who(1) }] },
                Group { token: low, payouts: vec![Payout { amount: 2, to: who(2) }] },
            ],
        };
        match round_trip(transfer(&t).unwrap()) {
            Record::Transfer(out) => {
                assert_eq!(out.groups[0].token, low, "ascending order, as the parser demands");
                assert_eq!(out.groups[1].token, high);
            }
            other => panic!("expected a transfer, got {other:?}"),
        }
    }

    #[test]
    fn the_same_token_twice_is_ambiguous_and_refused() {
        let token = TokenId { height: 100, tx_index: 0 };
        let t = Transfer {
            groups: vec![
                Group { token, payouts: vec![Payout { amount: 1, to: who(1) }] },
                Group { token, payouts: vec![Payout { amount: 2, to: who(2) }] },
            ],
        };
        assert!(transfer(&t).is_err());
    }

    /// An airdrop has a real ceiling, and a caller batching one needs to know
    /// where to split rather than discovering it by failing.
    #[test]
    fn an_airdrop_fills_the_output_and_then_says_so() {
        let token = TokenId { height: 100, tx_index: 0 };
        let mut payouts = Vec::new();
        for i in 0..15u8 {
            payouts.push(Payout { amount: 1_000, to: who(i) });
        }
        let t = Transfer { groups: vec![Group { token, payouts }] };
        let encoded = transfer(&t).unwrap();
        assert!(encoded.len() <= MAX_PAYLOAD_BYTES);
        assert!(remaining_payout_capacity(&t).unwrap() > 0);

        // Enough recipients and it stops fitting, with a message that says what
        // to do about it rather than a truncated record.
        let mut too_many = Vec::new();
        for i in 0..40u8 {
            too_many.push(Payout { amount: 1_000_000, to: who(i) });
        }
        let big = Transfer { groups: vec![Group { token, payouts: too_many }] };
        assert!(matches!(transfer(&big), Err(EncodeError::TooLarge { .. })));
    }

    #[test]
    fn the_simple_records_round_trip() {
        let token = TokenId { height: 7, tx_index: 2 };

        assert_eq!(
            round_trip(burn(token, 250).unwrap()),
            Record::Burn(crate::record::simple::Burn { token, amount: 250 })
        );
        assert_eq!(
            round_trip(lock_supply(token).unwrap()),
            Record::LockSupply(crate::record::simple::TokenRef { token })
        );
        assert_eq!(
            round_trip(mint(token, None).unwrap()),
            Record::Mint(crate::record::simple::Mint { token, recipient: None })
        );
        assert_eq!(
            round_trip(mint(token, Some(who(4))).unwrap()),
            Record::Mint(crate::record::simple::Mint { token, recipient: Some(who(4)) })
        );
        assert_eq!(
            round_trip(issuer_transfer(token, who(5)).unwrap()),
            Record::IssuerTransfer(crate::record::simple::IssuerTransfer {
                token,
                new_issuer: who(5)
            })
        );
        assert_eq!(
            round_trip(ticker_transfer(b"HELLO", who(6)).unwrap()),
            Record::TickerTransfer(crate::record::simple::TickerTransfer {
                ticker: b"HELLO".to_vec(),
                new_owner: who(6)
            })
        );
    }

    #[test]
    fn a_commit_matches_the_issue_it_commits_to() {
        let salt = [0x11u8; SALT_LEN];
        let name = b"HELLO";
        let c = commitment_of(&salt, name);

        match round_trip(name_commit(&c).unwrap()) {
            Record::NameCommit(n) => assert_eq!(n.commitment, c),
            other => panic!("expected a commit, got {other:?}"),
        }

        // The property that matters: the commit a wallet publishes is derived
        // exactly as the indexer will derive it when checking the reveal.
        let mut i = plain_issue(0);
        i.ticker = name.to_vec();
        i.salt = Some(salt);
        match round_trip(issue(&i).unwrap()) {
            Record::Issue(back) => {
                assert_eq!(commitment_of(&back.salt.unwrap(), &back.ticker), c);
            }
            other => panic!("expected an issue, got {other:?}"),
        }
    }

    #[test]
    fn zero_amounts_are_refused_on_the_way_out_as_well_as_in() {
        let token = TokenId { height: 1, tx_index: 0 };
        assert!(burn(token, 0).is_err());
        assert!(send(token, 0, who(1)).is_err());
    }
}
