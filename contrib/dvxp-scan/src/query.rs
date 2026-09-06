//! The read side: the questions a wallet and an explorer actually ask.
//!
//! Shaped to match `Divi-Desktop-6.9/docs/DMT-WALLET-INTERFACE.md` §2, which is
//! the front end's half of the contract and already has a UI coded against it.
//! Deliberately pure, so the wallet can answer these from its own embedded
//! indexer without an HTTP server anywhere in the picture.
//!
//! ## Amounts are integers, always
//!
//! Every amount here is an integer in the token's smallest unit. Never a float,
//! never pre-divided by `decimals`. The UI divides for display only. Getting
//! this wrong is how token wallets end up off by powers of ten, and a rounding
//! error in someone's balance is not a cosmetic bug.
//!
//! ## Direction is derived, not stored
//!
//! A transfer is one event with a `from` and a `to`. Whether it is an "in" or an
//! "out" depends on whose history is being asked for, so [`history`] decides
//! that per query rather than the log storing it twice and getting it wrong for
//! everyone else.

use dmt_indexer::fees;
use dmt_indexer::ledger::state::AddrKey;
use dmt_indexer::record::issue::FLAG_OPEN_MINT;

use crate::driver::Overlay;
use crate::events::{TokenEventKind, TokenKey};

/// How a token id is written for people: `height:tx_index`.
pub fn token_id_string(t: TokenKey) -> String {
    format!("{}:{}", t.0, t.1)
}

/// Parse that form back. Returns `None` rather than guessing at anything else.
pub fn parse_token_id(s: &str) -> Option<TokenKey> {
    let (h, i) = s.split_once(':')?;
    Some((h.parse().ok()?, i.parse().ok()?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBalance {
    pub token: TokenKey,
    /// Smallest unit. Integer, always.
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMeta {
    pub token: TokenKey,
    /// Empty when the token was issued without claiming a ticker.
    pub ticker: Vec<u8>,
    pub decimals: u8,
    /// Units in existence: premine plus minted, minus burns.
    pub total_supply: u64,
    /// `None` means uncapped.
    pub max_supply: Option<u64>,
    pub supply_locked: bool,
    pub issuer: AddrKey,
    pub mint_open: bool,
    /// The issuing transaction, so the UI can link to the explorer. `None` only
    /// if the issue happened before this index started.
    pub genesis_txid: Option<[u8; 32]>,
    /// Pointer to off-chain metadata, where a human-readable name and artwork
    /// live if the issuer published any.
    ///
    /// **The chain carries no display name.** It carries a ticker. Anything
    /// richer is behind this pointer, and a caller that has not resolved it
    /// should show the ticker rather than invent a name.
    pub metadata_ptr: Option<[u8; 32]>,
}

/// One line of someone's token history, from their point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub kind: HistoryKind,
    pub token: TokenKey,
    /// The other party, when there is one.
    pub counterparty: Option<AddrKey>,
    pub amount: u64,
    pub height: u64,
    pub txid: [u8; 32],
    pub block_time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    Issue,
    Mint,
    TransferIn,
    TransferOut,
    Burn,
}

impl HistoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HistoryKind::Issue => "issue",
            HistoryKind::Mint => "mint",
            HistoryKind::TransferIn => "transfer-in",
            HistoryKind::TransferOut => "transfer-out",
            HistoryKind::Burn => "burn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickerStatus {
    pub taken: bool,
    pub owner: Option<AddrKey>,
    /// Already naming a live token, and therefore frozen: whoever holds it can
    /// no longer move it, or they could rename a token under its holders' feet.
    pub bound: bool,
    /// Registration price in duffs, scaled by ticker length. `None` when the
    /// ticker is not a registrable length or charset.
    pub price_duffs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTermsView {
    /// What the next claim costs, including any rising-price step.
    pub next_price_duffs: u64,
    /// `None` means unlimited.
    pub cap: Option<u64>,
    pub minted: u64,
    pub remaining: Option<u64>,
    pub per_mint: u64,
    pub height_start: u64,
    /// 0 means no end.
    pub height_end: u64,
    /// Whether a claim would be accepted at this height right now.
    pub open_now: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfdView {
    pub id: [u8; 32],
    pub owner: AddrKey,
    pub arweave_ptr: [u8; 32],
    pub content_hash: [u8; 32],
    pub thumb_ptr: Option<[u8; 32]>,
    pub collection_id: Option<[u8; 32]>,
    pub mint_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionView {
    pub id: [u8; 32],
    pub creator: AddrKey,
    /// 0 means uncapped.
    pub max_supply: u32,
    pub meta_ptr: [u8; 32],
    pub minted: u32,
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// Everything the given addresses hold. One call, not one per address: a wallet
/// has many addresses and a round trip each would be absurd.
///
/// Zero balances are omitted. A row that says you hold none of something is not
/// a holding.
pub fn balances(o: &Overlay, addresses: &[AddrKey]) -> Vec<TokenBalance> {
    let mut out: Vec<TokenBalance> = Vec::new();
    for ((token, addr), amount) in &o.dmt.ledger.state.balances {
        if *amount == 0 || !addresses.contains(addr) {
            continue;
        }
        match out.iter_mut().find(|b| b.token == *token) {
            // A wallet's own addresses are one purse as far as the user is
            // concerned, so holdings of the same token are summed.
            Some(existing) => existing.amount = existing.amount.saturating_add(*amount),
            None => out.push(TokenBalance { token: *token, amount: *amount }),
        }
    }
    out.sort_by_key(|b| b.token);
    out
}

pub fn token_meta(o: &Overlay, token: TokenKey) -> Option<TokenMeta> {
    let t = o.dmt.ledger.state.tokens.get(&token)?;
    Some(TokenMeta {
        token,
        ticker: t.ticker.clone(),
        decimals: t.decimals,
        total_supply: t.circulating,
        max_supply: t.terms.as_ref().and_then(|m| (m.cap != 0).then_some(m.cap)),
        supply_locked: t.supply_locked,
        issuer: dmt_indexer::ledger::state::addr_key(t.issuer),
        mint_open: t.has(FLAG_OPEN_MINT),
        genesis_txid: o.log.token_genesis(token),
        metadata_ptr: t.metadata_ptr,
    })
}

/// Batch, so a balance list renders in one round trip instead of N.
pub fn tokens_meta(o: &Overlay, tokens: &[TokenKey]) -> Vec<TokenMeta> {
    tokens.iter().filter_map(|t| token_meta(o, *t)).collect()
}

/// Every token the index knows about, oldest first.
pub fn all_tokens(o: &Overlay) -> Vec<TokenMeta> {
    o.dmt.ledger.state.tokens.keys().filter_map(|t| token_meta(o, *t)).collect()
}

/// Someone's token history, newest first, from their point of view.
pub fn history(o: &Overlay, addresses: &[AddrKey], limit: usize) -> Vec<HistoryEntry> {
    let mut out = Vec::new();
    for e in o.log.token_events() {
        if out.len() >= limit {
            break;
        }
        let mine_from = e.from.map(|a| addresses.contains(&a)).unwrap_or(false);
        let mine_to = e.to.map(|a| addresses.contains(&a)).unwrap_or(false);
        if !mine_from && !mine_to {
            continue;
        }

        // Direction decided here, per asker. A transfer between two of your own
        // addresses is an outgoing line, because that is what you did.
        let (kind, counterparty) = match e.kind {
            TokenEventKind::Issue => (HistoryKind::Issue, None),
            TokenEventKind::Mint => (HistoryKind::Mint, None),
            TokenEventKind::Burn => (HistoryKind::Burn, None),
            TokenEventKind::Transfer if mine_from => (HistoryKind::TransferOut, e.to),
            TokenEventKind::Transfer => (HistoryKind::TransferIn, e.from),
        };

        out.push(HistoryEntry {
            kind,
            token: e.token,
            counterparty,
            amount: e.amount,
            height: e.height,
            txid: e.txid,
            block_time: e.block_time,
        });
    }
    out
}

/// Everything that ever happened to one token, newest first.
pub fn token_history(o: &Overlay, token: TokenKey, limit: usize) -> Vec<HistoryEntry> {
    o.log
        .token_events()
        .filter(|e| e.token == token)
        .take(limit)
        .map(|e| HistoryEntry {
            kind: match e.kind {
                TokenEventKind::Issue => HistoryKind::Issue,
                TokenEventKind::Mint => HistoryKind::Mint,
                TokenEventKind::Burn => HistoryKind::Burn,
                TokenEventKind::Transfer => HistoryKind::TransferOut,
            },
            token: e.token,
            counterparty: e.to.or(e.from),
            amount: e.amount,
            height: e.height,
            txid: e.txid,
            block_time: e.block_time,
        })
        .collect()
}

/// Is this ticker available, and what would it cost?
///
/// Asked before a user commits to a name, so it has to answer honestly for a
/// ticker that is registered but not yet attached to a token: still taken.
pub fn ticker_status(o: &Overlay, ticker: &[u8]) -> TickerStatus {
    match o.dmt.ledger.state.tickers.get(ticker) {
        Some(t) => TickerStatus {
            taken: true,
            owner: Some(dmt_indexer::ledger::state::addr_key(t.owner)),
            bound: t.is_bound(),
            price_duffs: fees::ticker_fee_duffs(ticker.len()),
        },
        None => TickerStatus {
            taken: false,
            owner: None,
            bound: false,
            price_duffs: fees::ticker_fee_duffs(ticker.len()),
        },
    }
}

/// Whether an open mint is live, and what a claim costs right now.
pub fn mint_terms(o: &Overlay, token: TokenKey, at_height: u64) -> Option<MintTermsView> {
    let t = o.dmt.ledger.state.tokens.get(&token)?;
    let terms = t.terms.as_ref()?;
    let started = terms.height_start == 0 || at_height >= terms.height_start;
    let ended = terms.height_end != 0 && at_height > terms.height_end;
    let remaining = t.remaining_cap();

    Some(MintTermsView {
        next_price_duffs: t.next_price(),
        cap: (terms.cap != 0).then_some(terms.cap),
        minted: t.minted,
        remaining,
        per_mint: terms.per_mint,
        height_start: terms.height_start,
        height_end: terms.height_end,
        open_now: t.has(FLAG_OPEN_MINT)
            && started
            && !ended
            && remaining.map(|r| r > 0).unwrap_or(true),
    })
}

/// What the overlay did in one block.
///
/// Exists so a block page is one request rather than one per transaction. A
/// block with two hundred transactions asking "is this one a collectible?" two
/// hundred times would make the index the slowest part of the explorer, and the
/// event log already has the answer indexed by height.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockActivity {
    /// Collectibles minted in this block, newest first within the block.
    pub minted: Vec<NfdView>,
    /// Collectibles that changed hands.
    pub transferred: Vec<NfdView>,
    /// Collections created.
    pub collections: Vec<[u8; 32]>,
    /// Tokens whose state moved, and how.
    pub token_events: Vec<HistoryEntry>,
}

impl BlockActivity {
    pub fn is_empty(&self) -> bool {
        self.minted.is_empty()
            && self.transferred.is_empty()
            && self.collections.is_empty()
            && self.token_events.is_empty()
    }
}

/// The same question, asked about one transaction.
///
/// A transaction page cannot answer this from its txid alone: a MINT's txid is
/// the collectible's id, but a TRANSFER's is not, so "look it up as an id" finds
/// mints and silently misses every transfer. The event log is keyed on the
/// transaction that carried each record, which is the only thing that catches
/// both.
pub fn tx_activity(o: &Overlay, txid: &[u8; 32]) -> BlockActivity {
    use crate::events::NfdEventKind;

    let mut out = BlockActivity::default();

    for e in o.log.nfd_events().filter(|e| &e.txid == txid) {
        match e.kind {
            NfdEventKind::Mint => {
                if let Some(n) = nfd(o, &e.id) {
                    out.minted.push(n);
                }
            }
            NfdEventKind::Transfer => {
                if let Some(n) = nfd(o, &e.id) {
                    out.transferred.push(n);
                }
            }
            NfdEventKind::CollectionCreate => out.collections.push(e.id),
        }
    }

    for e in o.log.token_events().filter(|e| &e.txid == txid) {
        out.token_events.push(HistoryEntry {
            kind: match e.kind {
                TokenEventKind::Issue => HistoryKind::Issue,
                TokenEventKind::Mint => HistoryKind::Mint,
                TokenEventKind::Burn => HistoryKind::Burn,
                TokenEventKind::Transfer => HistoryKind::TransferOut,
            },
            token: e.token,
            counterparty: e.to.or(e.from),
            amount: e.amount,
            height: e.height,
            txid: e.txid,
            block_time: e.block_time,
        });
    }

    out
}

pub fn block_activity(o: &Overlay, height: u64) -> BlockActivity {
    use crate::events::NfdEventKind;

    let mut out = BlockActivity::default();

    for e in o.log.nfd_events().filter(|e| e.height == height) {
        match e.kind {
            NfdEventKind::Mint => {
                if let Some(n) = nfd(o, &e.id) {
                    out.minted.push(n);
                }
            }
            NfdEventKind::Transfer => {
                if let Some(n) = nfd(o, &e.id) {
                    out.transferred.push(n);
                }
            }
            NfdEventKind::CollectionCreate => out.collections.push(e.id),
        }
    }

    for e in o.log.token_events().filter(|e| e.height == height) {
        out.token_events.push(HistoryEntry {
            kind: match e.kind {
                TokenEventKind::Issue => HistoryKind::Issue,
                TokenEventKind::Mint => HistoryKind::Mint,
                TokenEventKind::Burn => HistoryKind::Burn,
                // No asker, so no direction to derive. A block page is showing
                // what the block did, not what it did to anyone in particular.
                TokenEventKind::Transfer => HistoryKind::TransferOut,
            },
            token: e.token,
            counterparty: e.to.or(e.from),
            amount: e.amount,
            height: e.height,
            txid: e.txid,
            block_time: e.block_time,
        });
    }

    out
}

/// Headline counts, for a front page.
///
/// "Holders" and "creators" are counted as distinct addresses rather than as
/// rows, because a person who holds three tokens is one holder, and a table
/// length would flatter the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub tokens: usize,
    /// Distinct addresses holding a non-zero balance of anything.
    pub token_holders: usize,
    pub collectibles: usize,
    pub collections: usize,
    /// Distinct addresses that have minted a collectible.
    pub creators: usize,
}

pub fn stats(o: &Overlay) -> Stats {
    use crate::events::NfdEventKind;
    use std::collections::BTreeSet;

    let holders: BTreeSet<&AddrKey> = o
        .dmt
        .ledger
        .state
        .balances
        .iter()
        .filter(|(_, amount)| **amount > 0)
        .map(|((_, addr), _)| addr)
        .collect();

    let creators: BTreeSet<AddrKey> = o
        .log
        .nfd_events()
        .filter(|e| e.kind == NfdEventKind::Mint)
        .filter_map(|e| e.to)
        .collect();

    Stats {
        tokens: o.dmt.ledger.state.tokens.len(),
        token_holders: holders.len(),
        collectibles: o.nfd.count(),
        collections: o.nfd.collection_count(),
        creators: creators.len(),
    }
}

// ---------------------------------------------------------------------------
// Collectibles
// ---------------------------------------------------------------------------

pub fn nfd(o: &Overlay, id: &[u8; 32]) -> Option<NfdView> {
    let n = o.nfd.get(id)?;
    let mut owner = [0u8; 21];
    owner.copy_from_slice(&n.owner);
    Some(NfdView {
        id: *id,
        owner: (owner[0], {
            let mut h = [0u8; 20];
            h.copy_from_slice(&owner[1..21]);
            h
        }),
        arweave_ptr: n.arweave_ptr,
        content_hash: n.content_hash,
        thumb_ptr: n.thumb_ptr,
        collection_id: n.collection_id,
        mint_height: n.mint_height,
    })
}

/// The most recently minted collectibles, newest first.
///
/// Walks the event log rather than the ledger because the ledger is a map with
/// no notion of order, and "latest" is the first thing any explorer front page
/// wants. The log is already in block order, so this is a scan and not a sort.
pub fn recent_nfds(o: &Overlay, limit: usize) -> Vec<NfdView> {
    use crate::events::NfdEventKind;
    o.log
        .nfd_events()
        .filter(|e| e.kind == NfdEventKind::Mint)
        .filter_map(|e| nfd(o, &e.id))
        .take(limit)
        .collect()
}

/// Free-text search over collectibles.
///
/// Deliberately narrow: an id prefix, or an owner. There is no name to search
/// because the chain carries none, and pretending otherwise by matching against
/// off-chain metadata we have not fetched would return results the index cannot
/// stand behind.
pub fn search_nfds(o: &Overlay, needle: &str, limit: usize) -> Vec<NfdView> {
    let needle = needle.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return recent_nfds(o, limit);
    }

    let by_owner = crate::query::hex_to_addr(&needle);

    o.log
        .nfd_events()
        .filter_map(|e| nfd(o, &e.id))
        .filter(|n| {
            if let Some(a) = by_owner {
                return n.owner == a;
            }
            hex_lower(&n.id).starts_with(&needle)
                || n.collection_id.map(|c| hex_lower(&c) == needle).unwrap_or(false)
        })
        .take(limit)
        .collect()
}

fn hex_lower(b: &[u8; 32]) -> String {
    // Display order, matching what a user copies out of the explorer.
    b.iter().rev().map(|x| format!("{x:02x}")).collect()
}

/// Parse the `kind:hash160` form the API emits for addresses, so a search can
/// round-trip a value the user copied off one of our own pages.
pub fn hex_to_addr(s: &str) -> Option<AddrKey> {
    let (kind, hash) = s.split_once(':')?;
    let kind: u8 = kind.parse().ok()?;
    if hash.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(hash.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some((kind, out))
}

pub fn nfds_owned_by(o: &Overlay, addr: AddrKey) -> Vec<NfdView> {
    let mut packed = [0u8; 21];
    packed[0] = addr.0;
    packed[1..].copy_from_slice(&addr.1);
    o.nfd.owned_by(&packed).iter().filter_map(|id| nfd(o, id)).collect()
}

pub fn collection(o: &Overlay, id: &[u8; 32]) -> Option<CollectionView> {
    let c = o.nfd.collection_of(id)?;
    let mut creator = [0u8; 21];
    creator.copy_from_slice(&c.creator);
    Some(CollectionView {
        id: *id,
        creator: (creator[0], {
            let mut h = [0u8; 20];
            h.copy_from_slice(&creator[1..21]);
            h
        }),
        max_supply: c.max_supply,
        meta_ptr: c.meta_ptr,
        minted: c.minted,
    })
}

/// Collectibles minted into one collection.
///
/// Walks the event log rather than the ledger, because a collection's members
/// are only discoverable from the mints that named it.
pub fn collection_members(o: &Overlay, id: &[u8; 32]) -> Vec<NfdView> {
    let mut out: Vec<NfdView> = o
        .log
        .nfd_events()
        .filter_map(|e| nfd(o, &e.id))
        .filter(|n| n.collection_id.as_ref() == Some(id))
        .collect();
    out.sort_by_key(|n| n.id);
    out.dedup_by_key(|n| n.id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_ids_round_trip_in_the_form_people_read() {
        assert_eq!(token_id_string((4_131_200, 3)), "4131200:3");
        assert_eq!(parse_token_id("4131200:3"), Some((4_131_200, 3)));
        assert_eq!(parse_token_id("nonsense"), None);
        assert_eq!(parse_token_id("4131200"), None);
        assert_eq!(parse_token_id("4131200:x"), None);
    }

    #[test]
    fn an_empty_index_answers_without_inventing_anything() {
        let o = Overlay::new();
        assert!(balances(&o, &[(0, [1; 20])]).is_empty());
        assert!(all_tokens(&o).is_empty());
        assert_eq!(token_meta(&o, (1, 0)), None);
        assert_eq!(mint_terms(&o, (1, 0), 100), None);
        assert!(history(&o, &[(0, [1; 20])], 50).is_empty());
    }

    #[test]
    fn an_unregistered_ticker_is_free_but_still_priced() {
        let o = Overlay::new();
        let s = ticker_status(&o, b"HELLO");
        assert!(!s.taken);
        assert_eq!(s.owner, None);
        assert!(s.price_duffs.is_some(), "a price is quoted before anyone commits");
    }
}
