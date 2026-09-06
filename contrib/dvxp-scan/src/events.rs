//! What happened, as opposed to what is true now.
//!
//! The ledgers hold current state: who owns what, how much exists. Neither
//! retains any history, so "show me my token activity" had nothing to read. The
//! scanner is the only place that sees both the record and the transaction that
//! carried it, so it is the right place to record events.
//!
//! ## Events are neutral about perspective
//!
//! A transfer is recorded once, with a `from` and a `to`. It is deliberately
//! **not** recorded as "transfer-in" or "transfer-out", because which one it is
//! depends entirely on whose history is being asked for, and the same transfer
//! is an out for the sender and an in for the recipient. Baking a direction in
//! at write time would mean storing it twice and getting it wrong for anyone
//! else. The direction is derived at query time in [`crate::query`].
//!
//! ## Events are reorg-aware
//!
//! Every event carries the height that produced it, and a rollback discards
//! everything above the fork point. An event log that outlived its block would
//! report activity the chain no longer contains.

use dmt_indexer::ledger::state::AddrKey;

/// A token id as the ledger keys it: the issuing transaction's `(height, tx_index)`.
pub type TokenKey = (u64, u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEventKind {
    Issue,
    Mint,
    Transfer,
    Burn,
}

impl TokenEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenEventKind::Issue => "issue",
            TokenEventKind::Mint => "mint",
            TokenEventKind::Transfer => "transfer",
            TokenEventKind::Burn => "burn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEvent {
    pub token: TokenKey,
    pub kind: TokenEventKind,
    /// Where the units came from. `None` for an issue or a mint, which create
    /// them.
    pub from: Option<AddrKey>,
    /// Where they went. `None` for a burn, which destroys them.
    pub to: Option<AddrKey>,
    pub amount: u64,
    pub height: u64,
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub block_time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfdEventKind {
    Mint,
    Transfer,
    CollectionCreate,
}

impl NfdEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            NfdEventKind::Mint => "mint",
            NfdEventKind::Transfer => "transfer",
            NfdEventKind::CollectionCreate => "collection-create",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfdEvent {
    /// The collectible's id, or the collection's id for a collection event.
    pub id: [u8; 32],
    pub kind: NfdEventKind,
    pub from: Option<AddrKey>,
    pub to: Option<AddrKey>,
    pub height: u64,
    pub txid: [u8; 32],
    pub block_time: i64,
}

/// Everything the scanner records that the protocol ledgers do not.
///
/// Two things live here rather than in the rules crates. The **event log**,
/// because history is not state and the ledgers deliberately hold only the
/// latter. And the **genesis txid** of each token, because a token is keyed by
/// `(height, tx_index)` and the ledger never sees the transaction hash, yet
/// every explorer link needs it.
#[derive(Debug, Default)]
pub struct EventLog {
    tokens: Vec<TokenEvent>,
    nfds: Vec<NfdEvent>,
    token_genesis: std::collections::BTreeMap<TokenKey, [u8; 32]>,
}

impl EventLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_token(&mut self, e: TokenEvent) {
        self.tokens.push(e);
    }

    pub fn push_nfd(&mut self, e: NfdEvent) {
        self.nfds.push(e);
    }

    pub fn record_token_genesis(&mut self, token: TokenKey, txid: [u8; 32]) {
        self.token_genesis.insert(token, txid);
    }

    pub fn token_genesis(&self, token: TokenKey) -> Option<[u8; 32]> {
        self.token_genesis.get(&token).copied()
    }

    /// Newest first, which is the order every history view wants.
    pub fn token_events(&self) -> impl Iterator<Item = &TokenEvent> {
        self.tokens.iter().rev()
    }

    pub fn nfd_events(&self) -> impl Iterator<Item = &NfdEvent> {
        self.nfds.iter().rev()
    }

    pub fn token_event_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn nfd_event_count(&self) -> usize {
        self.nfds.len()
    }

    /// Discard everything a reorg removed.
    ///
    /// A token issued in a discarded block also loses its genesis txid, because
    /// the token id is derived from the height that no longer contains it.
    pub fn rollback_above(&mut self, height: u64) {
        self.tokens.retain(|e| e.height <= height);
        self.nfds.retain(|e| e.height <= height);
        self.token_genesis.retain(|(h, _), _| *h <= height);
    }
}
