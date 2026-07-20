//! Block boundaries, the chained state fingerprint, and reorg rollback
//! (spec §9.2, §9.4).
//!
//! ## Why the window is provably sufficient here
//!
//! Divi hard-caps reorganisations at **100 blocks**, so retaining 200 blocks of
//! undo data is not a guess — it is twice the deepest reorg the chain permits.
//! Bitcoin indexers cannot make that claim and have to pick a number and hope;
//! `ord` keeps roughly 10 blocks and aborts beyond it.
//!
//! ## Why we halt instead of guessing
//!
//! If a rollback is ever requested beyond the retained window, the indexer
//! **stops** rather than serving state it cannot justify. An indexer that stops
//! and asks to be resynced is unavailable, which is recoverable; one that
//! silently serves wrong balances is divergence, which is not.

use super::state::Undo;
use super::Ledger;
use dvxp_core::registry::Fingerprint;
use std::collections::VecDeque;

/// Blocks of undo data retained. Divi's max reorg is 100 (see module docs).
pub const UNDO_DEPTH: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReorgError {
    /// Asked to roll back further than the retained window allows.
    BeyondUndoWindow { requested: u64, oldest: u64 },
    /// Asked to roll back a height that was never applied.
    NotApplied(u64),
}

/// One applied block: what it changed, and the fingerprint after it.
#[derive(Debug, Clone)]
pub struct BlockRecord {
    pub height: u64,
    pub undo: Vec<Undo>,
    pub fingerprint: Fingerprint,
}

/// A ledger plus its block history — the part that can follow a live chain.
#[derive(Debug)]
pub struct Chain {
    pub ledger: Ledger,
    history: VecDeque<BlockRecord>,
    fingerprint: Fingerprint,
    tip: Option<u64>,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    pub fn new() -> Self {
        Self {
            ledger: Ledger::new(),
            history: VecDeque::new(),
            fingerprint: Fingerprint::genesis(),
            tip: None,
        }
    }

    pub fn tip(&self) -> Option<u64> {
        self.tip
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Oldest height still revertible.
    pub fn oldest_undo_height(&self) -> Option<u64> {
        self.history.front().map(|b| b.height)
    }

    /// Close the block at `height`: journal what it changed and advance the
    /// chained fingerprint.
    ///
    /// The journal supplies which keys changed; the fingerprint hashes their
    /// values *after* the block, in sorted order. Two indexers replaying the
    /// same blocks therefore produce the same fingerprint, and any divergence
    /// shows up immediately and permanently rather than years later. Because
    /// it hashes resulting state rather than the sequence of writes, an
    /// implementation that reaches the same ledger by a different route still
    /// agrees — which is what makes it a useful cross-check between
    /// independent implementations rather than a check that they share code.
    pub fn end_block(&mut self, height: u64) -> Fingerprint {
        let undo = self.ledger.state.take_pending();
        let deltas = encode_deltas(&self.ledger.state, &undo);
        self.fingerprint = self.fingerprint.advance(height, &deltas);

        self.history.push_back(BlockRecord {
            height,
            undo,
            fingerprint: self.fingerprint,
        });
        while self.history.len() > UNDO_DEPTH {
            self.history.pop_front();
        }
        self.tip = Some(height);
        self.fingerprint
    }

    /// Fingerprint recorded after a given block, if still retained. This is what
    /// two operators compare to check they agree.
    pub fn fingerprint_at(&self, height: u64) -> Option<Fingerprint> {
        self.history
            .iter()
            .find(|b| b.height == height)
            .map(|b| b.fingerprint)
    }

    /// Roll back every block above `height`, restoring exact prior state.
    pub fn rollback_to(&mut self, height: u64) -> Result<(), ReorgError> {
        let Some(tip) = self.tip else {
            return Err(ReorgError::NotApplied(height));
        };
        if height > tip {
            return Err(ReorgError::NotApplied(height));
        }
        if height == tip {
            return Ok(());
        }
        // Rolling back TO `height` means the block at `height` must still be
        // retained, so its fingerprint can be restored.
        if let Some(oldest) = self.oldest_undo_height() {
            if height < oldest {
                return Err(ReorgError::BeyondUndoWindow { requested: height, oldest });
            }
        }

        while let Some(last) = self.history.back() {
            if last.height <= height {
                break;
            }
            let block = self.history.pop_back().expect("checked above");
            self.ledger.state.revert(&block.undo);
        }

        // Anything the reverted blocks staged but never closed must not leak
        // into the next block's journal.
        self.ledger.state.clear_pending();

        self.fingerprint = self
            .history
            .back()
            .map(|b| b.fingerprint)
            .unwrap_or_else(Fingerprint::genesis);
        self.tip = self.history.back().map(|b| b.height).or(Some(height));
        Ok(())
    }
}

/// Canonical bytes for one block's changes, fed to the fingerprint.
///
/// **The undo journal supplies the set of keys that changed; the values come
/// from state AFTER the block.** Hashing the before-images alone is not enough
/// and was a real bug caught by `different_history_gives_a_different_fingerprint`:
/// sending 10 and sending 11 from the same starting balance touch the same keys
/// and have identical before-images, so two genuinely divergent ledgers would
/// have published matching fingerprints — the exact failure the fingerprint
/// exists to detect.
///
/// Using the changed keys rather than the whole ledger keeps the cost
/// proportional to what moved, so an indexer with a million holders still
/// fingerprints a quiet block in microseconds.
///
/// Keys are sorted and de-duplicated first, so a block that touches the same
/// key twice hashes identically to one that touches it once with the same
/// result — the fingerprint attests to resulting state, not to the path taken.
fn encode_deltas(state: &super::state::State, undo: &[Undo]) -> Vec<u8> {
    let mut balances: Vec<&((u64, u32), super::state::AddrKey)> = Vec::new();
    let mut tokens: Vec<&(u64, u32)> = Vec::new();
    let mut tickers: Vec<&Vec<u8>> = Vec::new();
    let mut commits: Vec<&[u8; 20]> = Vec::new();

    for u in undo {
        match u {
            Undo::Balance { key, .. } => balances.push(key),
            Undo::Token { key, .. } => tokens.push(key),
            Undo::Ticker { name, .. } => tickers.push(name),
            Undo::Commit { hash, .. } => commits.push(hash),
        }
    }
    balances.sort_unstable();
    balances.dedup();
    tokens.sort_unstable();
    tokens.dedup();
    tickers.sort_unstable();
    tickers.dedup();
    commits.sort_unstable();
    commits.dedup();

    let mut out = Vec::new();
    for key in balances {
        out.push(0x01);
        let ((h, ix), (kind, hash)) = key;
        out.extend_from_slice(&h.to_be_bytes());
        out.extend_from_slice(&ix.to_be_bytes());
        out.push(*kind);
        out.extend_from_slice(hash);
        match state.balances.get(key) {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
            }
            None => out.push(0),
        }
    }
    for key in tokens {
        out.push(0x02);
        out.extend_from_slice(&key.0.to_be_bytes());
        out.extend_from_slice(&key.1.to_be_bytes());
        match state.tokens.get(key) {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.circulating.to_be_bytes());
                out.extend_from_slice(&t.minted.to_be_bytes());
                out.extend_from_slice(&t.claims.to_be_bytes());
                out.push(t.flags);
                out.push(u8::from(t.supply_locked));
                out.push(t.issuer.kind);
                out.extend_from_slice(&t.issuer.hash160);
            }
            None => out.push(0),
        }
    }
    for name in tickers {
        out.push(0x03);
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(name);
        match state.tickers.get(name) {
            Some(t) => {
                out.push(1);
                out.push(t.owner.kind);
                out.extend_from_slice(&t.owner.hash160);
                match t.bound_to {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(&id.height.to_be_bytes());
                        out.extend_from_slice(&id.tx_index.to_be_bytes());
                    }
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
    }
    for hash in commits {
        out.push(0x04);
        out.extend_from_slice(hash);
        match state.commits.get(hash) {
            Some(c) => {
                out.push(1);
                out.push(c.committer.kind);
                out.extend_from_slice(&c.committer.hash160);
                out.extend_from_slice(&c.height.to_be_bytes());
            }
            None => out.push(0),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::tests_support::*;
    use crate::record::Record;

    #[test]
    fn a_reverted_block_restores_exact_prior_state() {
        let mut c = Chain::new();
        let id = seed_token(&mut c.ledger, who(1), 1000, 0);
        c.end_block(100);
        let before = format!("{:?}", c.ledger.state);
        let fp_before = c.fingerprint();

        c.ledger
            .apply(&Record::Transfer(send(id, 400, who(2))), &ctx(101, 0, who(1)))
            .unwrap();
        c.end_block(101);
        assert_eq!(c.ledger.state.balance(id, who(2)), 400);
        assert_ne!(c.fingerprint().hex(), fp_before.hex(), "state changed");

        c.rollback_to(100).unwrap();
        assert_eq!(c.ledger.state.balance(id, who(1)), 1000);
        assert_eq!(c.ledger.state.balance(id, who(2)), 0);
        assert_eq!(format!("{:?}", c.ledger.state), before, "exact restoration");
        assert_eq!(c.fingerprint().hex(), fp_before.hex(), "fingerprint rewinds too");
    }

    #[test]
    fn a_reverted_issuance_removes_the_token_and_its_ticker() {
        let mut c = Chain::new();
        c.end_block(99);
        let issue = named_issue(b"GOLD", 5);
        c.ledger
            .apply(&Record::NameCommit(commit_for(&issue)), &ctx(100, 0, who(1)))
            .unwrap();
        c.end_block(100);
        c.ledger.apply(&Record::Issue(issue), &ctx(120, 0, who(1))).unwrap();
        c.end_block(120);
        assert!(c.ledger.state.tickers.contains_key(b"GOLD".as_slice()));

        // Undo the issuance: token gone, ticker released, commit restored.
        c.rollback_to(100).unwrap();
        assert!(c.ledger.state.tokens.is_empty(), "token removed");
        assert!(c.ledger.state.tickers.is_empty(), "ticker released");
        assert_eq!(c.ledger.state.commits.len(), 1, "commit restored unspent");
    }

    #[test]
    fn rolling_back_many_blocks_at_once_is_exact() {
        let mut c = Chain::new();
        let id = seed_token(&mut c.ledger, who(1), 1000, 0);
        c.end_block(100);
        let snapshot = format!("{:?}", c.ledger.state);

        for h in 101..=140u64 {
            c.ledger
                .apply(&Record::Transfer(send(id, 10, who(2))), &ctx(h, 0, who(1)))
                .unwrap();
            c.end_block(h);
        }
        assert_eq!(c.ledger.state.balance(id, who(2)), 400);

        c.rollback_to(100).unwrap();
        assert_eq!(format!("{:?}", c.ledger.state), snapshot);
        assert_eq!(c.tip(), Some(100));
    }

    #[test]
    fn rollback_beyond_the_window_halts_instead_of_guessing() {
        let mut c = Chain::new();
        let id = seed_token(&mut c.ledger, who(1), u64::MAX / 2, 0);
        c.end_block(1);
        for h in 2..=(UNDO_DEPTH as u64 + 60) {
            c.ledger
                .apply(&Record::Transfer(send(id, 1, who(2))), &ctx(h, 0, who(1)))
                .unwrap();
            c.end_block(h);
        }
        // Deeper than retained -> refuse, never serve unjustifiable state.
        let err = c.rollback_to(5).unwrap_err();
        assert!(matches!(err, ReorgError::BeyondUndoWindow { .. }));

        // Divi caps reorgs at 100 blocks, comfortably inside the window.
        let tip = c.tip().unwrap();
        assert!(c.rollback_to(tip - 100).is_ok(), "a max-depth Divi reorg must fit");
    }

    #[test]
    fn replaying_the_same_blocks_gives_the_same_fingerprint() {
        let build = || {
            let mut c = Chain::new();
            let id = seed_token(&mut c.ledger, who(1), 500, 0);
            c.end_block(100);
            for (h, tag) in [(101u64, 2u8), (102, 3), (103, 4)] {
                c.ledger
                    .apply(&Record::Transfer(send(id, 10, who(tag))), &ctx(h, 0, who(1)))
                    .unwrap();
                c.end_block(h);
            }
            c
        };
        assert_eq!(build().fingerprint().hex(), build().fingerprint().hex());
    }

    /// Divergence must be detectable: different history, different fingerprint.
    #[test]
    fn different_history_gives_a_different_fingerprint() {
        let mut a = Chain::new();
        let id = seed_token(&mut a.ledger, who(1), 500, 0);
        a.end_block(100);
        a.ledger
            .apply(&Record::Transfer(send(id, 10, who(2))), &ctx(101, 0, who(1)))
            .unwrap();
        a.end_block(101);

        let mut b = Chain::new();
        let id2 = seed_token(&mut b.ledger, who(1), 500, 0);
        b.end_block(100);
        b.ledger
            .apply(&Record::Transfer(send(id2, 11, who(2))), &ctx(101, 0, who(1)))
            .unwrap();
        b.end_block(101);

        assert_ne!(a.fingerprint().hex(), b.fingerprint().hex());
    }

    #[test]
    fn fingerprint_at_a_past_height_is_retrievable() {
        let mut c = Chain::new();
        c.end_block(10);
        let at10 = c.fingerprint();
        c.end_block(11);
        assert_eq!(c.fingerprint_at(10).unwrap().hex(), at10.hex());
        assert!(c.fingerprint_at(999).is_none());
    }

    #[test]
    fn rollback_to_an_unapplied_height_is_refused() {
        let mut c = Chain::new();
        assert!(matches!(c.rollback_to(5), Err(ReorgError::NotApplied(5))));
        c.end_block(10);
        assert!(matches!(c.rollback_to(11), Err(ReorgError::NotApplied(11))));
        assert!(c.rollback_to(10).is_ok(), "rolling back to the tip is a no-op");
    }
}
