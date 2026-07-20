//! Ledger state (spec §1, §6, §7).
//!
//! **Every collection here is a `BTreeMap`, never a `HashMap`, and that is a
//! correctness requirement rather than a style choice.** The per-block state
//! fingerprint (spec §9.2) is computed by walking this state in order. A
//! `HashMap` iterates in an order that varies between runs and between builds,
//! so two indexers holding *identical* state would publish *different*
//! fingerprints and each conclude the other had diverged.

use crate::record::issue::{Issue, MintTerms};
use crate::record::TokenId;
use dvxp_core::codec::Address;
use std::collections::BTreeMap;

/// Sort key for an address. `Address` is not `Ord` in the shared crate, so the
/// ordering is defined once here and used for every deterministic walk.
pub type AddrKey = (u8, [u8; 20]);

pub fn addr_key(a: Address) -> AddrKey {
    (a.kind, a.hash160)
}

/// Everything known about one token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenState {
    pub issuer: Address,
    /// Empty when the token has no human-readable name (spec §7.3.1).
    pub ticker: Vec<u8>,
    pub decimals: u8,
    pub flags: u8,
    pub terms: Option<MintTerms>,
    pub metadata_ptr: Option<[u8; 32]>,
    /// Units in existence: premine plus everything minted, minus burns.
    pub circulating: u64,
    /// Units minted through open-mint claims so far, counted against the cap.
    pub minted: u64,
    /// Number of completed claims — drives the rising price (spec §6.3).
    pub claims: u64,
    /// Set by LOCK SUPPLY. Does not stop a running open mint (spec §5.6).
    pub supply_locked: bool,
}

impl TokenState {
    pub fn from_issue(issue: &Issue, issuer: Address) -> Self {
        Self {
            issuer,
            ticker: issue.ticker.clone(),
            decimals: issue.decimals,
            flags: issue.flags,
            terms: issue.terms.clone(),
            metadata_ptr: issue.metadata_ptr,
            circulating: issue.premine,
            minted: 0,
            claims: 0,
            supply_locked: issue.has(crate::record::issue::FLAG_SUPPLY_LOCKED),
        }
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Units still claimable, or `None` when the cap is unlimited.
    pub fn remaining_cap(&self) -> Option<u64> {
        let t = self.terms.as_ref()?;
        if t.cap == 0 {
            return None; // unlimited
        }
        Some(t.cap.saturating_sub(self.minted))
    }

    /// Price of the next claim, given claims already made (spec §6.3).
    pub fn next_price(&self) -> u64 {
        match &self.terms {
            None => 0,
            Some(t) => t
                .mint_price
                .saturating_add(t.price_step.saturating_mul(self.claims)),
        }
    }
}

/// A registered ticker. Freely transferable while unused; permanently frozen
/// once it names a live token (spec §7.5) — otherwise whoever holds the ticker
/// could rename a token under its holders' feet and every wallet would follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickerState {
    pub owner: Address,
    pub bound_to: Option<TokenId>,
}

impl TickerState {
    pub fn is_bound(&self) -> bool {
        self.bound_to.is_some()
    }
}

/// An unspent NAME COMMIT awaiting its reveal (spec §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitState {
    pub committer: Address,
    pub height: u64,
}

/// One recorded before-image, replayed in reverse to undo a block (spec §9.4).
///
/// Storing the *previous* value rather than an inverse operation means undo is
/// exact even for saturating or clamped arithmetic, where "subtract what you
/// added" would not reliably restore the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undo {
    Balance { key: ((u64, u32), AddrKey), prev: Option<u64> },
    Token { key: (u64, u32), prev: Option<Box<TokenState>> },
    Ticker { name: Vec<u8>, prev: Option<TickerState> },
    Commit { hash: [u8; 20], prev: Option<CommitState> },
}

/// The whole DMT ledger.
#[derive(Debug, Default, Clone)]
pub struct State {
    pub tokens: BTreeMap<(u64, u32), TokenState>,
    pub balances: BTreeMap<((u64, u32), AddrKey), u64>,
    pub tickers: BTreeMap<Vec<u8>, TickerState>,
    /// Keyed by commitment hash; removed when consumed by an ISSUE.
    pub commits: BTreeMap<[u8; 20], CommitState>,
    /// Before-images for the block currently being applied. Recording lives
    /// inside the mutators so a new rule cannot forget to journal its writes.
    pending: Vec<Undo>,
}

pub fn token_key(id: TokenId) -> (u64, u32) {
    (id.height, id.tx_index)
}

impl State {
    pub fn token(&self, id: TokenId) -> Option<&TokenState> {
        self.tokens.get(&token_key(id))
    }

    pub fn token_mut(&mut self, id: TokenId) -> Option<&mut TokenState> {
        self.tokens.get_mut(&token_key(id))
    }

    pub fn balance(&self, id: TokenId, who: Address) -> u64 {
        *self
            .balances
            .get(&(token_key(id), addr_key(who)))
            .unwrap_or(&0)
    }

    /// Add units. `None` on overflow, which the caller must treat as
    /// "ignore the whole record" rather than wrapping.
    #[must_use]
    pub fn credit(&mut self, id: TokenId, who: Address, amount: u64) -> Option<()> {
        let key = (token_key(id), addr_key(who));
        let prev = self.balances.get(&key).copied();
        let next = prev.unwrap_or(0).checked_add(amount)?;
        self.pending.push(Undo::Balance { key, prev });
        self.balances.insert(key, next);
        Some(())
    }

    /// Remove units. `None` if the holder does not have them.
    #[must_use]
    pub fn debit(&mut self, id: TokenId, who: Address, amount: u64) -> Option<()> {
        let key = (token_key(id), addr_key(who));
        let prev = self.balances.get(&key).copied()?;
        let next = prev.checked_sub(amount)?;
        self.pending.push(Undo::Balance { key, prev: Some(prev) });
        // Drop empty entries so the fingerprint reflects holders, not history.
        if next == 0 {
            self.balances.remove(&key);
        } else {
            self.balances.insert(key, next);
        }
        Some(())
    }

    /// Record a token's current value before it is modified. Call before any
    /// `token_mut` write, and before inserting a new token.
    pub fn touch_token(&mut self, id: TokenId) {
        let key = token_key(id);
        let prev = self.tokens.get(&key).cloned().map(Box::new);
        self.pending.push(Undo::Token { key, prev });
    }

    pub fn touch_ticker(&mut self, name: &[u8]) {
        let prev = self.tickers.get(name).cloned();
        self.pending.push(Undo::Ticker { name: name.to_vec(), prev });
    }

    pub fn touch_commit(&mut self, hash: [u8; 20]) {
        let prev = self.commits.get(&hash).cloned();
        self.pending.push(Undo::Commit { hash, prev });
    }

    /// Take the before-images recorded since the last call.
    pub fn take_pending(&mut self) -> Vec<Undo> {
        std::mem::take(&mut self.pending)
    }

    /// Discard before-images without applying them (used when a block is
    /// applied and its journal is being retained elsewhere).
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    /// Replay before-images in reverse, restoring the exact prior state.
    pub fn revert(&mut self, undo: &[Undo]) {
        for u in undo.iter().rev() {
            match u {
                Undo::Balance { key, prev } => match prev {
                    Some(v) => {
                        self.balances.insert(*key, *v);
                    }
                    None => {
                        self.balances.remove(key);
                    }
                },
                Undo::Token { key, prev } => match prev {
                    Some(v) => {
                        self.tokens.insert(*key, (**v).clone());
                    }
                    None => {
                        self.tokens.remove(key);
                    }
                },
                Undo::Ticker { name, prev } => match prev {
                    Some(v) => {
                        self.tickers.insert(name.clone(), v.clone());
                    }
                    None => {
                        self.tickers.remove(name);
                    }
                },
                Undo::Commit { hash, prev } => match prev {
                    Some(v) => {
                        self.commits.insert(*hash, v.clone());
                    }
                    None => {
                        self.commits.remove(hash);
                    }
                },
            }
        }
    }

    /// Holders of a token, in deterministic order.
    pub fn holders(&self, id: TokenId) -> impl Iterator<Item = (&AddrKey, &u64)> {
        let k = token_key(id);
        self.balances
            .iter()
            .filter(move |((t, _), _)| *t == k)
            .map(|((_, a), v)| (a, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::codec::ADDRESS_P2PKH;

    fn who(tag: u8) -> Address {
        Address { kind: ADDRESS_P2PKH, hash160: [tag; 20] }
    }
    fn tok() -> TokenId {
        TokenId { height: 5, tx_index: 1 }
    }

    #[test]
    fn credit_and_debit_track_balances() {
        let mut s = State::default();
        assert_eq!(s.balance(tok(), who(1)), 0);
        s.credit(tok(), who(1), 100).unwrap();
        s.credit(tok(), who(1), 50).unwrap();
        assert_eq!(s.balance(tok(), who(1)), 150);
        s.debit(tok(), who(1), 60).unwrap();
        assert_eq!(s.balance(tok(), who(1)), 90);
    }

    #[test]
    fn debit_refuses_to_go_negative() {
        let mut s = State::default();
        s.credit(tok(), who(1), 10).unwrap();
        assert!(s.debit(tok(), who(1), 11).is_none(), "must not overdraw");
        assert_eq!(s.balance(tok(), who(1)), 10, "failed debit changes nothing");
        assert!(s.debit(tok(), who(2), 1).is_none(), "unknown holder");
    }

    #[test]
    fn credit_reports_overflow_rather_than_wrapping() {
        let mut s = State::default();
        s.credit(tok(), who(1), u64::MAX).unwrap();
        assert!(s.credit(tok(), who(1), 1).is_none());
    }

    #[test]
    fn emptied_balances_are_removed_not_left_at_zero() {
        let mut s = State::default();
        s.credit(tok(), who(1), 5).unwrap();
        s.debit(tok(), who(1), 5).unwrap();
        assert!(s.balances.is_empty(), "zero balances must not linger in state");
    }

    #[test]
    fn balances_are_isolated_per_token() {
        let mut s = State::default();
        let other = TokenId { height: 5, tx_index: 2 };
        s.credit(tok(), who(1), 10).unwrap();
        assert_eq!(s.balance(other, who(1)), 0);
        assert_eq!(s.holders(tok()).count(), 1);
        assert_eq!(s.holders(other).count(), 0);
    }

    /// Determinism guard: state must walk in a fixed order regardless of the
    /// order things were inserted, or two indexers publish different
    /// fingerprints for identical state.
    #[test]
    fn iteration_order_is_insertion_independent() {
        let mut a = State::default();
        let mut b = State::default();
        for tag in [3u8, 1, 2] {
            a.credit(tok(), who(tag), tag as u64).unwrap();
        }
        for tag in [2u8, 3, 1] {
            b.credit(tok(), who(tag), tag as u64).unwrap();
        }
        let ka: Vec<_> = a.balances.keys().collect();
        let kb: Vec<_> = b.balances.keys().collect();
        assert_eq!(ka, kb);
    }
}
