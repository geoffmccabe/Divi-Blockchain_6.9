//! The DMT rules engine: applying records to state (spec §5–§7).
//!
//! ## Adding a new record type later
//!
//! Write an `apply_*` method and add one arm to [`Ledger::apply`]. Nothing else
//! changes. Each rule is a separate method on purpose, so a new idea is a new
//! method rather than an edit to a growing conditional.
//!
//! ## The invariant every method must preserve
//!
//! **Either a record applies completely, or it changes nothing at all.** A
//! record is validated in full before any mutation happens. There is no partial
//! application anywhere except the deliberate cap-boundary short fill in
//! [`Ledger::apply_mint`] — partial application elsewhere is how Counterparty
//! and Omni ended up with balances their own implementations disagreed about.

pub mod state;

use crate::config;
use crate::fees;
use crate::record::issue::{Issue, FLAG_NON_TRANSFERABLE, FLAG_OPEN_MINT, FLAG_PROCEEDS_BURNED};
use crate::record::{simple, transfer, Record, TokenId};
use dvxp_core::codec::Address;
use dvxp_core::Ignored;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use state::{addr_key, AddrKey, CommitState, State, TickerState, TokenState};
use std::collections::BTreeMap;

/// What the chain says about the transaction carrying a record.
///
/// `payments` and `burned` are how the ledger checks fees and mint prices: the
/// overlay cannot escrow DIVI, but it *can* require that a payment appears in
/// the very same transaction, which is what makes a priced mint atomic and
/// immune to the dispenser attack (spec §10.3).
#[derive(Debug, Clone)]
pub struct TxContext {
    pub height: u64,
    pub tx_index: u32,
    /// Address funding `vin[0]` — the deterministic sender rule (spec §4.1).
    pub sender: Address,
    /// Duffs paid to each address by this transaction's outputs.
    pub payments: BTreeMap<AddrKey, u64>,
    /// Duffs sent to provably-unspendable outputs.
    pub burned: u64,
}

impl TxContext {
    pub fn paid_to(&self, who: Address) -> u64 {
        *self.payments.get(&addr_key(who)).unwrap_or(&0)
    }

    /// This transaction's own token id, if it issues one.
    pub fn token_id(&self) -> TokenId {
        TokenId { height: self.height, tx_index: self.tx_index }
    }
}

/// `Hash160(salt ‖ ticker)` — the NAME COMMIT value (spec §7.2).
pub fn commitment_of(salt: &[u8; 20], ticker: &[u8]) -> [u8; 20] {
    let mut pre = Vec::with_capacity(20 + ticker.len());
    pre.extend_from_slice(salt);
    pre.extend_from_slice(ticker);
    let sha = Sha256::digest(&pre);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

#[derive(Debug, Default, Clone)]
pub struct Ledger {
    pub state: State,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one record. `Ok(())` means state changed; `Err` means nothing did.
    pub fn apply(&mut self, rec: &Record, ctx: &TxContext) -> Result<(), Ignored> {
        // Vacuous while GENESIS_HEIGHT is still the 0 placeholder, which is
        // exactly what clippy is pointing out. The check is kept because it
        // becomes load-bearing the moment a real height is set, and deleting it
        // now would mean silently replaying pre-genesis records later.
        #[allow(clippy::absurd_extreme_comparisons)]
        if ctx.height < config::GENESIS_HEIGHT {
            return Err(Ignored::RuleViolation("before DMT genesis height"));
        }
        match rec {
            Record::Issue(r) => self.apply_issue(r, ctx),
            Record::Transfer(r) => self.apply_transfer(r, ctx),
            Record::Mint(r) => self.apply_mint(r, ctx),
            Record::NameCommit(r) => self.apply_name_commit(r, ctx),
            Record::Burn(r) => self.apply_burn(r, ctx),
            Record::LockSupply(r) => self.apply_lock_supply(r, ctx),
            Record::IssuerTransfer(r) => self.apply_issuer_transfer(r, ctx),
            Record::TickerTransfer(r) => self.apply_ticker_transfer(r, ctx),
        }
    }

    // ---- §5.1 ISSUE --------------------------------------------------------

    fn apply_issue(&mut self, r: &Issue, ctx: &TxContext) -> Result<(), Ignored> {
        let id = ctx.token_id();
        if self.state.token(id).is_some() {
            return Err(Ignored::RuleViolation("token id already used"));
        }

        // Fees are two separate charges (spec §7.3.1, §7.4): creating a token,
        // and optionally registering a name. Both go to the treasury, and
        // neither is issuer-configurable -- a fee the payer can redirect to
        // themselves is not a fee, and the anti-squatting property collapses.
        let mut required = fees::token_creation_fee_duffs();
        if r.has_ticker() {
            let tf = fees::ticker_fee_duffs(r.ticker.len())
                .ok_or(Ignored::RuleViolation("no fee defined for ticker length"))?;
            required = required
                .checked_add(tf)
                .ok_or(Ignored::RuleViolation("fee overflow"))?;
        }
        if ctx.paid_to(config::treasury()) < required {
            return Err(Ignored::RuleViolation("registry fee not paid"));
        }

        // Claiming a name requires a matured commit from this same sender
        // (spec §7.2). Validate before mutating anything.
        let commitment = if r.has_ticker() {
            let salt = r.salt.ok_or(Ignored::Malformed("ticker without salt"))?;
            if self.state.tickers.contains_key(&r.ticker) {
                return Err(Ignored::RuleViolation("ticker already registered"));
            }
            let c = commitment_of(&salt, &r.ticker);
            let commit = self
                .state
                .commits
                .get(&c)
                .ok_or(Ignored::RuleViolation("no matching name commit"))?;
            if addr_key(commit.committer) != addr_key(ctx.sender) {
                return Err(Ignored::RuleViolation("commit belongs to another address"));
            }
            let depth = ctx.height.saturating_sub(commit.height);
            if depth < config::MIN_COMMIT_DEPTH {
                // The whole anti-front-running property: an attacker who learns
                // the name at reveal time cannot use it, because claiming needs
                // their own commit already this deep.
                return Err(Ignored::RuleViolation("name commit not yet mature"));
            }
            Some(c)
        } else {
            None
        };

        // ---- validated; mutate from here --------------------------------
        let token = TokenState::from_issue(r, ctx.sender);
        if r.premine > 0 {
            self.state
                .credit(id, ctx.sender, r.premine)
                .ok_or(Ignored::RuleViolation("premine overflows holder balance"))?;
        }
        self.state.tokens.insert(state::token_key(id), token);

        if let Some(c) = commitment {
            self.state.commits.remove(&c);
            self.state.tickers.insert(
                r.ticker.clone(),
                TickerState { owner: ctx.sender, bound_to: Some(id) },
            );
        }
        Ok(())
    }

    // ---- §5.2 TRANSFER -----------------------------------------------------

    fn apply_transfer(&mut self, r: &transfer::Transfer, ctx: &TxContext) -> Result<(), Ignored> {
        // Validate every group first: all-or-nothing, no clamping (spec §5.2).
        for g in &r.groups {
            let token = self
                .state
                .token(g.token)
                .ok_or(Ignored::RuleViolation("unknown token"))?;

            // Non-transferable tokens move only by the issuer's hand (spec §5.1).
            if token.has(FLAG_NON_TRANSFERABLE)
                && addr_key(token.issuer) != addr_key(ctx.sender)
            {
                return Err(Ignored::RuleViolation("token is non-transferable"));
            }

            let total = r
                .total_for(g.token)
                .ok_or(Ignored::RuleViolation("transfer total overflows"))?;
            if self.state.balance(g.token, ctx.sender) < total {
                return Err(Ignored::RuleViolation("insufficient balance"));
            }
        }

        // Credits are checked before any debit, so an overflow on the receiving
        // side cannot leave the sender debited.
        for g in &r.groups {
            for p in &g.payouts {
                let dest = self.state.balance(g.token, p.to);
                if dest.checked_add(p.amount).is_none() {
                    return Err(Ignored::RuleViolation("recipient balance overflows"));
                }
            }
        }

        // ---- validated; mutate from here --------------------------------
        for g in &r.groups {
            for p in &g.payouts {
                self.state
                    .debit(g.token, ctx.sender, p.amount)
                    .ok_or(Ignored::RuleViolation("insufficient balance"))?;
                self.state
                    .credit(g.token, p.to, p.amount)
                    .ok_or(Ignored::RuleViolation("recipient balance overflows"))?;
            }
        }
        Ok(())
    }

    // ---- §5.3 MINT ---------------------------------------------------------

    fn apply_mint(&mut self, r: &simple::Mint, ctx: &TxContext) -> Result<(), Ignored> {
        let token = self
            .state
            .token(r.token)
            .ok_or(Ignored::RuleViolation("unknown token"))?;
        if !token.has(FLAG_OPEN_MINT) {
            return Err(Ignored::RuleViolation("token is not open-mint"));
        }
        let terms = token
            .terms
            .clone()
            .ok_or(Ignored::RuleViolation("open-mint token without terms"))?;

        if ctx.height < terms.height_start {
            return Err(Ignored::RuleViolation("mint has not opened"));
        }
        if terms.height_end != 0 && ctx.height > terms.height_end {
            return Err(Ignored::RuleViolation("mint has closed"));
        }

        // Partial fill at the cap boundary ONLY (spec §5.3). Without it, two
        // buyers racing for the last units both pay and the later one gets
        // nothing -- a real loss. This is the sole place a short fill happens.
        let amount = match token.remaining_cap() {
            None => terms.per_mint,
            Some(0) => return Err(Ignored::RuleViolation("mint cap reached")),
            Some(left) => left.min(terms.per_mint),
        };

        // Payment must appear in this same transaction, which is what makes a
        // priced mint atomic: the issuer is not a participant and has nothing
        // to withhold, empty or reprice (spec §10.3).
        let price = token.next_price();
        if price > 0 {
            let paid = if token.has(FLAG_PROCEEDS_BURNED) {
                ctx.burned
            } else {
                ctx.paid_to(token.issuer)
            };
            if paid < price {
                return Err(Ignored::RuleViolation("mint price not paid"));
            }
        }

        let to = r.recipient.unwrap_or(ctx.sender);

        // ---- validated; mutate from here --------------------------------
        self.state
            .credit(r.token, to, amount)
            .ok_or(Ignored::RuleViolation("recipient balance overflows"))?;
        let t = self.state.token_mut(r.token).expect("checked above");
        t.minted = t.minted.saturating_add(amount);
        t.circulating = t.circulating.saturating_add(amount);
        t.claims = t.claims.saturating_add(1);
        Ok(())
    }

    // ---- §5.4 NAME COMMIT --------------------------------------------------

    fn apply_name_commit(&mut self, r: &simple::NameCommit, ctx: &TxContext) -> Result<(), Ignored> {
        // First commit wins; a later duplicate must not reset the clock, or the
        // maturity delay could be refreshed to grief a pending reveal.
        if self.state.commits.contains_key(&r.commitment) {
            return Err(Ignored::RuleViolation("commitment already published"));
        }
        self.state.commits.insert(
            r.commitment,
            CommitState { committer: ctx.sender, height: ctx.height },
        );
        Ok(())
    }

    // ---- §5.5 BURN ---------------------------------------------------------

    fn apply_burn(&mut self, r: &simple::Burn, ctx: &TxContext) -> Result<(), Ignored> {
        if self.state.token(r.token).is_none() {
            return Err(Ignored::RuleViolation("unknown token"));
        }
        if self.state.balance(r.token, ctx.sender) < r.amount {
            return Err(Ignored::RuleViolation("insufficient balance"));
        }
        self.state
            .debit(r.token, ctx.sender, r.amount)
            .ok_or(Ignored::RuleViolation("insufficient balance"))?;
        let t = self.state.token_mut(r.token).expect("checked above");
        t.circulating = t.circulating.saturating_sub(r.amount);
        Ok(())
    }

    // ---- §5.6 / §5.7 / §7.5 issuer and ticker ------------------------------

    fn apply_lock_supply(&mut self, r: &simple::TokenRef, ctx: &TxContext) -> Result<(), Ignored> {
        let t = self
            .state
            .token_mut(r.token)
            .ok_or(Ignored::RuleViolation("unknown token"))?;
        if addr_key(t.issuer) != addr_key(ctx.sender) {
            return Err(Ignored::RuleViolation("only the issuer may lock supply"));
        }
        t.supply_locked = true;
        Ok(())
    }

    fn apply_issuer_transfer(
        &mut self,
        r: &simple::IssuerTransfer,
        ctx: &TxContext,
    ) -> Result<(), Ignored> {
        let t = self
            .state
            .token_mut(r.token)
            .ok_or(Ignored::RuleViolation("unknown token"))?;
        if addr_key(t.issuer) != addr_key(ctx.sender) {
            return Err(Ignored::RuleViolation("only the issuer may transfer issuership"));
        }
        t.issuer = r.new_issuer;
        // The ticker travels with the token -- that is the supported way to sell
        // a live token's identity (spec §7.5).
        let ticker = t.ticker.clone();
        if !ticker.is_empty() {
            if let Some(ts) = self.state.tickers.get_mut(&ticker) {
                ts.owner = r.new_issuer;
            }
        }
        Ok(())
    }

    fn apply_ticker_transfer(
        &mut self,
        r: &simple::TickerTransfer,
        ctx: &TxContext,
    ) -> Result<(), Ignored> {
        let ts = self
            .state
            .tickers
            .get_mut(&r.ticker)
            .ok_or(Ignored::RuleViolation("ticker not registered"))?;
        if addr_key(ts.owner) != addr_key(ctx.sender) {
            return Err(Ignored::RuleViolation("only the owner may transfer a ticker"));
        }
        // Frozen once it names a live token. Otherwise the holder could rename a
        // token under its holders' feet and every wallet would follow -- a
        // rug pull with the protocol's assistance (spec §7.5).
        if ts.is_bound() {
            return Err(Ignored::RuleViolation("ticker is bound to a live token"));
        }
        ts.owner = r.new_owner;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
