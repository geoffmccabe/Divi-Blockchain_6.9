//! Shared test fixtures for the ledger and reorg suites.
//!
//! Kept in one place so both suites build records the same way — a helper that
//! drifted between suites would let a rule pass in one and fail in the other.

use super::{addr_key, commitment_of, Ledger, TxContext};
use crate::config;
use crate::fees;
use crate::record::issue::{Issue, MintTerms, FLAG_OPEN_MINT, FLAG_RISING_PRICE};
use crate::record::simple::NameCommit;
use crate::record::transfer::{Group, Payout, Transfer};
use crate::record::{Record, TokenId};
use dvxp_core::codec::{Address, ADDRESS_P2PKH};
use std::collections::BTreeMap;

pub fn who(tag: u8) -> Address {
    Address { kind: ADDRESS_P2PKH, hash160: [tag; 20] }
}

/// A context that has already paid the registry fees, so fee checks pass unless
/// a test deliberately clears `payments`.
pub fn ctx(height: u64, tx_index: u32, sender: Address) -> TxContext {
    let mut payments = BTreeMap::new();
    payments.insert(addr_key(config::treasury()), 10_000_000 * fees::COIN);
    TxContext { height, tx_index, sender, payments, burned: 0 }
}

pub fn issue_of(ticker: &[u8], premine: u64, flags: u8) -> Issue {
    Issue {
        flags,
        decimals: 0,
        ticker: ticker.to_vec(),
        salt: if ticker.is_empty() { None } else { Some([0x11; 20]) },
        premine,
        terms: None,
        metadata_ptr: None,
    }
}

pub fn named_issue(ticker: &[u8], premine: u64) -> Issue {
    issue_of(ticker, premine, 0)
}

/// The NAME COMMIT that matches a named issuance.
pub fn commit_for(issue: &Issue) -> NameCommit {
    NameCommit {
        commitment: commitment_of(&issue.salt.expect("named issue has a salt"), &issue.ticker),
    }
}

pub fn open_mint_of(cap: u64, per_mint: u64, price: u64, step: u64) -> Issue {
    let mut i = issue_of(b"", 0, FLAG_OPEN_MINT | if step > 0 { FLAG_RISING_PRICE } else { 0 });
    i.terms = Some(MintTerms {
        cap,
        per_mint,
        height_start: 0,
        height_end: 0,
        mint_price: price,
        price_step: step,
    });
    i
}

/// A single-recipient transfer.
pub fn send(token: TokenId, amount: u64, to: Address) -> Transfer {
    Transfer {
        groups: vec![Group { token, payouts: vec![Payout { amount, to }] }],
    }
}

/// Issue a ticker-less token (needs no commit) and return its id.
pub fn seed_token(l: &mut Ledger, issuer: Address, premine: u64, flags: u8) -> TokenId {
    let c = ctx(100, 0, issuer);
    l.apply(&Record::Issue(issue_of(b"", premine, flags)), &c)
        .expect("seed issuance should succeed");
    c.token_id()
}
