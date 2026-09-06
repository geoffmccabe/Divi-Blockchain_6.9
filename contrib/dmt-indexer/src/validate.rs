//! "Would this record be accepted, and if not, why?" — answered before any DIVI
//! is spent.
//!
//! `DMT-WALLET-INTERFACE.md` §3 asks for this, and the reason is worth stating
//! plainly: an overlay record that breaks a rule is **ignored**, not rejected.
//! The transaction still confirms, the fee is still paid, and nothing at all
//! happens. From the user's side that is the worst possible failure, because it
//! looks exactly like success until they check their balance.
//!
//! ## Why this is a dry run rather than a list of checks
//!
//! The obvious implementation is to reimplement each rule as a pre-flight check.
//! That produces a second copy of the rules, which drifts, and a wallet
//! confidently promising that a record will be accepted while the ledger
//! disagrees is worse than no check at all.
//!
//! So this **applies the record to a throwaway copy of the ledger** and reports
//! what happened. The rules consulted are therefore the rules, by construction,
//! and a new rule is covered the day it is written without anyone remembering to
//! update this file.
//!
//! ## The error this catches most often
//!
//! A record's sender is the address funding `vin[0]`. Ordinary coin selection
//! picks whatever inputs are convenient, which is usually a change address
//! holding no tokens, so the record applies to the wrong identity and is
//! ignored. Passing the `TxContext` you actually intend to broadcast, sender
//! included, turns that from a silently wasted fee into a message. See the
//! coin-selection note in [`crate::encode`].
//!
//! ## What it cannot tell you
//!
//! The answer is "would this be accepted **against the state I can see, at the
//! height I guessed**". Two things can still change underneath it:
//!
//! - **The index may be behind.** A ticker registered in a block the wallet has
//!   not seen still makes the issue fail. Check sync state as well.
//! - **Someone else may act first.** Two people claiming the same open-mint
//!   slot: both validate, one wins. This narrows the window; it cannot close it,
//!   and no local check could.

use crate::ledger::{Ledger, TxContext};
use crate::record::Record;
use dvxp_core::Ignored;

/// What a dry run concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It would apply. Not a promise: see the caveats on this module.
    WouldApply,
    /// It would be ignored, for this reason. The transaction would still
    /// confirm and still cost a fee, which is why this is worth knowing first.
    WouldBeIgnored(Ignored),
}

impl Verdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, Verdict::WouldApply)
    }

    /// A sentence to show someone, rather than a debug string.
    ///
    /// Written for a person deciding whether to press send, so each one says
    /// what is wrong in terms of the thing they were trying to do.
    pub fn explain(&self) -> String {
        let Verdict::WouldBeIgnored(why) = self else {
            return "This should go through.".into();
        };
        match why {
            Ignored::RuleViolation(r) => match *r {
                "registry fee not paid" => {
                    "The registry fee has not been included in this transaction. Creating a \
                     token costs a fee paid to the treasury in the same transaction."
                        .into()
                }
                "ticker already registered" => {
                    "That ticker is already taken. Pick another, or use no ticker at all: a \
                     token works without one."
                        .into()
                }
                "no matching name commit" => {
                    "No reservation was found for that ticker from this address. Reserve the \
                     name first, then issue about twelve minutes later."
                        .into()
                }
                "commit is not yet mature" => {
                    "The name reservation is not old enough yet. It needs twelve blocks, about \
                     twelve minutes, which is what stops someone else taking the name the \
                     moment they see it."
                        .into()
                }
                "commit belongs to another address" => {
                    "That name was reserved by a different address, so it cannot be claimed \
                     from this one."
                        .into()
                }
                "insufficient balance" => {
                    "This address does not hold enough of that token to send that much.".into()
                }
                "unknown token" => {
                    "That token does not exist in the index. If it was created very recently, \
                     the index may not have reached that block yet."
                        .into()
                }
                "sender is not the issuer" => {
                    "Only the token's issuer can do that, and this is not the issuer's address."
                        .into()
                }
                "token is not transferable" => {
                    "This token was issued as non-transferable, so it cannot be sent on.".into()
                }
                "supply is locked" => {
                    "This token's supply was permanently frozen, so no more can be created."
                        .into()
                }
                other => format!("This would be ignored: {other}."),
            },
            Ignored::Malformed(what) => {
                format!("The record is not well formed ({what}). This is a bug, not something \
                         you did.")
            }
            other => format!("This would be ignored: {other:?}."),
        }
    }
}

/// Try a record against a copy of the ledger and report what happened.
///
/// `ledger` is left completely untouched: the clone is what gets mutated, and
/// it is dropped on return.
pub fn dry_run(ledger: &Ledger, record: &Record, ctx: &TxContext) -> Verdict {
    let mut trial = ledger.clone();
    match trial.apply(record, ctx) {
        Ok(()) => Verdict::WouldApply,
        Err(why) => Verdict::WouldBeIgnored(why),
    }
}

/// Try several records in order, as one transaction would carry them.
///
/// Order matters: a mint that only succeeds because an earlier record in the
/// same batch created the token must be validated after it, not alongside it.
/// Returns the first failure, with its position, or `None` if all would apply.
pub fn dry_run_batch(
    ledger: &Ledger,
    records: &[(Record, TxContext)],
) -> Option<(usize, Verdict)> {
    let mut trial = ledger.clone();
    for (i, (record, ctx)) in records.iter().enumerate() {
        if let Err(why) = trial.apply(record, ctx) {
            return Some((i, Verdict::WouldBeIgnored(why)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::fees;
    use crate::ledger::state::addr_key;
    use crate::record::simple::Burn;
    use crate::record::TokenId;
    use dvxp_core::codec::{Address, ADDRESS_P2PKH};
    use std::collections::BTreeMap;

    fn who(tag: u8) -> Address {
        Address { kind: ADDRESS_P2PKH, hash160: [tag; 20] }
    }

    fn paid_ctx(height: u64, tx_index: u32, sender: Address) -> TxContext {
        let mut payments = BTreeMap::new();
        payments.insert(addr_key(config::treasury()), 10_000_000 * fees::COIN);
        TxContext { height, tx_index, sender, payments, burned: 0 }
    }

    fn unpaid_ctx(height: u64, tx_index: u32, sender: Address) -> TxContext {
        TxContext { height, tx_index, sender, payments: BTreeMap::new(), burned: 0 }
    }

    fn plain_issue(premine: u64) -> Record {
        Record::Issue(crate::record::issue::Issue {
            flags: 0,
            decimals: 0,
            ticker: Vec::new(),
            salt: None,
            premine,
            terms: None,
            metadata_ptr: None,
        })
    }

    #[test]
    fn a_good_record_says_so_and_changes_nothing() {
        let ledger = Ledger::new();
        let v = dry_run(&ledger, &plain_issue(1000), &paid_ctx(100, 0, who(7)));
        assert_eq!(v, Verdict::WouldApply);
        assert!(v.is_ok());
        // The whole point: asking must not do it.
        assert!(ledger.state.tokens.is_empty(), "the real ledger is untouched");
    }

    #[test]
    fn an_unpaid_fee_is_caught_before_the_transaction_is_sent() {
        let ledger = Ledger::new();
        let v = dry_run(&ledger, &plain_issue(1000), &unpaid_ctx(100, 0, who(7)));
        assert!(!v.is_ok());
        assert!(
            v.explain().contains("registry fee"),
            "the explanation must name the actual problem, got: {}",
            v.explain()
        );
    }

    #[test]
    fn burning_a_token_that_does_not_exist_is_caught() {
        let ledger = Ledger::new();
        let burn = Record::Burn(Burn { token: TokenId { height: 1, tx_index: 0 }, amount: 5 });
        let v = dry_run(&ledger, &burn, &unpaid_ctx(100, 0, who(7)));
        assert!(!v.is_ok());
        assert!(!v.explain().is_empty());
    }

    /// The batch case exists because a record can depend on one earlier in the
    /// same set: issue then burn is fine, burn then issue is not.
    #[test]
    fn a_batch_is_validated_in_order_and_names_which_one_failed() {
        let ledger = Ledger::new();
        let token = TokenId { height: 100, tx_index: 0 };

        let good = vec![
            (plain_issue(1000), paid_ctx(100, 0, who(7))),
            (
                Record::Burn(Burn { token, amount: 100 }),
                unpaid_ctx(101, 0, who(7)),
            ),
        ];
        assert_eq!(dry_run_batch(&ledger, &good), None, "issue then burn is fine");

        let backwards = vec![
            (
                Record::Burn(Burn { token, amount: 100 }),
                unpaid_ctx(99, 0, who(7)),
            ),
            (plain_issue(1000), paid_ctx(100, 0, who(7))),
        ];
        let failure = dry_run_batch(&ledger, &backwards);
        assert!(failure.is_some(), "burning before the token exists cannot work");
        assert_eq!(failure.unwrap().0, 0, "and it says which record was the problem");

        assert!(ledger.state.tokens.is_empty(), "neither batch touched the real ledger");
    }

    #[test]
    fn an_accepted_verdict_explains_itself_without_alarming_anyone() {
        assert_eq!(Verdict::WouldApply.explain(), "This should go through.");
    }
}
