//! Rules-engine tests. The recurring theme is the all-or-nothing invariant:
//! a rejected record must leave state byte-identical to before it was tried.

use super::*;
use crate::record::issue::{MintTerms, FLAG_ISSUER_MINTABLE, FLAG_SUPPLY_LOCKED};
use crate::record::transfer::{Group, Payout};
use dvxp_core::codec::ADDRESS_P2PKH;

fn who(tag: u8) -> Address {
    Address { kind: ADDRESS_P2PKH, hash160: [tag; 20] }
}

/// A context that has paid the registry fees, so fee checks pass by default.
fn ctx(height: u64, tx_index: u32, sender: Address) -> TxContext {
    let mut payments = BTreeMap::new();
    payments.insert(addr_key(config::treasury()), 10_000_000 * fees::COIN);
    TxContext { height, tx_index, sender, payments, burned: 0 }
}

fn issue_of(ticker: &[u8], premine: u64, flags: u8) -> Issue {
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

fn open_mint_of(cap: u64, per_mint: u64, price: u64, step: u64) -> Issue {
    let mut i = issue_of(b"", 0, FLAG_OPEN_MINT | if step > 0 { 0x40 } else { 0 });
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

/// Issue a ticker-less token (no commit needed) and return its id.
fn seed_token(l: &mut Ledger, issuer: Address, premine: u64, flags: u8) -> TokenId {
    let c = ctx(100, 0, issuer);
    l.apply(&Record::Issue(issue_of(b"", premine, flags)), &c).unwrap();
    c.token_id()
}

// ---- issuance --------------------------------------------------------------

#[test]
fn issues_a_ticker_less_token_and_credits_premine() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 500, FLAG_SUPPLY_LOCKED);
    assert_eq!(l.state.balance(id, who(1)), 500);
    assert_eq!(l.state.token(id).unwrap().circulating, 500);
    assert!(l.state.tickers.is_empty(), "no ticker was claimed");
}

#[test]
fn issuance_requires_the_registry_fee() {
    let mut l = Ledger::new();
    let mut c = ctx(100, 0, who(1));
    c.payments.clear(); // paid nothing
    let err = l.apply(&Record::Issue(issue_of(b"", 100, 0)), &c).unwrap_err();
    assert_eq!(err, Ignored::RuleViolation("registry fee not paid"));
    assert!(l.state.tokens.is_empty(), "failed issue must change nothing");
}

#[test]
fn a_ticker_needs_a_matured_commit_from_the_same_sender() {
    let mut l = Ledger::new();
    let issue = issue_of(b"GOLD", 10, 0);
    let commitment = commitment_of(&issue.salt.unwrap(), b"GOLD");

    // No commit at all.
    assert_eq!(
        l.apply(&Record::Issue(issue.clone()), &ctx(100, 0, who(1))).unwrap_err(),
        Ignored::RuleViolation("no matching name commit")
    );

    // Commit exists but is too young -- this is the anti-front-running rule.
    l.apply(
        &Record::NameCommit(simple::NameCommit { commitment }),
        &ctx(100, 0, who(1)),
    )
    .unwrap();
    assert_eq!(
        l.apply(&Record::Issue(issue.clone()), &ctx(105, 0, who(1))).unwrap_err(),
        Ignored::RuleViolation("name commit not yet mature")
    );

    // Mature, but revealed by somebody else -- the front-runner's case.
    assert_eq!(
        l.apply(&Record::Issue(issue.clone()), &ctx(120, 0, who(2))).unwrap_err(),
        Ignored::RuleViolation("commit belongs to another address")
    );

    // Mature and from the committer.
    let c = ctx(120, 3, who(1));
    l.apply(&Record::Issue(issue), &c).unwrap();
    let ts = l.state.tickers.get(b"GOLD".as_slice()).unwrap();
    assert_eq!(addr_key(ts.owner), addr_key(who(1)));
    assert_eq!(ts.bound_to, Some(c.token_id()));
    assert!(l.state.commits.is_empty(), "commit must be consumed");
}

#[test]
fn a_ticker_cannot_be_registered_twice() {
    let mut l = Ledger::new();
    let issue = issue_of(b"GOLD", 1, 0);
    let commitment = commitment_of(&issue.salt.unwrap(), b"GOLD");
    l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(100, 0, who(1)))
        .unwrap();
    l.apply(&Record::Issue(issue.clone()), &ctx(120, 1, who(1))).unwrap();

    // ISSUE publishes the salt on-chain, so anyone can now recompute the
    // commitment. Because the original was consumed, re-publishing it is
    // allowed -- and it buys the attacker nothing: the ticker is taken, so the
    // reveal still fails. Registration is protected by the ticker registry,
    // not by the secrecy of a spent salt.
    l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(130, 0, who(2)))
        .unwrap();
    assert_eq!(
        l.apply(&Record::Issue(issue), &ctx(200, 5, who(2))).unwrap_err(),
        Ignored::RuleViolation("ticker already registered")
    );
}

/// An unconsumed commitment blocks anyone else from publishing that exact
/// value, so a failed reveal cannot be hijacked by replaying the salt.
#[test]
fn an_unconsumed_commitment_cannot_be_republished() {
    let mut l = Ledger::new();
    let issue = issue_of(b"SILVER", 1, 0);
    let commitment = commitment_of(&issue.salt.unwrap(), b"SILVER");
    l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(100, 0, who(1)))
        .unwrap();

    // A reveal that fails for an unrelated reason must NOT consume the commit.
    let mut broke = ctx(120, 0, who(1));
    broke.payments.clear();
    assert!(l.apply(&Record::Issue(issue.clone()), &broke).is_err());
    assert!(l.state.commits.contains_key(&commitment), "failed reveal kept the commit");

    // The salt is now public, but the attacker cannot claim the commitment.
    assert_eq!(
        l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(121, 0, who(2)))
            .unwrap_err(),
        Ignored::RuleViolation("commitment already published")
    );
    // ...nor reveal against the original owner's commit.
    assert_eq!(
        l.apply(&Record::Issue(issue.clone()), &ctx(140, 0, who(2))).unwrap_err(),
        Ignored::RuleViolation("commit belongs to another address")
    );
    // The rightful committer can still complete.
    l.apply(&Record::Issue(issue), &ctx(140, 1, who(1))).unwrap();
    assert!(l.state.tickers.contains_key(b"SILVER".as_slice()));
}

// ---- transfers -------------------------------------------------------------

#[test]
fn transfers_move_units_between_addresses() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 1000, 0);
    let t = transfer::Transfer {
        groups: vec![Group {
            token: id,
            payouts: vec![
                Payout { amount: 300, to: who(2) },
                Payout { amount: 200, to: who(3) },
            ],
        }],
    };
    l.apply(&Record::Transfer(t), &ctx(101, 0, who(1))).unwrap();
    assert_eq!(l.state.balance(id, who(1)), 500);
    assert_eq!(l.state.balance(id, who(2)), 300);
    assert_eq!(l.state.balance(id, who(3)), 200);
}

/// The all-or-nothing rule: one unaffordable payout voids the entire record,
/// including payouts that would individually have succeeded.
#[test]
fn an_overdraft_voids_the_whole_transfer() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 100, 0);
    let t = transfer::Transfer {
        groups: vec![Group {
            token: id,
            payouts: vec![
                Payout { amount: 60, to: who(2) },
                Payout { amount: 60, to: who(3) },
            ],
        }],
    };
    assert_eq!(
        l.apply(&Record::Transfer(t), &ctx(101, 0, who(1))).unwrap_err(),
        Ignored::RuleViolation("insufficient balance")
    );
    assert_eq!(l.state.balance(id, who(1)), 100, "no partial application");
    assert_eq!(l.state.balance(id, who(2)), 0);
    assert_eq!(l.state.balance(id, who(3)), 0);
}

#[test]
fn non_transferable_tokens_move_only_by_the_issuer() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 100, FLAG_NON_TRANSFERABLE);
    // Issuer distributes a ticket.
    let out = transfer::Transfer {
        groups: vec![Group { token: id, payouts: vec![Payout { amount: 10, to: who(2) }] }],
    };
    l.apply(&Record::Transfer(out), &ctx(101, 0, who(1))).unwrap();
    assert_eq!(l.state.balance(id, who(2)), 10);

    // The holder cannot pass it on.
    let resale = transfer::Transfer {
        groups: vec![Group { token: id, payouts: vec![Payout { amount: 10, to: who(3) }] }],
    };
    assert_eq!(
        l.apply(&Record::Transfer(resale), &ctx(102, 0, who(2))).unwrap_err(),
        Ignored::RuleViolation("token is non-transferable")
    );
    assert_eq!(l.state.balance(id, who(2)), 10);
}

#[test]
fn transfers_of_unknown_tokens_are_rejected() {
    let mut l = Ledger::new();
    let ghost = TokenId { height: 1, tx_index: 1 };
    let t = transfer::Transfer {
        groups: vec![Group { token: ghost, payouts: vec![Payout { amount: 1, to: who(2) }] }],
    };
    assert_eq!(
        l.apply(&Record::Transfer(t), &ctx(101, 0, who(1))).unwrap_err(),
        Ignored::RuleViolation("unknown token")
    );
}

// ---- minting ---------------------------------------------------------------

#[test]
fn free_open_mint_credits_the_claimant() {
    let mut l = Ledger::new();
    let c = ctx(100, 0, who(1));
    l.apply(&Record::Issue(open_mint_of(100, 10, 0, 0)), &c).unwrap();
    let id = c.token_id();

    l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &ctx(101, 0, who(2)))
        .unwrap();
    assert_eq!(l.state.balance(id, who(2)), 10);
    assert_eq!(l.state.token(id).unwrap().minted, 10);
    assert_eq!(l.state.token(id).unwrap().claims, 1);
}

#[test]
fn a_priced_mint_requires_payment_in_the_same_transaction() {
    let mut l = Ledger::new();
    let c = ctx(100, 0, who(1));
    l.apply(&Record::Issue(open_mint_of(100, 10, 500, 0)), &c).unwrap();
    let id = c.token_id();

    // Nothing paid to the issuer.
    let mut buyer = ctx(101, 0, who(2));
    assert_eq!(
        l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &buyer).unwrap_err(),
        Ignored::RuleViolation("mint price not paid")
    );
    assert_eq!(l.state.balance(id, who(2)), 0);

    // Paying the issuer in the same transaction succeeds -- this is what makes
    // the primary sale atomic and immune to the dispenser attack.
    buyer.payments.insert(addr_key(who(1)), 500);
    l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &buyer).unwrap();
    assert_eq!(l.state.balance(id, who(2)), 10);
}

#[test]
fn rising_price_climbs_with_each_claim() {
    let mut l = Ledger::new();
    let c = ctx(100, 0, who(1));
    l.apply(&Record::Issue(open_mint_of(1000, 1, 100, 50)), &c).unwrap();
    let id = c.token_id();
    assert_eq!(l.state.token(id).unwrap().next_price(), 100);

    let mut b = ctx(101, 0, who(2));
    b.payments.insert(addr_key(who(1)), 100);
    l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &b).unwrap();
    assert_eq!(l.state.token(id).unwrap().next_price(), 150);

    // The old price is now insufficient.
    let mut b2 = ctx(102, 0, who(3));
    b2.payments.insert(addr_key(who(1)), 100);
    assert!(l
        .apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &b2)
        .is_err());
}

/// The deliberate exception to all-or-nothing (spec §5.3): the last claimant
/// gets a short fill instead of paying and receiving nothing.
#[test]
fn the_cap_boundary_short_fills_rather_than_rejecting() {
    let mut l = Ledger::new();
    let c = ctx(100, 0, who(1));
    l.apply(&Record::Issue(open_mint_of(25, 10, 0, 0)), &c).unwrap();
    let id = c.token_id();

    for tag in [2u8, 3] {
        l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &ctx(101, 0, who(tag)))
            .unwrap();
    }
    assert_eq!(l.state.token(id).unwrap().minted, 20);

    // Only 5 remain against a per_mint of 10 -- short fill, not rejection.
    l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &ctx(102, 0, who(4)))
        .unwrap();
    assert_eq!(l.state.balance(id, who(4)), 5);
    assert_eq!(l.state.token(id).unwrap().minted, 25);

    // Now genuinely exhausted.
    assert_eq!(
        l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &ctx(103, 0, who(5)))
            .unwrap_err(),
        Ignored::RuleViolation("mint cap reached")
    );
}

#[test]
fn mint_windows_are_enforced() {
    let mut l = Ledger::new();
    let c = ctx(100, 0, who(1));
    let mut issue = open_mint_of(100, 10, 0, 0);
    issue.terms.as_mut().unwrap().height_start = 200;
    issue.terms.as_mut().unwrap().height_end = 300;
    l.apply(&Record::Issue(issue), &c).unwrap();
    let id = c.token_id();

    let m = || Record::Mint(simple::Mint { token: id, recipient: None });
    assert!(l.apply(&m(), &ctx(150, 0, who(2))).is_err(), "before open");
    l.apply(&m(), &ctx(250, 0, who(2))).unwrap();
    assert!(l.apply(&m(), &ctx(350, 0, who(3))).is_err(), "after close");
}

#[test]
fn minting_a_non_open_token_is_rejected() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 100, FLAG_ISSUER_MINTABLE);
    assert_eq!(
        l.apply(&Record::Mint(simple::Mint { token: id, recipient: None }), &ctx(101, 0, who(2)))
            .unwrap_err(),
        Ignored::RuleViolation("token is not open-mint")
    );
}

// ---- burn, issuer, ticker --------------------------------------------------

#[test]
fn burn_reduces_the_holder_and_circulating_supply() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 100, 0);
    l.apply(&Record::Burn(simple::Burn { token: id, amount: 40 }), &ctx(101, 0, who(1)))
        .unwrap();
    assert_eq!(l.state.balance(id, who(1)), 60);
    assert_eq!(l.state.token(id).unwrap().circulating, 60);

    assert_eq!(
        l.apply(&Record::Burn(simple::Burn { token: id, amount: 61 }), &ctx(102, 0, who(1)))
            .unwrap_err(),
        Ignored::RuleViolation("insufficient balance")
    );
    assert_eq!(l.state.balance(id, who(1)), 60, "failed burn destroys nothing");
}

#[test]
fn issuer_only_actions_reject_strangers() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 10, 0);

    assert!(l
        .apply(&Record::LockSupply(simple::TokenRef { token: id }), &ctx(101, 0, who(9)))
        .is_err());
    assert!(!l.state.token(id).unwrap().supply_locked);

    l.apply(&Record::LockSupply(simple::TokenRef { token: id }), &ctx(101, 0, who(1)))
        .unwrap();
    assert!(l.state.token(id).unwrap().supply_locked);

    let it = simple::IssuerTransfer { token: id, new_issuer: who(2) };
    assert!(l.apply(&Record::IssuerTransfer(it.clone()), &ctx(102, 0, who(9))).is_err());
    l.apply(&Record::IssuerTransfer(it), &ctx(102, 0, who(1))).unwrap();
    assert_eq!(addr_key(l.state.token(id).unwrap().issuer), addr_key(who(2)));
}

/// §7.5's hard rule: a bound ticker cannot be sold away from its token, because
/// that would let the holder rename a token under its holders' feet.
#[test]
fn a_bound_ticker_cannot_be_transferred() {
    let mut l = Ledger::new();
    let issue = issue_of(b"GOLD", 5, 0);
    let commitment = commitment_of(&issue.salt.unwrap(), b"GOLD");
    l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(100, 0, who(1)))
        .unwrap();
    l.apply(&Record::Issue(issue), &ctx(120, 0, who(1))).unwrap();

    let tt = simple::TickerTransfer { ticker: b"GOLD".to_vec(), new_owner: who(2) };
    assert_eq!(
        l.apply(&Record::TickerTransfer(tt), &ctx(121, 0, who(1))).unwrap_err(),
        Ignored::RuleViolation("ticker is bound to a live token")
    );
    let ts = l.state.tickers.get(b"GOLD".as_slice()).unwrap();
    assert_eq!(addr_key(ts.owner), addr_key(who(1)));
}

#[test]
fn issuer_transfer_carries_the_ticker_with_the_token() {
    let mut l = Ledger::new();
    let issue = issue_of(b"GOLD", 5, 0);
    let commitment = commitment_of(&issue.salt.unwrap(), b"GOLD");
    l.apply(&Record::NameCommit(simple::NameCommit { commitment }), &ctx(100, 0, who(1)))
        .unwrap();
    l.apply(&Record::Issue(issue), &ctx(120, 0, who(1))).unwrap();

    l.apply(
        &Record::IssuerTransfer(simple::IssuerTransfer { token: TokenId { height: 120, tx_index: 0 }, new_issuer: who(2) }),
        &ctx(121, 0, who(1)),
    )
    .unwrap();
    let ts = l.state.tickers.get(b"GOLD".as_slice()).unwrap();
    assert_eq!(addr_key(ts.owner), addr_key(who(2)), "ticker follows the token");
}

// ---- cross-cutting ---------------------------------------------------------

#[test]
fn commitment_matches_hash160_of_salt_and_ticker() {
    // Known-answer style check: the same inputs always give the same digest,
    // and any change to either input changes it.
    let a = commitment_of(&[0x11; 20], b"GOLD");
    assert_eq!(a, commitment_of(&[0x11; 20], b"GOLD"));
    assert_ne!(a, commitment_of(&[0x12; 20], b"GOLD"));
    assert_ne!(a, commitment_of(&[0x11; 20], b"GOLE"));
    assert_eq!(a.len(), 20);
}

/// Every rejection path must be inert. This sweeps the rules engine with
/// records that should fail and asserts the ledger is untouched afterwards.
#[test]
fn every_rejected_record_leaves_state_unchanged() {
    let mut l = Ledger::new();
    let id = seed_token(&mut l, who(1), 100, 0);
    let before = format!("{:?}", l.state);

    let stranger = ctx(200, 0, who(9));
    let ghost = TokenId { height: 1, tx_index: 1 };
    let attempts = vec![
        Record::Transfer(transfer::Transfer {
            groups: vec![Group { token: id, payouts: vec![Payout { amount: 9999, to: who(2) }] }],
        }),
        Record::Transfer(transfer::Transfer {
            groups: vec![Group { token: ghost, payouts: vec![Payout { amount: 1, to: who(2) }] }],
        }),
        Record::Burn(simple::Burn { token: id, amount: 9999 }),
        Record::Burn(simple::Burn { token: ghost, amount: 1 }),
        Record::Mint(simple::Mint { token: id, recipient: None }),
        Record::LockSupply(simple::TokenRef { token: id }),
        Record::IssuerTransfer(simple::IssuerTransfer { token: id, new_issuer: who(5) }),
        Record::TickerTransfer(simple::TickerTransfer {
            ticker: b"NOPE".to_vec(),
            new_owner: who(5),
        }),
    ];
    for a in attempts {
        assert!(l.apply(&a, &stranger).is_err(), "should have been rejected: {a:?}");
    }
    assert_eq!(format!("{:?}", l.state), before, "a rejected record mutated state");
}
