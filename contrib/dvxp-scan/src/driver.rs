//! The combined overlay driver: one pass of the chain, every protocol, one
//! fingerprint, one reorg window.
//!
//! ## Why this exists rather than one driver per protocol
//!
//! Before this, the only scanner lived inside the explorer and advanced the
//! published fingerprint from **NFD deltas only**. DMT records were applied and
//! then left out of the value whose entire purpose is detecting that two
//! implementations disagree. A fingerprint that covers half the state is worse
//! than none: it reads as an assurance and is not one.
//!
//! So the fingerprint here is chained over **every** protocol's deltas for the
//! block, each tagged with its record type. Adding a protocol extends the tagged
//! sequence; it does not fork the fingerprint.
//!
//! ## Two invariants
//!
//! **A block applies completely or not at all.** Every payload in the block is
//! classified before any of them is applied, so an unreadable envelope version
//! halts the driver with the ledger still exactly as the previous block left it.
//! Halting mid-block would leave state that is neither block N nor block N-1,
//! and nothing downstream could tell.
//!
//! **Halting is permanent until a human intervenes.** A halted driver refuses
//! every subsequent block. An indexer that stops and asks to be upgraded is
//! unavailable, which is recoverable. One that guesses is divergent, which is
//! not.

use std::collections::{BTreeMap, VecDeque};

use dmt_indexer::ledger::reorg::{Chain as DmtChain, ReorgError, UNDO_DEPTH};
use dmt_indexer::ledger::state::AddrKey;
use dmt_indexer::ledger::TxContext;
use dvxp_core::codec::Address;
use dvxp_core::registry::{Fingerprint, RecordContext, RecordHandler};
use dvxp_core::{Halt, Ignored, TYPE_DMT, TYPE_NFD};
use nfd_indexer::{NfdLedger, Undo as NfdUndo};

use crate::events::{EventLog, NfdEvent, NfdEventKind, TokenEvent, TokenEventKind};

/// NFD subtypes the driver needs to recognise to record an event. The rules for
/// them live in `nfd-indexer`; these are only for describing what happened.
const NFD_SUB_MINT: u8 = 0x01;
const NFD_SUB_TRANSFER: u8 = 0x02;
const NFD_SUB_COLLECTION: u8 = 0x04;

fn addr21_key(p: &[u8]) -> Option<dmt_indexer::ledger::state::AddrKey> {
    if p.len() < 21 {
        return None;
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&p[1..21]);
    Some((p[0], h))
}

/// Tag bytes prefixing each protocol's slice of a block's deltas, so the
/// combined pre-image is unambiguous even when one protocol contributes
/// nothing. Without them, "NFD changed X, DMT changed nothing" and "NFD changed
/// nothing, DMT changed X" could hash alike.
const TAG_NFD: u8 = TYPE_NFD;
const TAG_DMT: u8 = TYPE_DMT;

/// One `OP_META` payload, with everything about its transaction the protocols
/// need.
///
/// `payments` and `burned` exist for DMT: the overlay cannot escrow DIVI, but it
/// can require that payment appears in the very same transaction, which is what
/// makes a priced mint atomic. NFD ignores both.
#[derive(Debug, Clone)]
pub struct TxPayload {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub payload: Vec<u8>,
    /// Address funding `vin[0]`. `None` when it could not be resolved, which is
    /// a skip rather than a halt: no sender means no authority to act.
    pub sender: Option<Address>,
    pub payments: BTreeMap<AddrKey, u64>,
    pub burned: u64,
}

/// One block, reduced to the parts the overlay cares about.
#[derive(Debug, Clone)]
pub struct BlockInput {
    pub height: u64,
    /// The block hash, retained so a reorg is detected by comparing hashes
    /// rather than by trusting that a height still means the same block.
    pub hash: [u8; 32],
    pub time: i64,
    /// Payloads in canonical order: transaction index, then output order.
    pub payloads: Vec<TxPayload>,
}

/// What one applied block did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    pub height: u64,
    pub fingerprint: Fingerprint,
    /// Records that changed state.
    pub applied: usize,
    /// Records deliberately ignored, with why. Never a silent drop: a skipped
    /// record is a fact about the chain and belongs in the log.
    pub skipped: Vec<(u32, Ignored)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// An envelope this build cannot read. Stop and upgrade.
    Halted(Halt),
    /// A block arrived out of order. The driver never guesses at a gap.
    NonContiguous { expected: u64, got: u64 },
    /// A reorg deeper than the retained undo window. Stop and resync.
    BeyondUndoWindow { requested: u64, oldest: u64 },
    /// Asked to roll back to a height that was never applied.
    NotApplied(u64),
    /// Every call after a halt, so a halted driver cannot be nudged back into
    /// service by simply being asked again.
    AlreadyHalted(Halt),
}

impl From<ReorgError> for ScanError {
    fn from(e: ReorgError) -> Self {
        match e {
            ReorgError::BeyondUndoWindow { requested, oldest } => {
                ScanError::BeyondUndoWindow { requested, oldest }
            }
            ReorgError::NotApplied(h) => ScanError::NotApplied(h),
        }
    }
}

/// One applied block, retained so it can be undone.
#[derive(Debug)]
struct AppliedBlock {
    height: u64,
    hash: [u8; 32],
    nfd_undo: Vec<NfdUndo>,
    fingerprint: Fingerprint,
}

/// Every overlay protocol, driven together over one pass of the chain.
#[derive(Debug)]
pub struct Overlay {
    pub nfd: NfdLedger,
    pub dmt: DmtChain,
    /// History, which neither ledger keeps: they hold what is true now, not
    /// what happened.
    pub log: EventLog,
    fingerprint: Fingerprint,
    history: VecDeque<AppliedBlock>,
    tip: Option<u64>,
    halted: Option<Halt>,
}

impl Default for Overlay {
    fn default() -> Self {
        Self::new()
    }
}

impl Overlay {
    pub fn new() -> Self {
        Self {
            nfd: NfdLedger::new(),
            dmt: DmtChain::new(),
            log: EventLog::new(),
            fingerprint: Fingerprint::genesis(),
            history: VecDeque::new(),
            tip: None,
            halted: None,
        }
    }

    /// Last applied height, or `None` before the first block.
    pub fn tip(&self) -> Option<u64> {
        self.tip
    }

    /// The combined fingerprint covering every protocol.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Why the driver stopped, if it has.
    pub fn halt_reason(&self) -> Option<&Halt> {
        self.halted.as_ref()
    }

    pub fn is_halted(&self) -> bool {
        self.halted.is_some()
    }

    /// Oldest height still revertible. A reorg below this cannot be undone.
    pub fn oldest_undo_height(&self) -> Option<u64> {
        self.history.front().map(|b| b.height)
    }

    /// The hash recorded for a height, if still retained. This is how a caller
    /// detects a reorg: ask the node for the hash at the same height and
    /// compare.
    pub fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.history.iter().find(|b| b.height == height).map(|b| b.hash)
    }

    /// Fingerprint after a given block, if still retained. Two operators compare
    /// this to check they agree.
    pub fn fingerprint_at(&self, height: u64) -> Option<Fingerprint> {
        self.history.iter().find(|b| b.height == height).map(|b| b.fingerprint)
    }

    /// Apply one block.
    ///
    /// Heights must arrive contiguously. A gap is refused rather than absorbed,
    /// because a fingerprint chained over a skipped block is a fingerprint that
    /// silently means something different from everyone else's.
    pub fn apply_block(&mut self, block: &BlockInput) -> Result<BlockSummary, ScanError> {
        if let Some(h) = &self.halted {
            return Err(ScanError::AlreadyHalted(h.clone()));
        }
        if let Some(tip) = self.tip {
            if block.height != tip + 1 {
                return Err(ScanError::NonContiguous { expected: tip + 1, got: block.height });
            }
        }

        // Pass one: classify everything before touching any state, so an
        // unreadable version halts with the ledger untouched.
        let mut classified = Vec::with_capacity(block.payloads.len());
        for tx in &block.payloads {
            match dvxp_core::classify(&tx.payload) {
                Err(halt) => {
                    self.halted = Some(halt.clone());
                    return Err(ScanError::Halted(halt));
                }
                Ok(outcome) => classified.push((tx, outcome)),
            }
        }

        // Pass two: apply.
        let mut nfd_deltas = Vec::new();
        let mut skipped = Vec::new();
        let mut applied = 0usize;

        for (tx, outcome) in classified {
            let rec = match outcome {
                Err(ignored) => {
                    skipped.push((tx.tx_index, ignored));
                    continue;
                }
                Ok(rec) => rec,
            };

            let ctx = RecordContext {
                height: block.height,
                tx_index: tx.tx_index,
                txid: tx.txid,
                block_time: block.time,
                sender: tx.sender,
            };

            match rec.record_type {
                TYPE_NFD => match self.nfd.apply(&rec, &ctx) {
                    Ok(delta) => {
                        nfd_deltas.extend_from_slice(&delta);
                        applied += 1;
                        self.record_nfd_event(&rec, &ctx, tx);
                    }
                    Err(ignored) => skipped.push((tx.tx_index, ignored)),
                },
                TYPE_DMT => {
                    // DMT is not a RecordHandler: its ledger needs the payments
                    // the transaction made, so it takes the richer context.
                    let Some(sender) = tx.sender else {
                        skipped.push((tx.tx_index, Ignored::RuleViolation("no resolvable sender")));
                        continue;
                    };
                    // Already classified above, so this cannot halt here.
                    match dmt_indexer::parse_payload(&tx.payload) {
                        Err(halt) => {
                            self.halted = Some(halt.clone());
                            return Err(ScanError::Halted(halt));
                        }
                        Ok(dmt_indexer::Outcome::Skip(ignored)) => {
                            skipped.push((tx.tx_index, ignored))
                        }
                        Ok(dmt_indexer::Outcome::Record(r)) => {
                            let tctx = TxContext {
                                height: block.height,
                                tx_index: tx.tx_index,
                                sender,
                                payments: tx.payments.clone(),
                                burned: tx.burned,
                            };
                            // Balances before, so a mint's real credit can be
                            // measured rather than assumed. A claim at the cap
                            // boundary is deliberately a SHORT fill, so the
                            // token's advertised per-mint size is not always
                            // what actually arrived.
                            let before = self.dmt.ledger.state.balances.clone();
                            match self.dmt.ledger.apply(&r, &tctx) {
                                Ok(()) => {
                                    applied += 1;
                                    self.record_token_event(&r, &tctx, tx, block.time, &before);
                                }
                                Err(ignored) => skipped.push((tx.tx_index, ignored)),
                            }
                        }
                    }
                }
                other => skipped.push((tx.tx_index, Ignored::UnknownType(other))),
            }
        }

        // Close the block. DMT keeps its own chain for its own undo window; we
        // take its delta bytes and ignore its private fingerprint, because the
        // fingerprint we publish has to cover everything.
        let (_dmt_fp, dmt_deltas) = self.dmt.end_block_deltas(block.height);

        let mut combined = Vec::with_capacity(nfd_deltas.len() + dmt_deltas.len() + 2);
        combined.push(TAG_NFD);
        combined.extend_from_slice(&nfd_deltas);
        combined.push(TAG_DMT);
        combined.extend_from_slice(&dmt_deltas);

        // Advance on every block, including empty ones. A chain that only
        // advanced on blocks with records could not distinguish "block N was
        // empty" from "I never saw block N".
        self.fingerprint = self.fingerprint.advance(block.height, &combined);

        self.history.push_back(AppliedBlock {
            height: block.height,
            hash: block.hash,
            nfd_undo: self.nfd.take_block_undo(),
            fingerprint: self.fingerprint,
        });
        while self.history.len() > UNDO_DEPTH {
            self.history.pop_front();
        }
        self.tip = Some(block.height);

        Ok(BlockSummary {
            height: block.height,
            fingerprint: self.fingerprint,
            applied,
            skipped,
        })
    }

    /// Describe what a successfully applied token record did.
    ///
    /// Only records that move units produce an event. Lock supply, issuer
    /// transfer, ticker transfer and name commit change a token's terms rather
    /// than anyone's holdings, and they are visible in the token's metadata
    /// where they belong. Inventing balance events for them would put lines in
    /// a user's history that never touched their balance.
    fn record_token_event(
        &mut self,
        rec: &dmt_indexer::Record,
        tctx: &TxContext,
        tx: &TxPayload,
        block_time: i64,
        balances_before: &BTreeMap<((u64, u32), AddrKey), u64>,
    ) {
        use dmt_indexer::ledger::state::token_key;
        use dmt_indexer::Record as R;

        let sender = dmt_indexer::ledger::state::addr_key(tctx.sender);
        // Collected first, then handed to the log in one go: the closure needs
        // the ledger for a mint's measured amount, and cannot hold the log at
        // the same time.
        let mut out: Vec<TokenEvent> = Vec::new();
        // A token is keyed by (height, tx_index); the ledger never sees the
        // transaction hash, but every explorer link needs it.
        let mut genesis: Option<((u64, u32), [u8; 32])> = None;
        let mut push = |kind, token, from, to, amount| {
            out.push(TokenEvent {
                token,
                kind,
                from,
                to,
                amount,
                height: tctx.height,
                tx_index: tctx.tx_index,
                txid: tx.txid,
                block_time,
            });
        };

        match rec {
            R::Issue(i) => {
                let token = token_key(tctx.token_id());
                genesis = Some((token, tx.txid));
                if i.premine > 0 {
                    push(TokenEventKind::Issue, token, None, Some(sender), i.premine);
                }
            }
            R::Mint(m) => {
                let token = token_key(m.token);
                let to = m
                    .recipient
                    .map(dmt_indexer::ledger::state::addr_key)
                    .unwrap_or(sender);
                // Measured, not assumed: a claim that runs into the cap is a
                // deliberate short fill, so the token's advertised per-mint size
                // is not always what arrived.
                let before = balances_before.get(&(token, to)).copied().unwrap_or(0);
                let after = self.dmt.ledger.state.balances.get(&(token, to)).copied().unwrap_or(0);
                let credited = after.saturating_sub(before);
                if credited > 0 {
                    push(TokenEventKind::Mint, token, None, Some(to), credited);
                }
            }
            R::Transfer(t) => {
                // One event per payout. An airdrop to two hundred addresses is
                // two hundred events, which is what each of those holders needs
                // to see in their own history.
                for group in &t.groups {
                    let token = token_key(group.token);
                    for payout in &group.payouts {
                        let to = dmt_indexer::ledger::state::addr_key(payout.to);
                        push(TokenEventKind::Transfer, token, Some(sender), Some(to), payout.amount);
                    }
                }
            }
            R::Burn(b) => {
                push(TokenEventKind::Burn, token_key(b.token), Some(sender), None, b.amount);
            }
            R::NameCommit(_) | R::LockSupply(_) | R::IssuerTransfer(_) | R::TickerTransfer(_) => {}
        }

        drop(push);
        if let Some((token, txid)) = genesis {
            self.log.record_token_genesis(token, txid);
        }
        for e in out {
            self.log.push_token(e);
        }
    }

    /// Describe what a successfully applied collectible record did.
    ///
    /// The bodies are re-read here rather than threaded out of `nfd-indexer`,
    /// which returns only its fingerprint delta. Re-reading is safe because the
    /// record already applied cleanly, so the layout is known good; the only
    /// cost is a few bounds checks.
    fn record_nfd_event(&mut self, rec: &dvxp_core::Record, ctx: &RecordContext, tx: &TxPayload) {
        let sender = ctx.sender.map(dmt_indexer::ledger::state::addr_key);
        let (kind, id, from, to) = match rec.subtype {
            NFD_SUB_MINT => (NfdEventKind::Mint, ctx.txid, None, sender),
            NFD_SUB_TRANSFER => {
                let Some(id) = rec.body.get(0..32) else { return };
                let mut mint_txid = [0u8; 32];
                mint_txid.copy_from_slice(id);
                let to = rec.body.get(32..53).and_then(addr21_key);
                (NfdEventKind::Transfer, mint_txid, sender, to)
            }
            NFD_SUB_COLLECTION => (NfdEventKind::CollectionCreate, ctx.txid, None, sender),
            // Key announce changes no ownership, so it is not an event about a
            // collectible.
            _ => return,
        };

        self.log.push_nfd(NfdEvent {
            id,
            kind,
            from,
            to,
            height: ctx.height,
            txid: tx.txid,
            block_time: ctx.block_time,
        });
    }

    /// Roll every protocol back to the state after `height`.
    ///
    /// Divi hard-caps reorgs at 100 blocks and the window retains 200, so this
    /// is twice the deepest reorg the chain permits. Beyond it the driver halts
    /// rather than serving state it cannot justify.
    pub fn rollback_to(&mut self, height: u64) -> Result<(), ScanError> {
        let Some(tip) = self.tip else {
            return Err(ScanError::NotApplied(height));
        };
        if height > tip {
            return Err(ScanError::NotApplied(height));
        }
        if height == tip {
            return Ok(());
        }
        if let Some(oldest) = self.oldest_undo_height() {
            if height < oldest {
                return Err(ScanError::BeyondUndoWindow { requested: height, oldest });
            }
        }

        // DMT first, so that if its window disagrees with ours we fail before
        // having half-unwound anything.
        self.dmt.rollback_to(height)?;

        while let Some(last) = self.history.back() {
            if last.height <= height {
                break;
            }
            let block = self.history.pop_back().expect("checked above");
            self.nfd.rollback_block(block.nfd_undo);
        }
        // An event that outlived its block would report activity the chain no
        // longer contains.
        self.log.rollback_above(height);

        self.fingerprint = self
            .history
            .back()
            .map(|b| b.fingerprint)
            .unwrap_or_else(Fingerprint::genesis);
        self.tip = self.history.back().map(|b| b.height).or(Some(height));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::{MAGIC, SUPPORTED_VERSION};

    fn addr(b: u8) -> Address {
        Address { kind: 0, hash160: [b; 20] }
    }

    fn envelope(record_type: u8, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend_from_slice(&[SUPPORTED_VERSION, record_type, subtype]);
        v.extend_from_slice(body);
        v
    }

    /// An NFD mint body with no thumbnail and no collection.
    fn nfd_mint() -> Vec<u8> {
        let mut b = vec![0xaa; 32]; // arweave_ptr
        b.extend_from_slice(&[0xbb; 32]); // content_hash
        b.push(0x01); // flags
        b
    }

    fn tx(tx_index: u32, txid: u8, payload: Vec<u8>, sender: Option<Address>) -> TxPayload {
        TxPayload {
            tx_index,
            txid: [txid; 32],
            payload,
            sender,
            payments: BTreeMap::new(),
            burned: 0,
        }
    }

    fn block(height: u64, hash: u8, payloads: Vec<TxPayload>) -> BlockInput {
        BlockInput { height, hash: [hash; 32], time: 1_700_000_000, payloads }
    }

    fn empty(height: u64, hash: u8) -> BlockInput {
        block(height, hash, vec![])
    }

    #[test]
    fn an_empty_block_still_advances_the_fingerprint() {
        let mut o = Overlay::new();
        let before = o.fingerprint();
        o.apply_block(&empty(1, 1)).unwrap();
        assert_ne!(o.fingerprint(), before, "a processed block must be attested");
        assert_eq!(o.tip(), Some(1));
    }

    /// The defect this crate was written to fix. Token activity has to move the
    /// published fingerprint; when it did not, the anti-divergence check was
    /// blind to every token in existence.
    #[test]
    fn token_activity_moves_the_combined_fingerprint() {
        let mut with_token = Overlay::new();
        let mut without = Overlay::new();

        // A DMT burn of a token that does not exist is REJECTED by the ledger,
        // so use an issue, which does change state.
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 20]); // salt
        let commit = envelope(TYPE_DMT, 0x04, &body); // NAME COMMIT

        with_token
            .apply_block(&block(1, 1, vec![tx(0, 1, commit, Some(addr(7)))]))
            .unwrap();
        without.apply_block(&empty(1, 1)).unwrap();

        assert_ne!(
            with_token.fingerprint(),
            without.fingerprint(),
            "a block containing a token record must not fingerprint like an empty one"
        );
    }

    #[test]
    fn collectible_activity_moves_the_combined_fingerprint() {
        let mut with_nfd = Overlay::new();
        let mut without = Overlay::new();

        let mint = envelope(TYPE_NFD, 0x01, &nfd_mint());
        with_nfd
            .apply_block(&block(1, 1, vec![tx(0, 1, mint, Some(addr(7)))]))
            .unwrap();
        without.apply_block(&empty(1, 1)).unwrap();

        assert_ne!(with_nfd.fingerprint(), without.fingerprint());
        assert_eq!(with_nfd.nfd.count(), 1);
    }

    #[test]
    fn heights_must_be_contiguous() {
        let mut o = Overlay::new();
        o.apply_block(&empty(10, 1)).unwrap();
        assert_eq!(
            o.apply_block(&empty(12, 2)),
            Err(ScanError::NonContiguous { expected: 11, got: 12 })
        );
    }

    /// A block whose second record cannot be read must leave the first one
    /// unapplied. Half a block is a state nothing downstream could describe.
    #[test]
    fn an_unreadable_version_halts_without_applying_the_rest_of_the_block() {
        let mut o = Overlay::new();
        o.apply_block(&empty(1, 1)).unwrap();
        let fp_before = o.fingerprint();

        let good = envelope(TYPE_NFD, 0x01, &nfd_mint());
        let mut future = MAGIC.to_vec();
        future.extend_from_slice(&[0x99, TYPE_NFD, 0x01]);

        let result = o.apply_block(&block(
            2,
            2,
            vec![tx(0, 1, good, Some(addr(7))), tx(1, 2, future, Some(addr(7)))],
        ));

        assert!(matches!(result, Err(ScanError::Halted(_))));
        assert_eq!(o.nfd.count(), 0, "the good record must not have been applied");
        assert_eq!(o.fingerprint(), fp_before, "the fingerprint must not have moved");
        assert_eq!(o.tip(), Some(1), "the block must not count as applied");
    }

    #[test]
    fn a_halted_driver_refuses_everything_afterwards() {
        let mut o = Overlay::new();
        let mut future = MAGIC.to_vec();
        future.extend_from_slice(&[0x99, TYPE_NFD, 0x01]);
        let _ = o.apply_block(&block(1, 1, vec![tx(0, 1, future, Some(addr(7)))]));
        assert!(o.is_halted());
        assert!(matches!(o.apply_block(&empty(1, 1)), Err(ScanError::AlreadyHalted(_))));
    }

    #[test]
    fn junk_is_skipped_with_a_reason_never_dropped_silently() {
        let mut o = Overlay::new();
        let s = o
            .apply_block(&block(
                1,
                1,
                vec![
                    tx(0, 1, b"not a record".to_vec(), Some(addr(7))),
                    tx(1, 2, envelope(0x7f, 0x01, &[]), Some(addr(7))),
                ],
            ))
            .unwrap();
        assert_eq!(s.applied, 0);
        assert_eq!(s.skipped.len(), 2, "every skip is reported");
    }

    #[test]
    fn a_reorg_unwinds_both_protocols_and_restores_the_fingerprint() {
        let mut o = Overlay::new();
        o.apply_block(&empty(1, 1)).unwrap();
        let fp_at_1 = o.fingerprint();

        let mint = envelope(TYPE_NFD, 0x01, &nfd_mint());
        o.apply_block(&block(2, 2, vec![tx(0, 9, mint, Some(addr(7)))])).unwrap();
        assert_eq!(o.nfd.count(), 1);
        assert_ne!(o.fingerprint(), fp_at_1);

        o.rollback_to(1).unwrap();
        assert_eq!(o.nfd.count(), 0, "the collectible is gone with its block");
        assert_eq!(o.tip(), Some(1));
        assert_eq!(o.fingerprint(), fp_at_1, "the fingerprint returns to where it was");
    }

    /// Replaying a different block 2 after a reorg must not reproduce the
    /// fingerprint of the block it replaced.
    #[test]
    fn a_replaced_block_fingerprints_differently() {
        let mut o = Overlay::new();
        o.apply_block(&empty(1, 1)).unwrap();
        let mint = envelope(TYPE_NFD, 0x01, &nfd_mint());
        o.apply_block(&block(2, 2, vec![tx(0, 9, mint.clone(), Some(addr(7)))])).unwrap();
        let original = o.fingerprint();

        o.rollback_to(1).unwrap();
        o.apply_block(&empty(2, 3)).unwrap();
        assert_ne!(o.fingerprint(), original);
    }

    #[test]
    fn hashes_are_retained_so_a_reorg_can_be_detected() {
        let mut o = Overlay::new();
        o.apply_block(&empty(1, 0xaa)).unwrap();
        o.apply_block(&empty(2, 0xbb)).unwrap();
        assert_eq!(o.hash_at(1), Some([0xaa; 32]));
        assert_eq!(o.hash_at(2), Some([0xbb; 32]));
        assert_eq!(o.hash_at(3), None);
    }

    #[test]
    fn rolling_back_past_the_window_refuses_rather_than_guessing() {
        let mut o = Overlay::new();
        for h in 1..=(UNDO_DEPTH as u64 + 20) {
            o.apply_block(&empty(h, (h % 251) as u8)).unwrap();
        }
        let oldest = o.oldest_undo_height().unwrap();
        assert!(oldest > 1, "the window must have dropped the earliest blocks");
        assert!(matches!(
            o.rollback_to(oldest - 1),
            Err(ScanError::BeyondUndoWindow { .. })
        ));
    }

    #[test]
    fn the_window_never_grows_past_its_depth() {
        let mut o = Overlay::new();
        for h in 1..=(UNDO_DEPTH as u64 + 50) {
            o.apply_block(&empty(h, (h % 251) as u8)).unwrap();
        }
        assert_eq!(o.history.len(), UNDO_DEPTH);
    }

    // ---- end to end: records in, queries out ---------------------------
    //
    // These build real record bodies rather than poking the ledgers, so they
    // exercise the whole path: envelope, classify, route, apply, journal,
    // fingerprint, query. Encoders live here because the write path (Phase 5)
    // does not exist yet; when it does, these should switch to it so the tests
    // stop being a second implementation of the same layout.

    use dvxp_core::varint::write_varint;

    fn issue_body(premine: u64) -> Vec<u8> {
        let mut b = vec![0u8]; // flags: no ticker, no open mint
        b.push(0); // decimals
        b.push(0); // ticker_len: 0 means no ticker, so no salt follows
        write_varint(&mut b, premine);
        b
    }

    fn transfer_body(token: (u64, u32), amount: u64, to: Address) -> Vec<u8> {
        let mut b = Vec::new();
        write_varint(&mut b, 1); // one group
        write_varint(&mut b, token.0); // first group's height is an absolute delta
        write_varint(&mut b, token.1 as u64);
        write_varint(&mut b, 1); // one recipient
        write_varint(&mut b, amount);
        to.write(&mut b);
        b
    }

    fn burn_body(token: (u64, u32), amount: u64) -> Vec<u8> {
        let mut b = Vec::new();
        write_varint(&mut b, token.0);
        write_varint(&mut b, token.1 as u64);
        write_varint(&mut b, amount);
        b
    }

    fn key(a: Address) -> AddrKey {
        dmt_indexer::ledger::state::addr_key(a)
    }

    /// A transaction that has paid the token creation fee.
    ///
    /// Note what this exposes: the fee is checked against
    /// `config::treasury()`, which is still the all-zero placeholder, so a
    /// payment to an unspendable address currently satisfies it. That is
    /// exactly why `treasury_is_configured()` exists, and why the daemon now
    /// refuses to start while it returns false.
    fn tx_with_fee(tx_index: u32, txid: u8, payload: Vec<u8>, sender: Address) -> TxPayload {
        let mut payments = BTreeMap::new();
        payments.insert(
            dmt_indexer::ledger::state::addr_key(dmt_indexer::config::treasury()),
            dmt_indexer::fees::token_creation_fee_duffs(),
        );
        TxPayload { tx_index, txid: [txid; 32], payload, sender: Some(sender), payments, burned: 0 }
    }

    /// Issue 1000, send 300 away, burn 100. Then ask the questions a wallet
    /// asks and check every answer.
    #[test]
    fn a_token_can_be_issued_sent_burned_and_then_queried() {
        use crate::query;

        let mut o = Overlay::new();
        let issuer = addr(7);
        let other = addr(9);

        // Block 1: issue. The token's id is (height, tx_index) of this record.
        o.apply_block(&block(
            1,
            1,
            vec![tx_with_fee(0, 0xaa, envelope(TYPE_DMT, 0x01, &issue_body(1000)), issuer)],
        ))
        .unwrap();
        let token = (1u64, 0u32);

        assert_eq!(
            query::balances(&o, &[key(issuer)]),
            vec![query::TokenBalance { token, amount: 1000 }]
        );

        let meta = query::token_meta(&o, token).expect("the token exists");
        assert_eq!(meta.total_supply, 1000);
        assert_eq!(meta.issuer, key(issuer));
        assert_eq!(
            meta.genesis_txid,
            Some([0xaa; 32]),
            "the issuing txid is recorded, since the ledger never sees it"
        );

        // Block 2: send 300 to someone else.
        o.apply_block(&block(
            2,
            2,
            vec![tx(
                0,
                0xbb,
                envelope(TYPE_DMT, 0x02, &transfer_body(token, 300, other)),
                Some(issuer),
            )],
        ))
        .unwrap();

        // Block 3: burn 100 of what is left.
        o.apply_block(&block(
            3,
            3,
            vec![tx(0, 0xcc, envelope(TYPE_DMT, 0x05, &burn_body(token, 100)), Some(issuer))],
        ))
        .unwrap();

        assert_eq!(
            query::balances(&o, &[key(issuer)]),
            vec![query::TokenBalance { token, amount: 600 }],
            "1000 issued, 300 sent, 100 burned"
        );
        assert_eq!(
            query::balances(&o, &[key(other)]),
            vec![query::TokenBalance { token, amount: 300 }]
        );
        assert_eq!(
            query::token_meta(&o, token).unwrap().total_supply,
            900,
            "a burn reduces supply; a transfer does not"
        );

        // History, newest first, from the issuer's side.
        let mine = query::history(&o, &[key(issuer)], 50);
        let kinds: Vec<_> = mine.iter().map(|h| h.kind).collect();
        assert_eq!(
            kinds,
            vec![query::HistoryKind::Burn, query::HistoryKind::TransferOut, query::HistoryKind::Issue]
        );
        assert_eq!(mine[1].counterparty, Some(key(other)));

        // The same transfer, from the other side, is an incoming line.
        let theirs = query::history(&o, &[key(other)], 50);
        assert_eq!(theirs.len(), 1, "they were not party to the issue or the burn");
        assert_eq!(theirs[0].kind, query::HistoryKind::TransferIn);
        assert_eq!(theirs[0].counterparty, Some(key(issuer)));
        assert_eq!(theirs[0].amount, 300);
    }

    /// A reorg must take the history with it. An event log that outlived its
    /// block would show a user activity the chain no longer contains.
    #[test]
    fn rolling_back_discards_the_events_and_the_genesis_txid() {
        use crate::query;

        let mut o = Overlay::new();
        let issuer = addr(7);
        let other = addr(9);

        // An empty block first, so there is something below the issue to roll
        // back to. You cannot unwind past the earliest block you ever applied,
        // and the driver says so rather than guessing.
        o.apply_block(&empty(1, 1)).unwrap();

        o.apply_block(&block(
            2,
            2,
            vec![tx_with_fee(0, 0xaa, envelope(TYPE_DMT, 0x01, &issue_body(1000)), issuer)],
        ))
        .unwrap();
        let token = (2u64, 0u32);

        o.apply_block(&block(
            3,
            3,
            vec![tx(
                0,
                0xbb,
                envelope(TYPE_DMT, 0x02, &transfer_body(token, 300, other)),
                Some(issuer),
            )],
        ))
        .unwrap();
        assert_eq!(query::history(&o, &[key(other)], 50).len(), 1);

        o.rollback_to(2).unwrap();

        assert!(
            query::history(&o, &[key(other)], 50).is_empty(),
            "the transfer's event goes with its block"
        );
        assert!(query::balances(&o, &[key(other)]).is_empty());
        assert_eq!(
            query::balances(&o, &[key(issuer)]),
            vec![query::TokenBalance { token, amount: 1000 }],
            "and the units come back"
        );
        assert!(
            query::token_meta(&o, token).unwrap().genesis_txid.is_some(),
            "block 2 survived, so its token keeps its txid"
        );

        // Now discard the issue too.
        o.rollback_to(1).unwrap();
        assert!(query::all_tokens(&o).is_empty());
        assert_eq!(o.log.token_event_count(), 0);
        assert_eq!(
            query::token_meta(&o, token),
            None,
            "the token and its genesis txid are both gone"
        );
    }

    /// A block page asks one question, not one per transaction in the block.
    #[test]
    fn a_block_reports_its_own_overlay_activity() {
        use crate::query;

        let mut o = Overlay::new();
        let minter = addr(7);

        assert!(query::block_activity(&o, 1).is_empty());

        o.apply_block(&block(
            1,
            1,
            vec![tx(0, 0x11, envelope(TYPE_NFD, 0x01, &nfd_mint()), Some(minter))],
        ))
        .unwrap();

        let a = query::block_activity(&o, 1);
        assert_eq!(a.minted.len(), 1);
        assert_eq!(a.minted[0].id, [0x11; 32]);
        assert!(a.transferred.is_empty());
        assert!(!a.is_empty());

        // A block with nothing in it says so, rather than being indistinguishable
        // from a block the index has not reached.
        o.apply_block(&empty(2, 2)).unwrap();
        assert!(query::block_activity(&o, 2).is_empty());
    }

    /// The trap a transaction page falls into if it looks its own txid up as a
    /// collectible id: that finds the mint and misses the transfer entirely.
    #[test]
    fn a_transfer_is_found_by_its_own_transaction_not_the_collectible_id() {
        use crate::query;

        let mut o = Overlay::new();
        let minter = addr(7);
        let buyer = addr(9);

        o.apply_block(&block(
            1,
            1,
            vec![tx(0, 0x11, envelope(TYPE_NFD, 0x01, &nfd_mint()), Some(minter))],
        ))
        .unwrap();
        let id = [0x11u8; 32];

        let mut body = id.to_vec();
        let mut packed = Vec::new();
        buyer.write(&mut packed);
        body.extend_from_slice(&packed);
        body.extend_from_slice(&[0u8; 32]);

        // The transfer rides a DIFFERENT transaction from the mint.
        o.apply_block(&block(
            2,
            2,
            vec![tx(0, 0x99, envelope(TYPE_NFD, 0x02, &body), Some(minter))],
        ))
        .unwrap();

        // Looked up as a collectible id, tx 0x99 is nothing at all.
        assert_eq!(query::nfd(&o, &[0x99; 32]), None);

        // Looked up as a transaction, it is the transfer.
        let a = query::tx_activity(&o, &[0x99; 32]);
        assert_eq!(a.transferred.len(), 1);
        assert_eq!(a.transferred[0].id, id);
        assert!(a.minted.is_empty());

        // And the mint transaction reports the mint, not the transfer.
        let m = query::tx_activity(&o, &[0x11; 32]);
        assert_eq!(m.minted.len(), 1);
        assert!(m.transferred.is_empty());
    }

    /// Collectible events are recorded the same way and read back per owner.
    #[test]
    fn collectible_ownership_and_history_read_back() {
        use crate::query;

        let mut o = Overlay::new();
        let minter = addr(7);
        let buyer = addr(9);

        o.apply_block(&block(
            1,
            1,
            vec![tx(0, 0x11, envelope(TYPE_NFD, 0x01, &nfd_mint()), Some(minter))],
        ))
        .unwrap();
        let id = [0x11u8; 32];

        assert_eq!(query::nfds_owned_by(&o, key(minter)).len(), 1);
        assert_eq!(query::nfd(&o, &id).unwrap().owner, key(minter));

        // Transfer it: 32-byte id, 21-byte new owner, 32-byte wrapkey pointer.
        let mut body = id.to_vec();
        let mut packed = Vec::new();
        buyer.write(&mut packed);
        body.extend_from_slice(&packed);
        body.extend_from_slice(&[0u8; 32]);

        o.apply_block(&block(
            2,
            2,
            vec![tx(0, 0x22, envelope(TYPE_NFD, 0x02, &body), Some(minter))],
        ))
        .unwrap();

        assert_eq!(query::nfd(&o, &id).unwrap().owner, key(buyer));
        assert!(query::nfds_owned_by(&o, key(minter)).is_empty());
        assert_eq!(query::nfds_owned_by(&o, key(buyer)).len(), 1);
        assert_eq!(o.log.nfd_event_count(), 2, "the mint and the transfer");
    }
}
