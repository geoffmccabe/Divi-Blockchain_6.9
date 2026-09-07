//! Following a chain: catching up, staying current, and unwinding a reorg.
//!
//! ## Why this is not inside the daemon
//!
//! Two very different programs need to do exactly this. The explorer runs a
//! daemon beside its node. The wallet embeds the scanner and drives it from its
//! own node connection, with no HTTP client compiled in at all, because a
//! self-custody wallet that got its balances from a service would let that
//! service's downtime hide a user's own holdings from them.
//!
//! Those two differ **only in how a block is fetched**. Everything else, the
//! order blocks are applied in, when a reorg is detected, how far back it may be
//! unwound, when to give up, is identical and must stay identical. Written twice,
//! it would not: one copy would gain a fix the other did not, and the wallet and
//! the explorer would disagree about the same chain while both looking healthy.
//!
//! So the loop lives here once, over a [`BlockSource`], and each host supplies
//! only the fetching.
//!
//! ## Yielding to the node
//!
//! Catching up is the one thing this crate does that can hurt its host. Divi
//! allocates a node thread per application connection and the pool is small; an
//! earlier scanner saturated it and took the public explorer offline. In a
//! wallet it would be worse, because the node it is starving is the one the user
//! is staking with.
//!
//! [`Follower::catch_up`] therefore works in **bounded slices** and returns. The
//! caller decides when to come back, which is the only arrangement where the
//! host can put its own work first.

use crate::driver::{BlockInput, Overlay, ScanError};

/// Where blocks come from. The only thing a host has to provide.
pub trait BlockSource {
    /// The chain's current height.
    fn tip(&mut self) -> Result<u64, String>;

    /// The hash at a height, as the node displays it. Used to detect a reorg by
    /// comparing against what was recorded, rather than trusting that a height
    /// still means the same block.
    fn block_hash(&mut self, height: u64) -> Result<String, String>;

    /// One block, reduced to the overlay records it carries.
    fn block_at(&mut self, height: u64) -> Result<BlockInput, String>;
}

/// Why following stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowError {
    /// The node could not be reached, or answered something unusable. Usually
    /// temporary: the caller may retry.
    Source(String),
    /// The chain moved in a way this index cannot follow, or a record cannot be
    /// read by this build. Not temporary: a human has to act.
    Fatal(ScanError),
}

impl std::fmt::Display for FollowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FollowError::Source(e) => write!(f, "{e}"),
            FollowError::Fatal(ScanError::Halted(h)) | FollowError::Fatal(ScanError::AlreadyHalted(h)) => {
                write!(f, "this build cannot read a record on the chain ({h:?}); upgrade and restart")
            }
            FollowError::Fatal(ScanError::BeyondUndoWindow { requested, oldest }) => write!(
                f,
                "the chain reorganised further back ({requested}) than this index can undo ({oldest}); a resync is needed"
            ),
            FollowError::Fatal(e) => write!(f, "the index cannot continue: {e:?}"),
        }
    }
}

/// What one slice of catching up did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Progress {
    /// Blocks applied in this slice.
    pub applied: u64,
    /// Height after the slice.
    pub height: u64,
    /// The chain's tip when the slice started.
    pub tip: u64,
    /// Records that changed state.
    pub records: usize,
    /// Records deliberately ignored, with why and where. Never dropped
    /// silently: a skipped record is a fact about the chain and the only place
    /// it can be investigated from is a log.
    pub skipped: Vec<(u64, u32, dvxp_core::Ignored)>,
    /// True when there is nothing left to apply right now.
    pub caught_up: bool,
}

/// Where on the chain an index has got to, and how it gets further.
///
/// Deliberately does **not** own the [`Overlay`]. The daemon keeps its state
/// behind a lock so the read API can serve from it while scanning continues, and
/// a wallet will hold it differently again. A follower that owned the state
/// would force one of those choices on both.
pub struct Follower {
    /// The first height this index counts from. Records below it are ignored by
    /// the rules, so starting here is not an optimisation: it is the definition.
    genesis: u64,
    next: u64,
}

impl Follower {
    pub fn new(genesis: u64) -> Self {
        Self { genesis, next: genesis }
    }

    pub fn genesis(&self) -> u64 {
        self.genesis
    }

    /// The next height that will be applied.
    pub fn next_height(&self) -> u64 {
        self.next
    }

    /// Height reached, given the state this follower has been driving.
    pub fn height(&self, overlay: &Overlay) -> u64 {
        overlay.tip().unwrap_or(self.genesis.saturating_sub(1))
    }

    /// Apply up to `budget` blocks, then return whatever happened.
    ///
    /// Bounded on purpose. See the note on yielding at the top of this module:
    /// the caller owns the decision about when the index gets the node again,
    /// because in a wallet that node is also staking.
    pub fn catch_up<S: BlockSource>(
        &mut self,
        overlay: &mut Overlay,
        source: &mut S,
        budget: u64,
    ) -> Result<Progress, FollowError> {
        let tip = source.tip().map_err(FollowError::Source)?;
        let mut p = Progress { tip, height: self.height(overlay), ..Default::default() };

        for _ in 0..budget {
            if self.next > tip {
                p.caught_up = true;
                break;
            }
            let block = source.block_at(self.next).map_err(FollowError::Source)?;
            let summary = overlay.apply_block(&block).map_err(FollowError::Fatal)?;

            for (tx_index, why) in summary.skipped {
                p.skipped.push((self.next, tx_index, why));
            }
            p.records += summary.applied;
            p.applied += 1;
            p.height = self.next;
            self.next += 1;
        }

        if self.next > tip {
            p.caught_up = true;
        }
        Ok(p)
    }

    /// Has the chain replaced blocks already applied, and if so, unwind them.
    ///
    /// Compares the hash the node reports at the current tip with the one
    /// recorded. Matching means nothing moved. Differing means walking back to
    /// the fork point and undoing everything above it.
    ///
    /// Divi caps reorganisations at 100 blocks and the undo window retains 200,
    /// so the search is bounded by design rather than by hope. Beyond the window
    /// this returns a fatal error instead of serving state it cannot justify.
    ///
    /// Returns the height rolled back to, or `None` if nothing changed.
    pub fn check_for_reorg<S: BlockSource>(
        &mut self,
        overlay: &mut Overlay,
        source: &mut S,
    ) -> Result<Option<u64>, FollowError> {
        let Some(our_tip) = overlay.tip() else { return Ok(None) };

        // A reorg can leave the chain SHORTER than it was, and then there is no
        // block at our own tip height to compare against. Asking for one gets a
        // "height out of range" from the node, which is indistinguishable from
        // the node being unwell unless the tip is checked first. Without this
        // the index would treat a shortening reorg as a transient failure and
        // retry forever, never unwinding, while quietly serving state from a
        // chain that no longer exists.
        let node_tip = source.tip().map_err(FollowError::Source)?;
        let mut compare_from = our_tip.min(node_tip);

        if compare_from < our_tip {
            // Already known to differ: our tip is not on the chain at all.
        } else {
            let Some(our_hash) = overlay.hash_at(compare_from) else { return Ok(None) };
            if self.hash_matches(source, compare_from, our_hash)? {
                return Ok(None);
            }
        }

        let oldest = overlay.oldest_undo_height().unwrap_or(our_tip);
        // Start the walk at the highest height that could still match.
        compare_from = compare_from.min(our_tip);
        let mut height = compare_from + 1;
        while height > oldest {
            height -= 1;
            let Some(stored) = overlay.hash_at(height) else { break };
            if self.hash_matches(source, height, stored)? {
                overlay.rollback_to(height).map_err(FollowError::Fatal)?;
                self.next = height + 1;
                return Ok(Some(height));
            }
        }

        Err(FollowError::Fatal(ScanError::BeyondUndoWindow { requested: oldest, oldest }))
    }

    fn hash_matches<S: BlockSource>(
        &self,
        source: &mut S,
        height: u64,
        expected: [u8; 32],
    ) -> Result<bool, FollowError> {
        let hex = source.block_hash(height).map_err(FollowError::Source)?;
        Ok(crate::parse::hash_bytes(&hex) == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::TxPayload;
    use dvxp_core::codec::Address;
    use dvxp_core::{MAGIC, SUPPORTED_VERSION, TYPE_NFD};
    use std::collections::BTreeMap;

    /// A chain held in memory, so the loop can be tested without a node. Blocks
    /// can be replaced, which is how a reorg is simulated.
    struct FakeChain {
        blocks: Vec<(u64, [u8; 32], Vec<TxPayload>)>,
        calls: usize,
    }

    impl FakeChain {
        fn new() -> Self {
            Self { blocks: Vec::new(), calls: 0 }
        }

        fn push(&mut self, hash: u8, payloads: Vec<TxPayload>) {
            let height = self.blocks.len() as u64 + 1;
            self.blocks.push((height, [hash; 32], payloads));
        }

        /// Replace everything above `height`, as a reorg does.
        fn reorg_from(&mut self, height: u64, hash: u8) {
            self.blocks.truncate(height as usize);
            self.push(hash, vec![]);
        }
    }

    impl BlockSource for FakeChain {
        fn tip(&mut self) -> Result<u64, String> {
            self.calls += 1;
            Ok(self.blocks.len() as u64)
        }

        fn block_hash(&mut self, height: u64) -> Result<String, String> {
            self.calls += 1;
            self.blocks
                .iter()
                .find(|(h, _, _)| *h == height)
                .map(|(_, hash, _)| hash.iter().rev().map(|b| format!("{b:02x}")).collect())
                .ok_or_else(|| format!("no block at {height}"))
        }

        fn block_at(&mut self, height: u64) -> Result<BlockInput, String> {
            self.calls += 1;
            self.blocks
                .iter()
                .find(|(h, _, _)| *h == height)
                .map(|(h, hash, p)| BlockInput {
                    height: *h,
                    hash: *hash,
                    time: 1_700_000_000,
                    payloads: p.clone(),
                })
                .ok_or_else(|| format!("no block at {height}"))
        }
    }

    fn nfd_mint_tx(txid: u8) -> TxPayload {
        let mut body = vec![0xaa; 32];
        body.extend_from_slice(&[0xbb; 32]);
        body.push(0x01);
        let mut payload = MAGIC.to_vec();
        payload.extend_from_slice(&[SUPPORTED_VERSION, TYPE_NFD, 0x01]);
        payload.extend_from_slice(&body);
        TxPayload {
            tx_index: 0,
            txid: [txid; 32],
            payload,
            sender: Some(Address { kind: 0, hash160: [7; 20] }),
            payments: BTreeMap::new(),
            burned: 0,
        }
    }

    #[test]
    fn catching_up_stops_at_the_budget_and_resumes_where_it_left_off() {
        let mut chain = FakeChain::new();
        for i in 1..=10u8 {
            chain.push(i, vec![]);
        }
        let mut f = Follower::new(1);
        let mut o = Overlay::new();

        let first = f.catch_up(&mut o, &mut chain, 4).unwrap();
        assert_eq!(first.applied, 4);
        assert_eq!(first.height, 4);
        assert!(!first.caught_up, "there are six blocks left");

        let second = f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(second.applied, 6, "it resumes rather than restarting");
        assert_eq!(second.height, 10);
        assert!(second.caught_up);

        // Nothing left to do, and asking again is cheap rather than an error.
        let third = f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(third.applied, 0);
        assert!(third.caught_up);
    }

    /// The genesis height is the definition of where this index starts, not an
    /// optimisation: records below it are ignored by the rules.
    #[test]
    fn it_starts_at_the_genesis_height_and_never_below() {
        let mut chain = FakeChain::new();
        for i in 1..=6u8 {
            chain.push(i, vec![]);
        }
        let mut f = Follower::new(4);
        let mut o = Overlay::new();
        let p = f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(p.applied, 3, "blocks 4, 5 and 6 only");
        assert_eq!(o.tip(), Some(6));
        assert_eq!(o.oldest_undo_height(), Some(4));
    }

    #[test]
    fn records_are_applied_and_skips_are_reported_with_their_height() {
        let mut chain = FakeChain::new();
        chain.push(1, vec![nfd_mint_tx(0x11)]);
        // Junk in the next block: skipped with a reason, never dropped.
        let mut junk = nfd_mint_tx(0x22);
        junk.payload = b"not a record".to_vec();
        chain.push(2, vec![junk]);

        let mut f = Follower::new(1);
        let mut o = Overlay::new();
        let p = f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(p.records, 1);
        assert_eq!(o.nfd.count(), 1);
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].0, 2, "the height is reported, so it can be found again");
    }

    #[test]
    fn a_reorg_is_detected_unwound_and_re_applied_from_the_fork() {
        let mut chain = FakeChain::new();
        chain.push(1, vec![]);
        chain.push(2, vec![nfd_mint_tx(0x11)]);
        chain.push(3, vec![]);

        let mut f = Follower::new(1);
        let mut o = Overlay::new();
        f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(o.nfd.count(), 1);
        assert_eq!(f.height(&o), 3);

        // Blocks 2 and 3 are replaced by a SHORTER chain: there is now no block
        // at height 3 at all, which is the case that used to look like a broken
        // node rather than a reorg.
        chain.reorg_from(1, 0x99);

        let rolled = f.check_for_reorg(&mut o, &mut chain).unwrap();
        assert_eq!(rolled, Some(1), "unwound to the fork point");
        assert_eq!(o.nfd.count(), 0, "the collectible went with its block");
        assert_eq!(f.next_height(), 2, "and it will re-apply from there");

        let p = f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(p.applied, 1, "the one replacement block");
        assert_eq!(o.nfd.count(), 0, "which does not contain it");
    }

    #[test]
    fn an_unchanged_chain_is_not_reported_as_a_reorg() {
        let mut chain = FakeChain::new();
        chain.push(1, vec![]);
        chain.push(2, vec![]);
        let mut f = Follower::new(1);
        let mut o = Overlay::new();
        f.catch_up(&mut o, &mut chain, 100).unwrap();
        assert_eq!(f.check_for_reorg(&mut o, &mut chain).unwrap(), None);
    }

    /// A node that goes away must be a retryable error, not a fatal one: the
    /// wallet's node restarts all the time and the index should wait, not halt.
    #[test]
    fn losing_the_node_is_retryable_rather_than_fatal() {
        struct Dead;
        impl BlockSource for Dead {
            fn tip(&mut self) -> Result<u64, String> {
                Err("connection refused".into())
            }
            fn block_hash(&mut self, _: u64) -> Result<String, String> {
                Err("connection refused".into())
            }
            fn block_at(&mut self, _: u64) -> Result<BlockInput, String> {
                Err("connection refused".into())
            }
        }
        let mut f = Follower::new(1);
        let mut o = Overlay::new();
        match f.catch_up(&mut o, &mut Dead, 10) {
            Err(FollowError::Source(e)) => assert!(e.contains("refused")),
            other => panic!("a missing node must be retryable, got {other:?}"),
        }
    }
}
