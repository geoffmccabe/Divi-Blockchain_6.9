//! A per-epoch Merkle commitment to who owns which collectible.
//!
//! ## What this is for, and what it is not
//!
//! A transaction inclusion proof shows that a record is **in a block**. It does
//! not show that the record **did anything**. A malformed NFD record, or one
//! sent by somebody who did not own the collectible, is still in the block and
//! still provably included; only the overlay rules decide whether ownership
//! actually moved.
//!
//! So a chain that wants to know who owns a collectible has two options: run its
//! own overlay indexer, or be handed a commitment to the interpreted result.
//! This is the second. Each epoch produces one 32-byte root, and any individual
//! collectible can then be proven against it with a proof of about
//! `log2(n) * 32` bytes.
//!
//! **The root is a commitment, not an oracle.** It says "an indexer that
//! followed these rules got this answer". Its trustworthiness is entirely the
//! trustworthiness of whoever signs and publishes it, which today is one key and
//! is therefore no better than a coordinator's signature. The format is what is
//! being fixed now; the signer is a separate question and a later one.
//!
//! ## Deliberately not mirrored state
//!
//! One root per epoch, and proofs on demand. The alternative, copying the
//! registry onto another chain, costs storage forever for every collectible
//! including the overwhelming majority nobody ever bridges, and it goes stale
//! between updates. A stale copy of *ownership* is the specific failure worth
//! avoiding: it is what lets somebody trade against an owner who has already
//! moved on.
//!
//! ## Two details a Solidity verifier must match byte for byte
//!
//! **Domain separation.** Leaves are hashed with a `0x00` prefix and internal
//! nodes with `0x01`. Without it, an attacker can present an internal node as if
//! it were a leaf, because both are just 32 bytes, and prove membership of
//! something that was never in the tree.
//!
//! **No duplicated odd node.** The usual trick for an odd row is to hash the
//! last node with itself. That is the flaw behind Bitcoin's CVE-2012-2459: two
//! different trees produce the same root, so a root no longer identifies one set.
//! Here an odd node is **promoted unchanged** to the next row instead, which has
//! no such ambiguity.
//!
//! Leaves are also **sorted and de-duplicated** before the tree is built, so the
//! root depends on the set and not on the order an indexer happened to walk it.

use sha2::{Digest, Sha256};

use dmt_indexer::ledger::state::AddrKey;

use crate::driver::Overlay;
use crate::query;

/// How often roots are cut, in blocks.
///
/// Divi targets a block a minute, so this is hourly. Chosen with the DIVA lane:
/// a 32-byte root is negligible storage and the real cost is one publish
/// transaction, so hourly settlement beats daily for a handful of transactions a
/// day. It layers under their bridge as the slow-and-authoritative half, with
/// transaction-inclusion proofs giving an immediate provisional answer, so the
/// epoch length does not set how responsive the bridge feels.
pub const HOURLY_BLOCKS: u64 = 60;

/// When roots are cut.
///
/// Configurable, at the DIVA lane's request, so it can be tuned once their
/// validator set and real load exist. The obvious worry about making it
/// configurable, that two publishers pick different schedules and produce roots
/// nobody can line up, is answered by [`RootHeader`]: the **published height**
/// is what a verifier binds to, never an assumed schedule. The schedule is only
/// how a publisher decides which heights to cut at.
///
/// The boundary is a block-height modulus, never wall clock, so both chains
/// agree without any clock to disagree about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSchedule {
    pub blocks: u64,
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self::hourly()
    }
}

impl EpochSchedule {
    pub fn hourly() -> Self {
        Self { blocks: HOURLY_BLOCKS }
    }

    /// Blocks per epoch, never zero: a zero-length epoch has no boundaries.
    pub fn new(blocks: u64) -> Self {
        Self { blocks: blocks.max(1) }
    }

    /// Which epoch a height falls in.
    pub fn epoch_of(&self, height: u64) -> u64 {
        height / self.blocks
    }

    /// The height an epoch commits to: its final block.
    pub fn end_height(&self, epoch: u64) -> u64 {
        (epoch + 1) * self.blocks - 1
    }

    /// Whether this height closes an epoch, and so is a height to cut at.
    pub fn is_boundary(&self, height: u64) -> bool {
        (height + 1) % self.blocks == 0
    }
}

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;



/// One collectible's ownership, as committed to.
///
/// Deliberately minimal. Everything else about a collectible (its storage
/// pointer, its preview, its traits) is either immutable and fetchable from the
/// chain, or is the creator's claim rather than a fact. Committing to more would
/// mean re-committing whenever any of it changed, for no gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub id: [u8; 32],
    pub owner: AddrKey,
}

impl Entry {
    /// The canonical 53 bytes an entry contributes: id, then the 21-byte packed
    /// address. Fixed width throughout, so no length prefix is needed and no two
    /// different entries can encode alike.
    pub fn encode(&self) -> [u8; 53] {
        let mut out = [0u8; 53];
        out[..32].copy_from_slice(&self.id);
        out[32] = self.owner.0;
        out[33..].copy_from_slice(&self.owner.1);
        out
    }

    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([LEAF_TAG]);
        h.update(self.encode());
        h.finalize().into()
    }
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// What gets signed and published: the root, plus what it is a root OF.
///
/// The root alone is not enough. A verifier handed a bare 32 bytes cannot tell
/// which epoch it belongs to, and an old root presented as the current one would
/// verify perfectly against proofs from its own epoch. So the height and the
/// leaf count travel with it and are covered by the same signature.
///
/// The leaf count is there because it pins the tree's shape: RFC 6962's
/// structure is determined by the number of leaves, so committing to the count
/// removes any question of a differently-sized tree being presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootHeader {
    pub epoch: u64,
    /// The block this commits to. **This, not an assumed schedule, is what a
    /// verifier binds a proof to.**
    pub height: u64,
    pub leaf_count: u64,
    pub root: [u8; 32],
}

/// Tag for the bytes a publisher signs, so a signature over a root header can
/// never be mistaken for a signature over anything else in the system.
const HEADER_TAG: &[u8] = b"DVXP-NFD-REGISTRY-ROOT-v1";

impl RootHeader {
    /// The exact bytes to sign, and the exact bytes a verifier reconstructs.
    ///
    /// Fixed width and big-endian throughout: no length prefixes to get wrong
    /// and no platform-dependent byte order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_TAG.len() + 8 * 3 + 32);
        out.extend_from_slice(HEADER_TAG);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        out.extend_from_slice(&self.root);
        out
    }

    /// A single 32-byte digest of the header, for a signer that prefers one.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.signing_bytes());
        h.finalize().into()
    }

    pub fn root_hex(&self) -> String {
        self.root.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// One epoch's commitment, and the entries it was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRoot {
    pub header: RootHeader,
    pub entries: Vec<Entry>,
}

impl EpochRoot {
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn root(&self) -> [u8; 32] {
        self.header.root
    }

    pub fn root_hex(&self) -> String {
        self.header.root_hex()
    }
}

/// Build the commitment for the registry as it stands.
///
/// The caller is responsible for calling this at an epoch boundary; committing
/// to a height nobody agrees on produces a root nobody can check.
pub fn build(overlay: &Overlay, epoch: u64, height: u64) -> EpochRoot {
    let mut entries: Vec<Entry> = query::recent_nfds(overlay, usize::MAX)
        .into_iter()
        .map(|n| Entry { id: n.id, owner: n.owner })
        .collect();

    // Sorted and de-duplicated, so the root is a function of the SET. Two
    // indexers that walked their state in different orders must still agree.
    entries.sort_unstable();
    entries.dedup();

    let root = root_of(&entries);
    EpochRoot {
        header: RootHeader { epoch, height, leaf_count: entries.len() as u64, root },
        entries,
    }
}

/// The root over a prepared entry list.
///
/// An empty registry commits to all-zero, which is distinguishable from any real
/// root and means "nothing existed", not "nothing was checked".
pub fn root_of(entries: &[Entry]) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    let mut row: Vec<[u8; 32]> = entries.iter().map(Entry::leaf_hash).collect();
    while row.len() > 1 {
        row = fold(&row);
    }
    row[0]
}

/// One row of the tree.
///
/// An odd node is PROMOTED, never duplicated. Duplicating it is the
/// CVE-2012-2459 flaw: it lets two different entry lists produce one root, and a
/// root that does not identify a single set is not a commitment.
fn fold(row: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(row.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < row.len() {
        next.push(node_hash(&row[i], &row[i + 1]));
        i += 2;
    }
    if i < row.len() {
        next.push(row[i]);
    }
    next
}

/// A path from one entry to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub entry: Entry,
    /// Sibling hashes from the leaf upward, each with which side it sits on.
    /// A promoted odd node contributes no step, which is what makes the proof
    /// shorter for some entries than others.
    pub path: Vec<(Side, [u8; 32])>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

impl Proof {
    /// Bytes for the wire: one side byte and one hash per step.
    ///
    /// The entry is not included: a verifier already knows which collectible and
    /// owner it is being asked about, and a proof that carried its own claim
    /// would invite checking the proof against the claim rather than against the
    /// question asked.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.path.len() * 33);
        for (side, hash) in &self.path {
            out.push(match side {
                Side::Left => 0,
                Side::Right => 1,
            });
            out.extend_from_slice(hash);
        }
        out
    }
}

/// Prove one collectible's ownership against an epoch's root.
///
/// `None` when the collectible is not in that epoch's registry, which is a
/// meaningful answer rather than a failure: it did not exist, or was not owned
/// by that address, as of that height.
pub fn prove(epoch: &EpochRoot, id: &[u8; 32]) -> Option<Proof> {
    let index = epoch.entries.iter().position(|e| &e.id == id)?;
    let entry = epoch.entries[index];

    let mut row: Vec<[u8; 32]> = epoch.entries.iter().map(Entry::leaf_hash).collect();
    let mut position = index;
    let mut path = Vec::new();

    while row.len() > 1 {
        if position + 1 < row.len() || position % 2 == 1 {
            // Paired: the sibling is on the other side of the pair.
            if position % 2 == 0 {
                path.push((Side::Right, row[position + 1]));
            } else {
                path.push((Side::Left, row[position - 1]));
            }
            position /= 2;
        } else {
            // Promoted: no sibling, and therefore no step in the proof.
            position /= 2;
        }
        row = fold(&row);
    }

    Some(Proof { entry, path })
}

/// Check a proof against a root.
///
/// This is the function a Solidity verifier mirrors. Everything it needs is an
/// argument; it reads no state and trusts nothing it was not given.
pub fn verify(root: &[u8; 32], proof: &Proof) -> bool {
    let mut running = proof.entry.leaf_hash();
    for (side, sibling) in &proof.path {
        running = match side {
            Side::Left => node_hash(sibling, &running),
            Side::Right => node_hash(&running, sibling),
        };
    }
    &running == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u8, owner: u8) -> Entry {
        Entry { id: [id; 32], owner: (0, [owner; 20]) }
    }

    /// The commitment for a prepared list, as `build` would produce it.
    fn epoch_for_test(entries: Vec<Entry>) -> EpochRoot {
        let root = root_of(&entries);
        EpochRoot {
            header: RootHeader { epoch: 0, height: 0, leaf_count: entries.len() as u64, root },
            entries,
        }
    }

    fn entries(n: u8) -> Vec<Entry> {
        let mut v: Vec<Entry> = (1..=n).map(|i| entry(i, i)).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn every_entry_proves_against_the_root_at_every_tree_shape() {
        // Odd and even counts, and the sizes where a promotion happens on more
        // than one row, which is where a naive implementation breaks.
        for n in 1..=17u8 {
            let list = entries(n);
            let root = root_of(&list);
            let epoch = epoch_for_test(list.clone());

            for e in &list {
                let p = prove(&epoch, &e.id).expect("every entry is provable");
                assert!(verify(&root, &p), "entry {:?} failed to verify with {n} entries", e.id[0]);
            }
        }
    }

    #[test]
    fn a_collectible_that_is_not_in_the_registry_cannot_be_proven() {
        let list = entries(8);
        let epoch = epoch_for_test(list);
        assert!(prove(&epoch, &[99; 32]).is_none());
    }

    /// The point of the whole thing: a proof must not survive a change of owner.
    #[test]
    fn a_proof_does_not_verify_once_the_owner_differs() {
        let list = entries(6);
        let root = root_of(&list);
        let epoch = epoch_for_test(list);

        let mut p = prove(&epoch, &[3; 32]).unwrap();
        assert!(verify(&root, &p));

        p.entry.owner = (0, [0xff; 20]);
        assert!(!verify(&root, &p), "someone else's ownership must not verify");
    }

    #[test]
    fn tampering_with_any_step_of_the_path_fails() {
        let list = entries(9);
        let root = root_of(&list);
        let epoch = epoch_for_test(list);
        let good = prove(&epoch, &[5; 32]).unwrap();
        assert!(verify(&root, &good));

        for i in 0..good.path.len() {
            let mut bad = good.clone();
            bad.path[i].1[0] ^= 0xff;
            assert!(!verify(&root, &bad), "a corrupted sibling at step {i} still verified");
            let mut flipped = good.clone();
            flipped.path[i].0 = match flipped.path[i].0 {
                Side::Left => Side::Right,
                Side::Right => Side::Left,
            };
            // Flipping a side changes the concatenation order, so it must fail
            // unless the two happen to be equal, which sorted distinct leaves
            // make impossible.
            assert!(!verify(&root, &flipped), "a flipped side at step {i} still verified");
        }
    }

    /// Domain separation. Without the leaf and node tags an internal node could
    /// be presented as a leaf, proving membership of something never in the set.
    #[test]
    fn an_internal_node_cannot_be_passed_off_as_a_leaf() {
        let list = entries(4);
        let leaves: Vec<[u8; 32]> = list.iter().map(Entry::leaf_hash).collect();
        let internal = node_hash(&leaves[0], &leaves[1]);

        // No entry can hash to an internal node, because the tags differ.
        for e in &list {
            assert_ne!(e.leaf_hash(), internal);
        }
        // And the tags are what does it: same bytes, different prefix.
        let mut without_tag = Sha256::new();
        without_tag.update(list[0].encode());
        let untagged: [u8; 32] = without_tag.finalize().into();
        assert_ne!(list[0].leaf_hash(), untagged);
    }

    /// CVE-2012-2459: duplicating an odd node lets two different sets share a
    /// root. Promotion has no such ambiguity, and this proves it for the shape
    /// that classically breaks.
    #[test]
    fn two_different_registries_never_share_a_root() {
        let three = entries(3);
        // The classic attack: repeat the last entry to make an even row. With
        // duplication these hash alike; with promotion they must not.
        let mut duplicated = three.clone();
        duplicated.push(three[2]);
        // De-duplication is what a real build does, so do it here too and then
        // check the raw tree function on the un-deduplicated list as well.
        assert_ne!(
            root_of(&three),
            root_of(&duplicated),
            "a repeated trailing entry must change the root"
        );

        // And any genuine difference changes it.
        let mut different_owner = three.clone();
        different_owner[1].owner = (0, [0xaa; 20]);
        assert_ne!(root_of(&three), root_of(&different_owner));
    }

    #[test]
    fn the_root_depends_on_the_set_not_the_order_it_was_collected_in() {
        let mut a = entries(7);
        let mut b = a.clone();
        b.reverse();
        // `build` sorts; do the same here to show sorting is what makes it so.
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(root_of(&a), root_of(&b));
    }

    #[test]
    fn an_empty_registry_commits_to_a_distinguishable_nothing() {
        assert_eq!(root_of(&[]), [0u8; 32]);
        assert_ne!(root_of(&entries(1)), [0u8; 32]);
    }

    /// RFC 6962 defines the tree top-down: split at the largest power of two
    /// below n, recurse. This crate builds it bottom-up by pairing and promoting.
    /// Those are different algorithms and the claim that they agree is exactly
    /// the kind of thing that should be checked rather than asserted, because
    /// the DIVA lane intends to reuse an audited RFC 6962 Solidity verifier and
    /// a mismatch at one awkward size would only surface in production.
    fn rfc6962_reference(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => [0u8; 32],
            1 => leaves[0],
            n => {
                // Largest power of two strictly less than n.
                let mut k = 1usize;
                while k * 2 < n {
                    k *= 2;
                }
                node_hash(&rfc6962_reference(&leaves[..k]), &rfc6962_reference(&leaves[k..]))
            }
        }
    }

    #[test]
    fn the_tree_is_rfc_6962() {
        for n in 1..=64usize {
            let list: Vec<Entry> = (0..n).map(|i| entry((i % 251) as u8 + 1, i as u8)).collect();
            let leaves: Vec<[u8; 32]> = list.iter().map(Entry::leaf_hash).collect();
            assert_eq!(
                root_of(&list),
                rfc6962_reference(&leaves),
                "bottom-up build disagrees with RFC 6962 at {n} leaves"
            );
        }
    }

    #[test]
    fn epochs_line_up_with_their_heights() {
        let s = EpochSchedule::hourly();
        assert_eq!(s.blocks, 60, "an hour of Divi blocks");
        assert_eq!(s.epoch_of(0), 0);
        assert_eq!(s.epoch_of(59), 0);
        assert_eq!(s.epoch_of(60), 1);
        assert_eq!(s.end_height(0), 59);
        assert_eq!(s.end_height(1), 119);
        // The boundary is the LAST block of an epoch, not the first of the next.
        assert_eq!(s.epoch_of(s.end_height(5)), 5);
        assert!(s.is_boundary(59));
        assert!(!s.is_boundary(60));
        assert!(s.is_boundary(119));
    }

    /// A zero-length epoch has no boundaries at all, so it is refused rather
    /// than allowed to divide by zero later.
    #[test]
    fn a_schedule_cannot_be_zero_length() {
        assert_eq!(EpochSchedule::new(0).blocks, 1);
        assert_eq!(EpochSchedule::new(240).blocks, 240);
    }

    /// The root alone is not enough to bind a proof to a moment. An old root
    /// presented as the current one verifies perfectly against its own proofs,
    /// so what gets signed has to say which epoch and height it is for.
    #[test]
    fn the_signed_header_covers_the_epoch_not_just_the_root() {
        let list = entries(5);
        let root = root_of(&list);
        let a = RootHeader { epoch: 7, height: 479, leaf_count: 5, root };

        let mut later = a;
        later.epoch = 8;
        later.height = 539;
        assert_ne!(a.commitment(), later.commitment(), "a different epoch must sign differently");

        let mut resized = a;
        resized.leaf_count = 4;
        assert_ne!(a.commitment(), resized.commitment(), "the leaf count is covered too");

        let mut other_root = a;
        other_root.root[0] ^= 0xff;
        assert_ne!(a.commitment(), other_root.commitment());

        // Fixed width and big-endian, so a verifier on another chain rebuilds
        // exactly these bytes.
        let bytes = a.signing_bytes();
        assert_eq!(bytes.len(), HEADER_TAG.len() + 8 + 8 + 8 + 32);
        assert!(bytes.starts_with(HEADER_TAG), "the tag stops this signature meaning anything else");
        assert_eq!(&bytes[HEADER_TAG.len()..HEADER_TAG.len() + 8], &7u64.to_be_bytes());
    }

    #[test]
    fn a_proof_encodes_to_a_step_per_sibling() {
        let list = entries(8);
        let epoch = epoch_for_test(list);
        let p = prove(&epoch, &[1; 32]).unwrap();
        assert_eq!(p.path.len(), 3, "eight leaves is three rows");
        assert_eq!(p.encode().len(), 3 * 33);
    }
}

#[cfg(test)]
mod vectors {
    //! Known-answer vectors.
    //!
    //! An independent implementation, in Solidity or anything else, agrees with
    //! this one or it does not. Prose describing a format is not enough to catch
    //! a byte-order slip or a missing tag; a fixed expected value is. These are
    //! reproduced in `docs/NFD-REGISTRY-ROOT.md`.
    //!
    //! If one of these ever changes, the wire format changed, and every verifier
    //! already deployed is now wrong. That is the point of pinning them.

    use super::*;

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Entry 1: id = 0x01 repeated, owner kind 0 with hash160 0x02 repeated.
    fn v1() -> Entry {
        Entry { id: [0x01; 32], owner: (0, [0x02; 20]) }
    }
    fn v2() -> Entry {
        Entry { id: [0x03; 32], owner: (0, [0x04; 20]) }
    }
    fn v3() -> Entry {
        Entry { id: [0x05; 32], owner: (1, [0x06; 20]) }
    }

    #[test]
    fn leaf_hashes_are_pinned() {
        assert_eq!(hex(&v1().leaf_hash()), "144329472f5aa0e2145989b5418b8481b5457621d17328b1266e11ed0717b2a2");
        assert_eq!(hex(&v2().leaf_hash()), "03ba3cd42eaae6ca2259e61ef7e78b249030628637411fa3e127d8892c19e648");
        // A P2SH owner: the kind byte is part of the leaf, so this differs from
        // the same hash160 under kind 0.
        assert_eq!(hex(&v3().leaf_hash()), "7c93babe0009547810aa990c9b345c714619ccf8fe2fb35cef4284174fb1ef1b");
    }

    #[test]
    fn roots_are_pinned_including_the_odd_promotion_case() {
        // One entry: the root IS the leaf, because there is nothing to pair it
        // with and promotion carries it straight up.
        assert_eq!(hex(&root_of(&[v1()])), "144329472f5aa0e2145989b5418b8481b5457621d17328b1266e11ed0717b2a2");
        assert_eq!(hex(&root_of(&[v1(), v2()])), "53b7c6f2f96ffa9294e3db507e3fed686cdfae514c282b56d6e19812f4093df8");
        // Three entries exercises promotion, which is where implementations
        // most often disagree.
        assert_eq!(hex(&root_of(&[v1(), v2(), v3()])), "b5f681547da3a628a8bae98c0dfbfb53ea6ec7a9cf1f35c5b823910b466248e9");
    }

    /// The encoding itself, so a mismatch is caught at the first byte rather
    /// than as an inexplicably different root.
    #[test]
    fn the_entry_encoding_is_pinned() {
        let e = v3();
        let enc = e.encode();
        assert_eq!(enc.len(), 53);
        assert_eq!(&enc[..32], &[0x05u8; 32], "id first, unchanged");
        assert_eq!(enc[32], 1, "then the address kind byte");
        assert_eq!(&enc[33..], &[0x06u8; 20], "then the hash160");
    }
}
