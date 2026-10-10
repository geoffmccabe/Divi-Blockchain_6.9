//! NFD / Divi Collectibles indexer handler (record type `0x02`).
//!
//! A `dvxp-core` [`RecordHandler`] that replays the NFD records into an
//! **address-based** ownership ledger (spec §2b — ownership is an address, never
//! a coin, so staking can't touch it). The shared crate does the envelope
//! parsing, skip/halt decisions, dispatch and fingerprint; this file only knows
//! the NFD body layout and the ownership rules.
//!
//! Addresses are the shared 21-byte packed form (`kind` + `hash160`) used across
//! the overlay protocols (dvxp-core `codec::Address`).
//!
//! Body layouts (spec §2, matching the wallet's `nfd_record.rs`):
//!   MINT 0x01:  arweave_ptr(32) | content_hash(32) | flags(1) | [thumb_ptr(32)]
//!               | [collection_id(32) + traits_ptr(32)]  (when flag bit2 set)
//!   TRANSFER 0x02: mint_txid(32) | new_owner(21) | wrapkey_ptr(32)
//!   KEY-ANNOUNCE 0x03: enc_pubkey(32)
//!   COLLECTION-CREATE 0x04: max_supply(4, big-endian u32) | meta_ptr(32)
//!   FORGE 0x05: input_a(32) | input_b(32) | collection_id(32)

use dvxp_core::codec::Address;
use dvxp_core::registry::{RecordContext, RecordHandler};
use dvxp_core::varint::Cursor;
use dvxp_core::{Ignored, Record, TYPE_NFD};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const SUB_MINT: u8 = 0x01;
const SUB_TRANSFER: u8 = 0x02;
const SUB_KEYANNOUNCE: u8 = 0x03;
const SUB_COLLECTION: u8 = 0x04;
/// REVEAL 0x06: mint_txid(32). The owner commits to revealing a sealed Perc; the
/// result is resolved from the hash of the block REVEAL_DELAY later, so it can't
/// be ground. See resolve_due + resolve_reveal.
const SUB_REVEAL: u8 = 0x06;
/// Blocks between a reveal's commit and the block whose hash seeds its roll.
const REVEAL_DELAY: u64 = 6;
/// FORGE 0x05: input_a(32) | input_b(32) | collection_id(32). Signed by the
/// forger (the funding sender), who must own both inputs. Both inputs must be
/// REVEALED to the SAME tier, in the named Perc collection. The forge BURNS both
/// inputs and creates ONE new sealed result pack, keyed by the forge txid, owned
/// by the forger. Its tier is NOT decided here: like a reveal it resolves from a
/// FUTURE block's hash (FORGE_DELAY later) as input_tier + K, where K is the
/// halving bump (+1 @ 50%, +2 @ 25%, ...), so the guaranteed minimum is
/// input_tier + 1 and the outcome cannot be ground. See apply_forge + resolve_due.
const SUB_FORGE: u8 = 0x05;
/// Blocks between a forge's commit and the block whose hash seeds its roll.
const FORGE_DELAY: u64 = 6;
/// Largest tier bump a forge can grant (the result tier may still exceed the
/// collection's tier_count; art caps but the number keeps climbing).
const FORGE_MAX_BUMP: u16 = 40;
/// COMMISSION-SET 0x09: collection_id(32) | amount_duffs(8, big-endian u64) |
/// payout(21 packed). Signed by the collection creator; the amount can only be
/// lowered (see docs/NFD-CREATOR-COMMISSION.md). Set on the collection; a
/// transfer of a member is then valid only if it pays >= amount to payout.
const SUB_COMMISSION: u8 = 0x09;
/// COLLECTION-FORGE-FEE 0x0A: collection_id(32) | amount_duffs(8, big-endian u64)
/// | payout(21 packed). Signed by the collection creator; freely settable (a
/// forge is a voluntary act by the pack owner, so unlike the resale commission it
/// is NOT down-only). `None` until the creator sets one, in which case forging is
/// free. When set, a FORGE is valid only if it pays >= amount_duffs to payout.
const SUB_FORGE_FEE: u8 = 0x0A;
/// LIST 0x0B: item_id(32) | price_duffs(8) | payout(21) | expiry_height(8). The
/// current owner lists an item for sale at `price` (what the BUYER pays), paid to
/// `payout`. Listing LOCKS the item: while listed it cannot be transferred,
/// forged, or revealed, so the seller cannot front-run or double-sell it. The
/// owner can re-list (update) or CANCEL. `expiry_height` 0 = never expires.
const SUB_LIST: u8 = 0x0B;
/// CANCEL-LISTING 0x0C: item_id(32). The lister removes their listing and unlocks
/// the item.
const SUB_CANCEL: u8 = 0x0C;
/// BUY 0x0D: item_id(32). The buyer (funding sender) purchases a listed item. The
/// transaction must pay >= creator commission to the creator payout AND >= the
/// seller's net (price - commission) to the listing payout; the indexer then
/// moves ownership to the buyer and clears the listing. Settling payment and the
/// ownership move in ONE buyer transaction, against a locked item, is what makes
/// the sale safe without custody.
const SUB_BUY: u8 = 0x0D;
/// MINT-PRICE-SET 0x0E: collection_id(32) | amount_duffs(8, big-endian u64) |
/// payout(21 packed). Signed by the collection creator. Sets the PRIMARY mint
/// price: while it is `Some`, anyone (not just the creator) may MINT a pack into
/// the collection if their transaction pays >= amount_duffs to payout; the
/// creator always mints free (so they can give packs away or sell at a discount
/// by minting from the creator address). `None` until the creator sets one, in
/// which case minting stays creator-only (the pre-mint model). Like the resale
/// commission it is DOWN-ONLY: once set, the price can only be lowered, never
/// raised, so the primary price is a promise that can improve but never worsen.
const SUB_MINTPRICE: u8 = 0x0E;
const FLAG_HAS_THUMB: u8 = 0x02;
const FLAG_IN_COLLECTION: u8 = 0x04;

/// A packed address: `kind` byte + 20-byte hash160.
pub type Addr21 = [u8; 21];

fn packed(a: &Address) -> Addr21 {
    let mut p = [0u8; 21];
    p[0] = a.kind;
    p[1..].copy_from_slice(&a.hash160);
    p
}

/// One collectible's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nfd {
    pub owner: Addr21,
    pub arweave_ptr: [u8; 32],
    pub content_hash: [u8; 32],
    pub thumb_ptr: Option<[u8; 32]>,
    pub collection_id: Option<[u8; 32]>,
    pub mint_height: u64,
    pub mint_tx_index: u32,
    /// For a Perc (a pack in a collection with a rarity config): `None` = still
    /// sealed, `Some` = revealed to this tier. Non-Perc NFDs stay `None`.
    pub revealed: Option<RevealOutcome>,
}

/// On-chain rarity config for a blind-pack (Perc) collection, so a reveal/forge
/// roll can be resolved by the protocol itself (the chain can't read Arweave).
/// Ultra-rare chances are parts-per-million (e.g. 10_000 ppm = 1%).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RarityConfig {
    pub tier_count: u16,
    pub ur_basic_ppm: u32,
    pub ur_progressive_ppm: u32,
    pub ur_count: u16,
}

/// A collection: creator-owned, capped, with public metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub creator: Addr21,
    pub max_supply: u32, // 0 = uncapped
    pub meta_ptr: [u8; 32],
    pub minted: u32,
    /// Rarity config for blind-pack collections (None = not a blind-pack set, or
    /// a plain collection). Written into the COLLECTION-CREATE record at launch.
    pub rarity: Option<RarityConfig>,
    /// Creator commission (amount_duffs, payout address). `None` until the
    /// creator sets one. A transfer of a member must pay >= amount_duffs to
    /// payout to be valid. The amount can only be lowered over time.
    pub commission: Option<(u64, Addr21)>,
    /// Creator forge fee (amount_duffs, payout address). `None` until the creator
    /// sets one (then forging is free). A FORGE of this collection's packs must
    /// pay >= amount_duffs to payout to be valid. Freely settable (not down-only).
    pub forge_fee: Option<(u64, Addr21)>,
    /// Primary mint price (amount_duffs, payout address). `None` = minting is
    /// creator-only (the pre-mint model). `Some` = anyone may MINT a pack into
    /// this collection by paying >= amount_duffs to payout (the creator still
    /// mints free, for giveaways/discounts). DOWN-ONLY: once set it can only be
    /// lowered, never raised. The cap (`max_supply`) still bounds total mints.
    pub mint_price: Option<(u64, Addr21)>,
}

/// One reversible change, kept so a reorg can be undone exactly.
///
/// DMT has had this since it was written; NFD went without it, which meant a
/// reorg silently left collectible ownership wrong. Wrong ownership that nobody
/// is told about is the one failure this whole design is supposed to prevent, so
/// the ledger now records the inverse of every mutation it makes.
///
/// Entries are recorded **only on success**. A record that is skipped changes no
/// state, so it has nothing to undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undo {
    /// A collectible was created. Remove it, and give back the collection slot
    /// it consumed if it was minted into one.
    Minted { mint_txid: [u8; 32], collection: Option<[u8; 32]> },
    /// Ownership moved. Put it back where it was.
    Transferred { mint_txid: [u8; 32], previous_owner: Addr21 },
    /// An encryption key was announced. Restore the key it replaced, or remove
    /// the entry entirely if this address had never announced one.
    KeyAnnounced { addr: Addr21, previous: Option<[u8; 32]> },
    /// A collection was created. Remove it.
    CollectionCreated { id: [u8; 32] },
    /// A collection's commission changed. Restore the amount/payout it replaced
    /// (`None` means the collection had no commission before).
    CommissionSet { id: [u8; 32], previous: Option<(u64, Addr21)> },
    /// A collection's forge fee changed. Restore the amount/payout it replaced
    /// (`None` means the collection had no forge fee before).
    ForgeFeeSet { id: [u8; 32], previous: Option<(u64, Addr21)> },
    /// A collection's primary mint price changed. Restore the amount/payout it
    /// replaced (`None` means the collection had no mint price before).
    MintPriceSet { id: [u8; 32], previous: Option<(u64, Addr21)> },
    /// A reveal was committed (pending until its seed block). Drop it.
    RevealCommitted { pack_id: [u8; 32], seed_height: u64 },
    /// A pending reveal was resolved at its seed block. Clear the tier and put
    /// it back on the pending list for that height.
    RevealResolved { pack_id: [u8; 32], seed_height: u64 },
    /// A forge was committed: a result pack was created (pending until its seed
    /// block) and two inputs were burned. Undo removes the result, restores the
    /// burned inputs exactly as they were, and drops the pending forge entry.
    Forged { result_id: [u8; 32], seed_height: u64, restored_inputs: Vec<([u8; 32], Nfd)> },
    /// A pending forge was resolved at its seed block. Clear the result's tier
    /// and put it back on the pending forge list for that height.
    ForgeResolved { result_id: [u8; 32], seed_height: u64, input_tier: u16 },
    /// A listing was created or updated. Restore the listing it replaced (`None`
    /// means the item had no listing before, so remove it).
    Listed { item_id: [u8; 32], previous: Option<Listing> },
    /// A listing was cancelled. Put it back exactly.
    ListingCancelled { item_id: [u8; 32], previous: Listing },
    /// An item was bought: ownership moved to the buyer and the listing cleared.
    /// Restore the seller as owner and re-list it exactly as it was.
    Bought { item_id: [u8; 32], previous_owner: Addr21, listing: Listing },
}

/// A forge result awaiting its seed block: the new pack's id plus the shared
/// input tier the halving bump is added to when it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForgePending {
    result_id: [u8; 32],
    input_tier: u16,
}

/// An active marketplace listing on an item. `price` is what the buyer pays (the
/// creator commission comes out of it; the seller nets price - commission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing {
    pub price: u64,
    pub payout: Addr21,
    /// Block height at/after which the listing is expired (0 = never).
    pub expiry: u64,
    /// The owner who listed it (must still own it for a buy to settle).
    pub seller: Addr21,
}

/// The NFD ownership ledger. Keyed by mint txid (the collectible's id).
#[derive(Debug, Default)]
pub struct NfdLedger {
    nfds: HashMap<[u8; 32], Nfd>,
    collections: HashMap<[u8; 32], Collection>, // collection id (create txid) -> collection
    keys: HashMap<Addr21, [u8; 32]>,            // address -> announced X25519 encryption pubkey
    /// Reveals committed but not yet resolved, bucketed by the seed block height
    /// at which they resolve. `pending_set` is the same packs, for O(1) "already
    /// pending?" checks.
    pending_reveals: HashMap<u64, Vec<[u8; 32]>>,
    pending_set: HashSet<[u8; 32]>,
    /// Forge results committed but not yet resolved, bucketed by the seed block
    /// height at which they resolve, carrying the input tier the bump adds to.
    /// `pending_forge_set` is the same result ids, for O(1) "mid-forge?" checks
    /// (so the pack can't also be revealed through the normal reveal path).
    pending_forges: HashMap<u64, Vec<ForgePending>>,
    pending_forge_set: HashSet<[u8; 32]>,
    /// Active marketplace listings, keyed by item id. An item present here is
    /// LOCKED: it cannot be transferred, forged, or revealed until it is bought,
    /// cancelled, or (TODO, if ever) expired.
    listings: HashMap<[u8; 32], Listing>,
    /// Inverses of everything applied since the last [`NfdLedger::take_block_undo`].
    undo: Vec<Undo>,
}

impl NfdLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, mint_txid: &[u8; 32]) -> Option<&Nfd> {
        self.nfds.get(mint_txid)
    }
    pub fn owner_of(&self, mint_txid: &[u8; 32]) -> Option<Addr21> {
        self.nfds.get(mint_txid).map(|n| n.owner)
    }
    pub fn enc_pubkey_of(&self, addr: &Addr21) -> Option<[u8; 32]> {
        self.keys.get(addr).copied()
    }
    pub fn owned_by(&self, addr: &Addr21) -> Vec<[u8; 32]> {
        let mut ids: Vec<_> = self.nfds.iter().filter(|(_, n)| &n.owner == addr).map(|(id, _)| *id).collect();
        ids.sort_unstable(); // deterministic
        ids
    }
    pub fn count(&self) -> usize {
        self.nfds.len()
    }
    pub fn collection_of(&self, id: &[u8; 32]) -> Option<&Collection> {
        self.collections.get(id)
    }
    /// The current creator commission (amount_duffs, payout) for a collection.
    pub fn commission_of(&self, id: &[u8; 32]) -> Option<(u64, Addr21)> {
        self.collections.get(id).and_then(|c| c.commission)
    }
    /// The current creator forge fee (amount_duffs, payout) for a collection.
    /// `None` means forging this collection's packs is free.
    pub fn forge_fee_of(&self, id: &[u8; 32]) -> Option<(u64, Addr21)> {
        self.collections.get(id).and_then(|c| c.forge_fee)
    }
    /// The current primary mint price (amount_duffs, payout) for a collection.
    /// `None` means minting is creator-only (no public primary sale).
    pub fn mint_price_of(&self, id: &[u8; 32]) -> Option<(u64, Addr21)> {
        self.collections.get(id).and_then(|c| c.mint_price)
    }
    /// The active marketplace listing on an item, if any.
    pub fn listing_of(&self, item_id: &[u8; 32]) -> Option<Listing> {
        self.listings.get(item_id).copied()
    }
    /// Whether an item is currently listed (and therefore locked).
    pub fn is_listed(&self, item_id: &[u8; 32]) -> bool {
        self.listings.contains_key(item_id)
    }
    /// Every active listing, as (item_id, Listing), sorted by item id for a
    /// deterministic order. For the marketplace browse.
    pub fn all_listings(&self) -> Vec<([u8; 32], Listing)> {
        let mut v: Vec<_> = self.listings.iter().map(|(id, l)| (*id, *l)).collect();
        v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        v
    }
    /// The on-chain rarity config for a collection, if it is a blind-pack set.
    pub fn rarity_of(&self, id: &[u8; 32]) -> Option<RarityConfig> {
        self.collections.get(id).and_then(|c| c.rarity)
    }
    /// True while a pack's reveal has been committed but not yet resolved (it is
    /// waiting for its seed block). Any client can show "opening…" and refuse a
    /// second reveal, so no one wastes a fee on a REVEAL the rules would reject.
    pub fn reveal_pending(&self, id: &[u8; 32]) -> bool {
        self.pending_set.contains(id)
    }

    /// Whether this pack is a forge result still awaiting its seed block (so it
    /// is sealed, with a guaranteed minimum tier, but its tier is not yet rolled).
    pub fn forge_pending(&self, id: &[u8; 32]) -> bool {
        self.pending_forge_set.contains(id)
    }
    pub fn collection_count(&self) -> usize {
        self.collections.len()
    }

    /// Take everything applied since the last call. The driver calls this at a
    /// block boundary and keeps the result alongside the block, which is what
    /// makes a later rollback possible.
    pub fn take_block_undo(&mut self) -> Vec<Undo> {
        std::mem::take(&mut self.undo)
    }

    /// Whether anything has been applied since the last [`Self::take_block_undo`].
    pub fn has_pending_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    /// Reverse one block, newest change first.
    ///
    /// Order matters and is not cosmetic. Within a block a collectible can be
    /// minted and then transferred; undoing the mint first would leave the
    /// transfer with nothing to put back. Reversing the log end to start makes
    /// each inverse see exactly the state its forward step saw.
    ///
    /// This is deliberately infallible. The entries were produced by mutations
    /// this ledger actually performed, so there is no user input to reject here;
    /// anything unexpected means the caller handed back an undo log from a
    /// different ledger, which is a programming error rather than a chain event.
    pub fn rollback_block(&mut self, undo: Vec<Undo>) {
        for entry in undo.into_iter().rev() {
            match entry {
                Undo::Minted { mint_txid, collection } => {
                    self.nfds.remove(&mint_txid);
                    if let Some(cid) = collection {
                        if let Some(col) = self.collections.get_mut(&cid) {
                            // Mirrors the saturating_add on the way in, so a
                            // count can never wrap under repeated rollback.
                            col.minted = col.minted.saturating_sub(1);
                        }
                    }
                }
                Undo::Transferred { mint_txid, previous_owner } => {
                    if let Some(nfd) = self.nfds.get_mut(&mint_txid) {
                        nfd.owner = previous_owner;
                    }
                }
                Undo::KeyAnnounced { addr, previous } => match previous {
                    Some(key) => {
                        self.keys.insert(addr, key);
                    }
                    None => {
                        self.keys.remove(&addr);
                    }
                },
                Undo::CollectionCreated { id } => {
                    self.collections.remove(&id);
                }
                Undo::CommissionSet { id, previous } => {
                    if let Some(col) = self.collections.get_mut(&id) {
                        col.commission = previous;
                    }
                }
                Undo::ForgeFeeSet { id, previous } => {
                    if let Some(col) = self.collections.get_mut(&id) {
                        col.forge_fee = previous;
                    }
                }
                Undo::MintPriceSet { id, previous } => {
                    if let Some(col) = self.collections.get_mut(&id) {
                        col.mint_price = previous;
                    }
                }
                Undo::Listed { item_id, previous } => match previous {
                    Some(prev) => { self.listings.insert(item_id, prev); }
                    None => { self.listings.remove(&item_id); }
                },
                Undo::ListingCancelled { item_id, previous } => {
                    self.listings.insert(item_id, previous);
                }
                Undo::Bought { item_id, previous_owner, listing } => {
                    if let Some(nfd) = self.nfds.get_mut(&item_id) {
                        nfd.owner = previous_owner;
                    }
                    self.listings.insert(item_id, listing);
                }
                Undo::RevealCommitted { pack_id, seed_height } => {
                    self.drop_pending(&pack_id, seed_height);
                }
                Undo::RevealResolved { pack_id, seed_height } => {
                    if let Some(nfd) = self.nfds.get_mut(&pack_id) {
                        nfd.revealed = None;
                    }
                    self.pending_reveals.entry(seed_height).or_default().push(pack_id);
                    self.pending_set.insert(pack_id);
                }
                Undo::Forged { result_id, seed_height, restored_inputs } => {
                    // Remove the result pack, drop its pending forge entry, and
                    // put the two burned inputs back exactly as they were.
                    self.nfds.remove(&result_id);
                    if let Some(v) = self.pending_forges.get_mut(&seed_height) {
                        if let Some(pos) = v.iter().position(|fp| fp.result_id == result_id) {
                            v.remove(pos);
                        }
                        if v.is_empty() {
                            self.pending_forges.remove(&seed_height);
                        }
                    }
                    self.pending_forge_set.remove(&result_id);
                    for (id, nfd) in restored_inputs {
                        self.nfds.insert(id, nfd);
                    }
                }
                Undo::ForgeResolved { result_id, seed_height, input_tier } => {
                    // Un-roll: clear the result's tier and put it back on the
                    // pending forge list for its seed height.
                    if let Some(nfd) = self.nfds.get_mut(&result_id) {
                        nfd.revealed = None;
                    }
                    self.pending_forges.entry(seed_height).or_default().push(ForgePending { result_id, input_tier });
                    self.pending_forge_set.insert(result_id);
                }
            }
        }
    }

    fn sender(ctx: &RecordContext) -> Result<Addr21, Ignored> {
        ctx.sender.as_ref().map(packed).ok_or(Ignored::RuleViolation("no resolvable sender"))
    }

    fn apply_mint(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let arweave_ptr = read32(&mut c)?;
        let content_hash = read32(&mut c)?;
        let flags = c.read_u8().map_err(|_| Ignored::Malformed("flags"))?;
        let thumb_ptr = if flags & FLAG_HAS_THUMB != 0 { Some(read32(&mut c)?) } else { None };
        let collection_ref = if flags & FLAG_IN_COLLECTION != 0 {
            let cid = read32(&mut c)?;
            let _traits_ptr = read32(&mut c)?; // public traits JSON id (indexer keeps only the ref)
            Some(cid)
        } else {
            None
        };
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        // One OP_META record per tx is relay policy, not consensus; refuse a
        // second mint under the same txid rather than silently overwrite.
        if self.nfds.contains_key(&ctx.txid) {
            return Err(Ignored::RuleViolation("duplicate mint id for this tx"));
        }
        let owner = Self::sender(ctx)?;

        // Collection rules. Minting is creator-only UNLESS the creator has set a
        // primary mint price, in which case anyone may mint by paying >= the price
        // to its payout (the uncircumventable payment check, as for commission and
        // the forge fee). The creator always mints free, which is how they give
        // packs away or sell at a discount. The cap bounds total mints either way.
        if let Some(cid) = collection_ref {
            let col = self.collections.get_mut(&cid).ok_or(Ignored::RuleViolation("unknown collection"))?;
            if col.creator != owner {
                match col.mint_price {
                    None => return Err(Ignored::RuleViolation("only the collection creator may mint into it")),
                    Some((price, payout)) => {
                        if price > 0 {
                            let mut h = [0u8; 20];
                            h.copy_from_slice(&payout[1..21]);
                            let paid = ctx.payments.get(&(payout[0], h)).copied().unwrap_or(0);
                            if paid < price {
                                return Err(Ignored::RuleViolation("mint price not paid"));
                            }
                        }
                    }
                }
            }
            if col.max_supply != 0 && col.minted >= col.max_supply {
                return Err(Ignored::RuleViolation("collection is minted out"));
            }
            col.minted = col.minted.saturating_add(1);
        }

        self.nfds.insert(
            ctx.txid,
            Nfd {
                owner,
                arweave_ptr,
                content_hash,
                thumb_ptr,
                collection_id: collection_ref,
                mint_height: ctx.height,
                mint_tx_index: ctx.tx_index,
                revealed: None,
            },
        );
        self.undo.push(Undo::Minted { mint_txid: ctx.txid, collection: collection_ref });

        let mut d = vec![SUB_MINT];
        d.extend_from_slice(&ctx.txid);
        d.extend_from_slice(&owner);
        Ok(d)
    }

    fn apply_transfer(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let mint_txid = read32(&mut c)?;
        let no = c.read_bytes(21).map_err(|_| Ignored::Malformed("new_owner"))?;
        let mut new_owner: Addr21 = [0u8; 21];
        new_owner.copy_from_slice(no);
        let _wrapkey_ptr = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        // A listed item is locked: it must be cancelled before it can be moved.
        if self.listings.contains_key(&mint_txid) {
            return Err(Ignored::RuleViolation("item is listed for sale; cancel the listing first"));
        }
        // Read current owner + collection without holding a mutable borrow.
        let (previous_owner, collection_id) = {
            let nfd = self.nfds.get(&mint_txid).ok_or(Ignored::RuleViolation("unknown nfd"))?;
            if nfd.owner != sender {
                return Err(Ignored::RuleViolation("sender is not the current owner"));
            }
            (nfd.owner, nfd.collection_id)
        };
        // Creator commission: if this item's collection carries one, the transfer
        // transaction must pay at least that amount to the payout address, or the
        // transfer is NOT valid and ownership does not move. This is what makes
        // the commission uncircumventable (see docs/NFD-CREATOR-COMMISSION.md).
        if let Some(cid) = collection_id {
            if let Some((amount, payout)) = self.collections.get(&cid).and_then(|c| c.commission) {
                if amount > 0 {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(&payout[1..21]);
                    let paid = ctx.payments.get(&(payout[0], h)).copied().unwrap_or(0);
                    if paid < amount {
                        return Err(Ignored::RuleViolation("creator commission not paid"));
                    }
                }
            }
        }
        // Commission satisfied (or none owed): move ownership.
        self.nfds.get_mut(&mint_txid).expect("nfd checked present above").owner = new_owner;
        self.undo.push(Undo::Transferred { mint_txid, previous_owner });

        let mut d = vec![SUB_TRANSFER];
        d.extend_from_slice(&mint_txid);
        d.extend_from_slice(&new_owner);
        Ok(d)
    }

    fn apply_key_announce(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let enc_pubkey = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let addr = Self::sender(ctx)?;
        let previous = self.keys.insert(addr, enc_pubkey);
        self.undo.push(Undo::KeyAnnounced { addr, previous });

        let mut d = vec![SUB_KEYANNOUNCE];
        d.extend_from_slice(&addr);
        d.extend_from_slice(&enc_pubkey);
        Ok(d)
    }

    fn apply_collection_create(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let ms = c.read_bytes(4).map_err(|_| Ignored::Malformed("max_supply"))?;
        let max_supply = u32::from_be_bytes([ms[0], ms[1], ms[2], ms[3]]);
        let meta_ptr = read32(&mut c)?;
        // Optional trailing rarity config for a blind-pack collection. When
        // present it is exactly 12 bytes: tier_count(2) ur_basic_ppm(4)
        // ur_progressive_ppm(4) ur_count(2), all big-endian.
        let rarity = if c.is_empty() {
            None
        } else {
            let tc = c.read_bytes(2).map_err(|_| Ignored::Malformed("tier_count"))?;
            let tier_count = u16::from_be_bytes([tc[0], tc[1]]);
            let ub = c.read_bytes(4).map_err(|_| Ignored::Malformed("ur_basic_ppm"))?;
            let ur_basic_ppm = u32::from_be_bytes([ub[0], ub[1], ub[2], ub[3]]);
            let up = c.read_bytes(4).map_err(|_| Ignored::Malformed("ur_progressive_ppm"))?;
            let ur_progressive_ppm = u32::from_be_bytes([up[0], up[1], up[2], up[3]]);
            let uc = c.read_bytes(2).map_err(|_| Ignored::Malformed("ur_count"))?;
            let ur_count = u16::from_be_bytes([uc[0], uc[1]]);
            if !c.is_empty() {
                return Err(Ignored::TrailingBytes);
            }
            Some(RarityConfig { tier_count, ur_basic_ppm, ur_progressive_ppm, ur_count })
        };
        if self.collections.contains_key(&ctx.txid) {
            return Err(Ignored::RuleViolation("duplicate collection id for this tx"));
        }
        let creator = Self::sender(ctx)?;
        self.collections.insert(ctx.txid, Collection { creator, max_supply, meta_ptr, minted: 0, commission: None, forge_fee: None, mint_price: None, rarity });
        self.undo.push(Undo::CollectionCreated { id: ctx.txid });

        let mut d = vec![SUB_COLLECTION];
        d.extend_from_slice(&ctx.txid);
        d.extend_from_slice(&creator);
        Ok(d)
    }

    fn apply_commission_set(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let cid = read32(&mut c)?;
        let amt = c.read_bytes(8).map_err(|_| Ignored::Malformed("amount"))?;
        let mut amt8 = [0u8; 8];
        amt8.copy_from_slice(amt);
        let amount = u64::from_be_bytes(amt8);
        let po = c.read_bytes(21).map_err(|_| Ignored::Malformed("payout"))?;
        let mut payout: Addr21 = [0u8; 21];
        payout.copy_from_slice(po);
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        let col = self.collections.get_mut(&cid).ok_or(Ignored::RuleViolation("unknown collection"))?;
        // Only the collection's creator may set its commission.
        if col.creator != sender {
            return Err(Ignored::RuleViolation("only the collection creator may set its commission"));
        }
        // DOWN-ONLY: once set, the amount can only be lowered, never raised.
        if let Some((current, _)) = col.commission {
            if amount > current {
                return Err(Ignored::RuleViolation("creator commission can only be lowered"));
            }
        }
        let previous = col.commission;
        col.commission = Some((amount, payout));
        self.undo.push(Undo::CommissionSet { id: cid, previous });

        let mut d = vec![SUB_COMMISSION];
        d.extend_from_slice(&cid);
        d.extend_from_slice(&amount.to_be_bytes());
        d.extend_from_slice(&payout);
        Ok(d)
    }

    fn apply_forge_fee(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let cid = read32(&mut c)?;
        let amt = c.read_bytes(8).map_err(|_| Ignored::Malformed("amount"))?;
        let mut amt8 = [0u8; 8];
        amt8.copy_from_slice(amt);
        let amount = u64::from_be_bytes(amt8);
        let po = c.read_bytes(21).map_err(|_| Ignored::Malformed("payout"))?;
        let mut payout: Addr21 = [0u8; 21];
        payout.copy_from_slice(po);
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        let col = self.collections.get_mut(&cid).ok_or(Ignored::RuleViolation("unknown collection"))?;
        // Only the collection's creator may set its forge fee.
        if col.creator != sender {
            return Err(Ignored::RuleViolation("only the collection creator may set its forge fee"));
        }
        // Freely settable (up or down): forging is a voluntary act by the pack
        // owner, so there is no captive-buyer to protect as with the commission.
        let previous = col.forge_fee;
        col.forge_fee = Some((amount, payout));
        self.undo.push(Undo::ForgeFeeSet { id: cid, previous });

        let mut d = vec![SUB_FORGE_FEE];
        d.extend_from_slice(&cid);
        d.extend_from_slice(&amount.to_be_bytes());
        d.extend_from_slice(&payout);
        Ok(d)
    }

    /// Set (or lower) the collection's PRIMARY mint price. Signed by the creator.
    /// The first set (from `None`) may be any amount; after that it is DOWN-ONLY,
    /// mirroring the resale commission, so the price a buyer faces can only ever
    /// improve. Enabling a price opens public minting (anyone may pay to mint);
    /// the creator still mints free regardless.
    fn apply_mint_price(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let cid = read32(&mut c)?;
        let amt = c.read_bytes(8).map_err(|_| Ignored::Malformed("amount"))?;
        let mut amt8 = [0u8; 8];
        amt8.copy_from_slice(amt);
        let amount = u64::from_be_bytes(amt8);
        let po = c.read_bytes(21).map_err(|_| Ignored::Malformed("payout"))?;
        let mut payout: Addr21 = [0u8; 21];
        payout.copy_from_slice(po);
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        let col = self.collections.get_mut(&cid).ok_or(Ignored::RuleViolation("unknown collection"))?;
        // Only the collection's creator may set its mint price.
        if col.creator != sender {
            return Err(Ignored::RuleViolation("only the collection creator may set its mint price"));
        }
        // DOWN-ONLY: once set, the price can only be lowered, never raised.
        if let Some((current, _)) = col.mint_price {
            if amount > current {
                return Err(Ignored::RuleViolation("primary mint price can only be lowered"));
            }
        }
        let previous = col.mint_price;
        col.mint_price = Some((amount, payout));
        self.undo.push(Undo::MintPriceSet { id: cid, previous });

        let mut d = vec![SUB_MINTPRICE];
        d.extend_from_slice(&cid);
        d.extend_from_slice(&amount.to_be_bytes());
        d.extend_from_slice(&payout);
        Ok(d)
    }

    /// List an item for sale (or update an existing listing). Signed by the
    /// current owner. The item is LOCKED while listed.
    fn apply_list(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let item_id = read32(&mut c)?;
        let pr = c.read_bytes(8).map_err(|_| Ignored::Malformed("price"))?;
        let mut pr8 = [0u8; 8];
        pr8.copy_from_slice(pr);
        let price = u64::from_be_bytes(pr8);
        let po = c.read_bytes(21).map_err(|_| Ignored::Malformed("payout"))?;
        let mut payout: Addr21 = [0u8; 21];
        payout.copy_from_slice(po);
        let ex = c.read_bytes(8).map_err(|_| Ignored::Malformed("expiry"))?;
        let mut ex8 = [0u8; 8];
        ex8.copy_from_slice(ex);
        let expiry = u64::from_be_bytes(ex8);
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        if price == 0 {
            return Err(Ignored::RuleViolation("price must be greater than zero"));
        }
        let sender = Self::sender(ctx)?;
        // Must be the current owner. A pack mid-reveal/mid-forge cannot be listed.
        let nfd = self.nfds.get(&item_id).ok_or(Ignored::RuleViolation("unknown nfd"))?;
        if nfd.owner != sender {
            return Err(Ignored::RuleViolation("only the owner may list it"));
        }
        if self.pending_set.contains(&item_id) || self.pending_forge_set.contains(&item_id) {
            return Err(Ignored::RuleViolation("item is resolving a reveal/forge; try again once it settles"));
        }
        let previous = self.listings.get(&item_id).copied();
        self.listings.insert(item_id, Listing { price, payout, expiry, seller: sender });
        self.undo.push(Undo::Listed { item_id, previous });

        let mut d = vec![SUB_LIST];
        d.extend_from_slice(&item_id);
        d.extend_from_slice(&price.to_be_bytes());
        d.extend_from_slice(&payout);
        d.extend_from_slice(&expiry.to_be_bytes());
        Ok(d)
    }

    /// Cancel a listing and unlock the item. Signed by the lister (current owner).
    fn apply_cancel(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let item_id = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        let listing = *self.listings.get(&item_id).ok_or(Ignored::RuleViolation("item is not listed"))?;
        // Only the current owner (the lister) may cancel.
        if self.nfds.get(&item_id).map(|n| n.owner) != Some(sender) {
            return Err(Ignored::RuleViolation("only the owner may cancel the listing"));
        }
        self.listings.remove(&item_id);
        self.undo.push(Undo::ListingCancelled { item_id, previous: listing });

        let mut d = vec![SUB_CANCEL];
        d.extend_from_slice(&item_id);
        Ok(d)
    }

    /// Buy a listed item. The buyer (funding sender) must pay, in this same
    /// transaction, >= the creator commission to the creator payout AND >= the
    /// seller's net (price - commission) to the listing payout. Ownership then
    /// moves to the buyer and the listing clears. Settling money + ownership in
    /// one buyer tx against a LOCKED item is what makes the sale non-custodial
    /// and safe: the seller cannot have moved the item away (it was locked), and
    /// the buyer cannot take ownership without paying.
    fn apply_buy(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let item_id = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let buyer = Self::sender(ctx)?;
        let listing = *self.listings.get(&item_id).ok_or(Ignored::RuleViolation("item is not listed"))?;
        // Expired listings cannot be bought (0 = never expires).
        if listing.expiry != 0 && ctx.height >= listing.expiry {
            return Err(Ignored::RuleViolation("listing has expired"));
        }
        let (previous_owner, collection_id) = {
            let nfd = self.nfds.get(&item_id).ok_or(Ignored::RuleViolation("unknown nfd"))?;
            (nfd.owner, nfd.collection_id)
        };
        // The lister must still be the owner (a lock should guarantee this, but we
        // verify rather than trust it).
        if previous_owner != listing.seller {
            return Err(Ignored::RuleViolation("listing is stale: the seller no longer owns the item"));
        }
        if buyer == previous_owner {
            return Err(Ignored::RuleViolation("the owner cannot buy their own listing"));
        }
        // Creator commission (if any) comes OUT of the price; the seller nets the
        // rest. The buyer's transaction must pay BOTH, each to the right address.
        let commission = collection_id
            .and_then(|cid| self.collections.get(&cid))
            .and_then(|col| col.commission)
            .filter(|(amount, _)| *amount > 0);
        let paid_to = |addr: &Addr21| -> u64 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&addr[1..21]);
            ctx.payments.get(&(addr[0], h)).copied().unwrap_or(0)
        };
        let commission_amount = commission.map(|(a, _)| a).unwrap_or(0);
        if let Some((amount, payout)) = commission {
            if paid_to(&payout) < amount {
                return Err(Ignored::RuleViolation("creator commission not paid"));
            }
        }
        let seller_net = listing.price.saturating_sub(commission_amount);
        if paid_to(&listing.payout) < seller_net {
            return Err(Ignored::RuleViolation("seller not paid the listed price"));
        }
        // Settle: move ownership to the buyer and clear the listing.
        self.nfds.get_mut(&item_id).expect("nfd present above").owner = buyer;
        self.listings.remove(&item_id);
        self.undo.push(Undo::Bought { item_id, previous_owner, listing });

        let mut d = vec![SUB_BUY];
        d.extend_from_slice(&item_id);
        d.extend_from_slice(&buyer);
        Ok(d)
    }

    /// Commit a reveal: the owner of a sealed Perc asks to reveal it. The result
    /// is NOT decided here — it is resolved at a future block (REVEAL_DELAY
    /// later) in [`resolve_due`], so the roll cannot be ground.
    fn apply_reveal(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let pack_id = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        let sender = Self::sender(ctx)?;
        let (owner, already_revealed, coll) = {
            let nfd = self.nfds.get(&pack_id).ok_or(Ignored::RuleViolation("unknown nfd"))?;
            (nfd.owner, nfd.revealed.is_some(), nfd.collection_id)
        };
        if owner != sender {
            return Err(Ignored::RuleViolation("only the owner may reveal it"));
        }
        if self.listings.contains_key(&pack_id) {
            return Err(Ignored::RuleViolation("pack is listed for sale; cancel the listing first"));
        }
        if already_revealed {
            return Err(Ignored::RuleViolation("already revealed"));
        }
        // Only a Perc (an item in a collection that carries a rarity config) can
        // be revealed.
        let is_perc = coll.and_then(|cid| self.collections.get(&cid)).and_then(|c| c.rarity).is_some();
        if !is_perc {
            return Err(Ignored::RuleViolation("not a revealable Perc"));
        }
        if self.pending_set.contains(&pack_id) {
            return Err(Ignored::RuleViolation("reveal already pending"));
        }
        if self.pending_forge_set.contains(&pack_id) {
            // A forge result resolves by the forge roll, never the reveal roll.
            return Err(Ignored::RuleViolation("pack is mid-forge, not revealable"));
        }
        let seed_height = ctx.height + REVEAL_DELAY;
        self.pending_reveals.entry(seed_height).or_default().push(pack_id);
        self.pending_set.insert(pack_id);
        self.undo.push(Undo::RevealCommitted { pack_id, seed_height });

        let mut d = vec![SUB_REVEAL];
        d.extend_from_slice(&pack_id);
        d.extend_from_slice(&seed_height.to_be_bytes());
        Ok(d)
    }

    /// Commit a forge: burn two revealed, same-tier packs the forger owns in a
    /// Perc collection, and create ONE sealed result pack keyed by the forge
    /// txid. The result tier is NOT decided here — like a reveal it resolves from
    /// a future block (FORGE_DELAY later) in [`resolve_due`] as input_tier + the
    /// halving bump, so the guaranteed minimum is input_tier + 1 and the roll
    /// cannot be ground. Both inputs are consumed.
    fn apply_forge(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let input_a = read32(&mut c)?;
        let input_b = read32(&mut c)?;
        let collection_id = read32(&mut c)?;
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        if input_a == input_b {
            return Err(Ignored::RuleViolation("forge needs two different packs"));
        }
        // A listed input is locked for sale: it cannot be consumed by a forge.
        if self.listings.contains_key(&input_a) || self.listings.contains_key(&input_b) {
            return Err(Ignored::RuleViolation("an input is listed for sale; cancel the listing first"));
        }
        // The result pack is keyed by the forge txid; refuse a collision.
        if self.nfds.contains_key(&ctx.txid) || self.pending_forge_set.contains(&ctx.txid) {
            return Err(Ignored::RuleViolation("duplicate forge id for this tx"));
        }
        let sender = Self::sender(ctx)?;
        // Each input must exist, be owned by the forger, be in the named
        // collection, and be revealed. Read their tiers without a mutable borrow.
        let read_input = |me: &Self, id: &[u8; 32], which: &'static str| -> Result<u16, Ignored> {
            let nfd = me.nfds.get(id).ok_or(Ignored::RuleViolation(match which {
                "a" => "unknown input a",
                _ => "unknown input b",
            }))?;
            if nfd.owner != sender {
                return Err(Ignored::RuleViolation("forger does not own an input"));
            }
            if nfd.collection_id != Some(collection_id) {
                return Err(Ignored::RuleViolation("an input is not in this collection"));
            }
            let outcome = nfd.revealed.ok_or(Ignored::RuleViolation("an input is not revealed"))?;
            Ok(outcome.base_tier)
        };
        let tier_a = read_input(self, &input_a, "a")?;
        let tier_b = read_input(self, &input_b, "b")?;
        if tier_a != tier_b {
            return Err(Ignored::RuleViolation("inputs are not the same tier"));
        }
        // The collection must be a Perc set (carries a rarity config), mirroring reveal.
        let is_perc = self.collections.get(&collection_id).and_then(|c| c.rarity).is_some();
        if !is_perc {
            return Err(Ignored::RuleViolation("not a Perc collection"));
        }
        // Creator forge fee: if this collection carries one, the forge transaction
        // must pay at least that amount to the payout address, or the forge is
        // invalid (same uncircumventable mechanism as the transfer commission).
        if let Some((amount, payout)) = self.collections.get(&collection_id).and_then(|c| c.forge_fee) {
            if amount > 0 {
                let mut h = [0u8; 20];
                h.copy_from_slice(&payout[1..21]);
                let paid = ctx.payments.get(&(payout[0], h)).copied().unwrap_or(0);
                if paid < amount {
                    return Err(Ignored::RuleViolation("forge fee not paid"));
                }
            }
        }

        // Burn the two inputs, remembering them exactly so a reorg can restore them.
        let mut restored_inputs = Vec::with_capacity(2);
        for id in [input_a, input_b] {
            if let Some(nfd) = self.nfds.remove(&id) {
                restored_inputs.push((id, nfd));
            }
        }
        // Create the sealed result pack (id = forge txid), owned by the forger.
        // It references the result tier's shared art off-chain (resolved via the
        // tier-art registry), so it carries no per-item bundle: zeroed pointers.
        self.nfds.insert(
            ctx.txid,
            Nfd {
                owner: sender,
                arweave_ptr: [0u8; 32],
                content_hash: [0u8; 32],
                thumb_ptr: None,
                collection_id: Some(collection_id),
                mint_height: ctx.height,
                mint_tx_index: ctx.tx_index,
                revealed: None,
            },
        );
        // Defer the roll to a future block (ungrindable), carrying the input tier.
        let seed_height = ctx.height + FORGE_DELAY;
        self.pending_forges
            .entry(seed_height)
            .or_default()
            .push(ForgePending { result_id: ctx.txid, input_tier: tier_a });
        self.pending_forge_set.insert(ctx.txid);
        self.undo.push(Undo::Forged { result_id: ctx.txid, seed_height, restored_inputs });

        let mut d = vec![SUB_FORGE];
        d.extend_from_slice(&ctx.txid);
        d.extend_from_slice(&input_a);
        d.extend_from_slice(&input_b);
        d.extend_from_slice(&tier_a.to_be_bytes());
        d.extend_from_slice(&seed_height.to_be_bytes());
        Ok(d)
    }

    /// Resolve every reveal AND forge whose seed block is `height`, using
    /// `block_hash` as the seed. The driver calls this once per block (after
    /// records), folding the returned delta into the block fingerprint; each
    /// resolution records an undo so a reorg of the seed block re-rolls correctly.
    pub fn resolve_due(&mut self, height: u64, block_hash: &[u8; 32]) -> Vec<u8> {
        let mut delta = Vec::new();
        let reveals_due = self.pending_reveals.remove(&height).unwrap_or_default();
        for pack_id in reveals_due {
            self.pending_set.remove(&pack_id);
            let cfg = self
                .nfds
                .get(&pack_id)
                .and_then(|n| n.collection_id)
                .and_then(|cid| self.collections.get(&cid))
                .and_then(|c| c.rarity);
            let Some(cfg) = cfg else { continue }; // collection/config gone (reorg edge): skip
            // seed = SHA256(pack_id || seed_block_hash)
            let mut h = Sha256::new();
            h.update(pack_id);
            h.update(block_hash);
            let digest = h.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&digest);
            let outcome = resolve_reveal(&seed, &cfg);
            if let Some(nfd) = self.nfds.get_mut(&pack_id) {
                nfd.revealed = Some(outcome);
            }
            self.undo.push(Undo::RevealResolved { pack_id, seed_height: height });
            delta.push(SUB_REVEAL);
            delta.extend_from_slice(&pack_id);
            delta.extend_from_slice(&outcome.base_tier.to_be_bytes());
            delta.push(outcome.ur_tier.is_some() as u8);
            if let Some(ut) = outcome.ur_tier {
                delta.extend_from_slice(&ut.to_be_bytes());
            }
        }
        // Forge results whose seed block is this one: result tier = input tier +
        // the halving bump, seeded by SHA256(result_id || block_hash).
        let forges_due = self.pending_forges.remove(&height).unwrap_or_default();
        for fp in forges_due {
            self.pending_forge_set.remove(&fp.result_id);
            let mut h = Sha256::new();
            h.update(fp.result_id);
            h.update(block_hash);
            let digest = h.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&digest);
            let result_tier = fp.input_tier.saturating_add(forge_tier_bump(&seed));
            if let Some(nfd) = self.nfds.get_mut(&fp.result_id) {
                nfd.revealed = Some(RevealOutcome { base_tier: result_tier, ur_tier: None });
            }
            self.undo.push(Undo::ForgeResolved { result_id: fp.result_id, seed_height: height, input_tier: fp.input_tier });
            delta.push(SUB_FORGE);
            delta.extend_from_slice(&fp.result_id);
            delta.extend_from_slice(&result_tier.to_be_bytes());
        }
        delta
    }

    fn drop_pending(&mut self, pack_id: &[u8; 32], seed_height: u64) {
        if let Some(v) = self.pending_reveals.get_mut(&seed_height) {
            if let Some(pos) = v.iter().position(|p| p == pack_id) {
                v.remove(pos);
            }
            if v.is_empty() {
                self.pending_reveals.remove(&seed_height);
            }
        }
        self.pending_set.remove(pack_id);
    }

    /// The revealed tier of a Perc, if it has been revealed.
    pub fn revealed_of(&self, id: &[u8; 32]) -> Option<RevealOutcome> {
        self.nfds.get(id).and_then(|n| n.revealed)
    }
}

impl RecordHandler for NfdLedger {
    fn record_type(&self) -> u8 {
        TYPE_NFD
    }

    fn apply(&mut self, rec: &Record, ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        match rec.subtype {
            SUB_MINT => self.apply_mint(rec.body, ctx),
            SUB_TRANSFER => self.apply_transfer(rec.body, ctx),
            SUB_KEYANNOUNCE => self.apply_key_announce(rec.body, ctx),
            SUB_COLLECTION => self.apply_collection_create(rec.body, ctx),
            SUB_COMMISSION => self.apply_commission_set(rec.body, ctx),
            SUB_FORGE_FEE => self.apply_forge_fee(rec.body, ctx),
            SUB_MINTPRICE => self.apply_mint_price(rec.body, ctx),
            SUB_LIST => self.apply_list(rec.body, ctx),
            SUB_CANCEL => self.apply_cancel(rec.body, ctx),
            SUB_BUY => self.apply_buy(rec.body, ctx),
            SUB_REVEAL => self.apply_reveal(rec.body, ctx),
            SUB_FORGE => self.apply_forge(rec.body, ctx),
            other => Err(Ignored::UnknownSubtype(other)),
        }
    }
}

fn read32(c: &mut Cursor) -> Result<[u8; 32], Ignored> {
    let b = c.read_bytes(32).map_err(|_| Ignored::Malformed("expected 32 bytes"))?;
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// The outcome of resolving a reveal: a base tier (always) and, when the
/// ultra-rare gate fires, a UR tier on its own ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealOutcome {
    pub base_tier: u16,       // 1..=tier_count
    pub ur_tier: Option<u16>, // Some(1..=ur_count) when ultra-rare
}

/// Resolve a reveal PROVABLY-FAIRLY from a deterministic `seed` (derived from a
/// future block, so no one can grind it) and the collection's on-chain
/// [`RarityConfig`]. Integer-only, so the wallet, every indexer and the explorer
/// reach the identical result. The base tier is a 1/2-geometric (50 / 25 / 12.5
/// …) capped at `tier_count`. The ultra-rare gate fires with probability
/// `ur_basic_ppm`; when it does, a UR tier is drawn from a `ur_progressive_ppm`
/// geometric, capped at `ur_count`. The base tier is kept either way.
pub fn resolve_reveal(seed: &[u8; 32], cfg: &RarityConfig) -> RevealOutcome {
    // Independent 32-bit draws: word(n) = first 4 bytes of SHA256(seed || n_le).
    let word = |n: u32| -> u32 {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(n.to_le_bytes());
        let d = h.finalize();
        u32::from_le_bytes([d[0], d[1], d[2], d[3]])
    };
    // "Continue" with probability ppm/1_000_000. 64-bit so 100% (= 1_000_000,
    // whose 2^32 threshold overflows a u32) is handled as always-continue.
    let cont = |w: u32, ppm: u32| -> bool {
        ppm >= 1_000_000 || (w as u64) < (((ppm as u64) << 32) / 1_000_000)
    };

    let tier_cap = cfg.tier_count.max(1);
    let mut base: u16 = 1;
    let mut i = 0u32;
    while base < tier_cap && (word(i) & 0x8000_0000) != 0 {
        base += 1;
        i += 1;
    }

    let mut ur_tier = None;
    if cfg.ur_count > 0 && cfg.ur_basic_ppm > 0 && cont(word(1_000), cfg.ur_basic_ppm) {
        let mut ut: u16 = 1;
        let mut j = 0u32;
        while ut < cfg.ur_count && cont(word(2_000 + j), cfg.ur_progressive_ppm) {
            ut += 1;
            j += 1;
        }
        ur_tier = Some(ut);
    }
    RevealOutcome { base_tier: base, ur_tier }
}

/// The forge tier bump K from a 32-byte seed: treat the seed's bits as fair coin
/// flips (MSB first), K = (leading 1-bits) + 1, capped at FORGE_MAX_BUMP. So
/// P(K=1)=1/2, P(K=2)=1/4, ..., exactly the halving spec in docs/NFD-FORGING.md.
/// This is the authoritative roll; the wallet reads the result back from here.
pub fn forge_tier_bump(seed: &[u8; 32]) -> u16 {
    let mut heads: u16 = 0;
    'outer: for &byte in seed.iter() {
        for i in (0..8).rev() {
            if (byte >> i) & 1 == 1 {
                heads += 1;
                if heads + 1 >= FORGE_MAX_BUMP {
                    break 'outer; // capped
                }
            } else {
                break 'outer; // first tail ends the run
            }
        }
    }
    (heads + 1).min(FORGE_MAX_BUMP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::registry::{Outcome, Registry};
    use dvxp_core::MAGIC;
    use std::collections::BTreeMap;

    fn addr(b: u8) -> Address {
        Address { kind: 0, hash160: [b; 20] }
    }
    fn pk(b: u8) -> Addr21 {
        packed(&addr(b))
    }
    fn ctx(txid: u8, sender: Option<Address>) -> RecordContext {
        RecordContext { height: 100, tx_index: 1, txid: [txid; 32], block_time: 0, sender, payments: BTreeMap::new() }
    }
    fn ctx_pay(txid: u8, sender: Option<Address>, payments: BTreeMap<(u8, [u8; 20]), u64>) -> RecordContext {
        RecordContext { height: 100, tx_index: 1, txid: [txid; 32], block_time: 0, sender, payments }
    }
    fn collection_body(max_supply: u32) -> Vec<u8> {
        let mut b = max_supply.to_be_bytes().to_vec();
        b.extend_from_slice(&[0xee; 32]); // meta_ptr
        b
    }
    fn mint_into_body(collection_id: [u8; 32]) -> Vec<u8> {
        let mut b = vec![0xaa; 32]; // arweave_ptr
        b.extend_from_slice(&[0xbb; 32]); // content_hash
        b.push(FLAG_IN_COLLECTION); // flags: in-collection, no thumb
        b.extend_from_slice(&collection_id);
        b.extend_from_slice(&[0xdd; 32]); // traits_ptr
        b
    }
    fn commission_body(collection_id: [u8; 32], amount: u64, payout: Addr21) -> Vec<u8> {
        let mut b = collection_id.to_vec();
        b.extend_from_slice(&amount.to_be_bytes());
        b.extend_from_slice(&payout);
        b
    }
    fn pay(addr21: Addr21, amount: u64) -> BTreeMap<(u8, [u8; 20]), u64> {
        let mut h = [0u8; 20];
        h.copy_from_slice(&addr21[1..21]);
        let mut m = BTreeMap::new();
        m.insert((addr21[0], h), amount);
        m
    }
    fn mint_body(thumb: bool) -> Vec<u8> {
        let mut b = vec![0xaa; 32];
        b.extend_from_slice(&[0xbb; 32]);
        b.push(if thumb { 0x03 } else { 0x01 });
        if thumb {
            b.extend_from_slice(&[0xcc; 32]);
        }
        b
    }
    fn rec(subtype: u8, body: &[u8]) -> Record<'_> {
        Record { record_type: TYPE_NFD, subtype, body }
    }

    #[test]
    fn mint_sets_owner_to_the_sender() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)));
        assert_eq!(l.count(), 1);
    }

    #[test]
    fn mint_with_thumbnail_parses() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(true)), &ctx(1, Some(addr(7)))).unwrap();
        assert_eq!(l.get(&[1; 32]).unwrap().thumb_ptr, Some([0xcc; 32]));
    }

    #[test]
    fn mint_without_sender_is_ignored() {
        let mut l = NfdLedger::new();
        assert!(l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, None)).is_err());
        assert_eq!(l.count(), 0);
    }

    #[test]
    fn duplicate_mint_id_does_not_overwrite() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        assert!(l.apply(&rec(SUB_MINT, &mint_body(true)), &ctx(1, Some(addr(9)))).is_err());
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)));
    }

    #[test]
    fn transfer_by_owner_moves_it_but_by_others_is_ignored() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();

        let mut tbody = vec![1u8; 32]; // mint_txid
        tbody.extend_from_slice(&pk(9)); // new_owner (21-byte packed)
        tbody.extend_from_slice(&[0u8; 32]); // wrapkey_ptr

        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(5)))).is_err());
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)));

        l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(7)))).unwrap();
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(9)));
    }

    #[test]
    fn transfer_of_unknown_nfd_is_ignored() {
        let mut l = NfdLedger::new();
        let mut tbody = vec![0xffu8; 32];
        tbody.extend_from_slice(&pk(9));
        tbody.extend_from_slice(&[0u8; 32]);
        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(7)))).is_err());
    }

    #[test]
    fn key_announce_records_pubkey() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_KEYANNOUNCE, &[0x42u8; 32]), &ctx(1, Some(addr(7)))).unwrap();
        assert_eq!(l.enc_pubkey_of(&pk(7)), Some([0x42; 32]));
    }

    #[test]
    fn malformed_and_trailing_are_rejected() {
        let mut l = NfdLedger::new();
        assert!(l.apply(&rec(SUB_MINT, &[0u8; 10]), &ctx(1, Some(addr(7)))).is_err());
        let mut long = mint_body(false);
        long.push(0x00);
        assert!(l.apply(&rec(SUB_MINT, &long), &ctx(1, Some(addr(7)))).is_err());
        assert!(l.apply(&rec(0x09, &[]), &ctx(1, Some(addr(7)))).is_err());
    }

    fn coll_mint_body(cid: &[u8; 32]) -> Vec<u8> {
        let mut b = vec![0xaa; 32];
        b.extend_from_slice(&[0xbb; 32]);
        b.push(0x05); // FLAG_ENCRYPTED | FLAG_IN_COLLECTION
        b.extend_from_slice(cid);
        b.extend_from_slice(&[0xdd; 32]); // traits_ptr
        b
    }

    #[test]
    fn collection_creator_only_and_cap_enforced() {
        let mut l = NfdLedger::new();
        // creator = addr 7 makes a collection with cap 1 at tx 100
        let mut cbody = 1u32.to_be_bytes().to_vec();
        cbody.extend_from_slice(&[0xee; 32]); // meta_ptr
        l.apply(&rec(SUB_COLLECTION, &cbody), &ctx(100, Some(addr(7)))).unwrap();
        let cid = [100u8; 32];
        assert_eq!(l.collection_count(), 1);

        // a non-creator cannot mint into it
        assert!(l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(101, Some(addr(9)))).is_err());
        // the creator can (fills the cap)
        l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(102, Some(addr(7)))).unwrap();
        assert_eq!(l.collection_of(&cid).unwrap().minted, 1);
        assert_eq!(l.get(&[102; 32]).unwrap().collection_id, Some(cid));
        // now minted out
        assert!(l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(103, Some(addr(7)))).is_err());
        // minting into an unknown collection is rejected
        assert!(l.apply(&rec(SUB_MINT, &coll_mint_body(&[0xff; 32])), &ctx(104, Some(addr(7)))).is_err());
    }

    #[test]
    fn works_through_the_shared_registry() {
        let mut reg = Registry::new();
        reg.register(Box::new(NfdLedger::new())).unwrap();
        let mut payload = MAGIC.to_vec();
        payload.extend_from_slice(&[0x01, TYPE_NFD, SUB_MINT]);
        payload.extend_from_slice(&mint_body(false));
        let out = reg.process(&payload, &ctx(1, Some(addr(7)))).unwrap();
        assert!(matches!(out, Outcome::Applied { record_type: TYPE_NFD, .. }));
    }

    // ---- reorg rollback -------------------------------------------------
    //
    // Divi hard-caps reorgs at 100 blocks, so these are not hypothetical: a
    // block containing a mint or a transfer can and will be replaced.

    fn transfer_body(mint_txid: u8, to: u8) -> Vec<u8> {
        let mut b = vec![mint_txid; 32];
        b.extend_from_slice(&pk(to));
        b.extend_from_slice(&[0u8; 32]); // wrapkey_ptr
        b
    }

    #[test]
    fn rollback_removes_a_mint_and_leaves_no_trace() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        assert!(l.has_pending_undo());

        let undo = l.take_block_undo();
        assert!(!l.has_pending_undo(), "taking the log must clear it");

        l.rollback_block(undo);
        assert_eq!(l.count(), 0);
        assert_eq!(l.owner_of(&[1; 32]), None);
    }

    #[test]
    fn rollback_puts_ownership_back_where_it_was() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        let _block_one = l.take_block_undo();

        l.apply(&rec(SUB_TRANSFER, &transfer_body(1, 9)), &ctx(2, Some(addr(7)))).unwrap();
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(9)));

        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)), "the collectible must go home");
        assert_eq!(l.count(), 1, "rolling back a transfer must not delete it");
    }

    /// The ordering property. Two transfers in one block only unwind correctly
    /// when the log is replayed backwards; forwards leaves the collectible with
    /// the wrong owner, which is precisely the silent corruption to avoid.
    #[test]
    fn two_transfers_in_one_block_unwind_newest_first() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        let _block_one = l.take_block_undo();

        l.apply(&rec(SUB_TRANSFER, &transfer_body(1, 9)), &ctx(2, Some(addr(7)))).unwrap();
        l.apply(&rec(SUB_TRANSFER, &transfer_body(1, 5)), &ctx(3, Some(addr(9)))).unwrap();
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(5)));

        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)));
    }

    /// A collection slot consumed by a mint that later gets reorged away must
    /// come back. Otherwise every reorg permanently shrinks a capped collection
    /// and the cap quietly stops meaning what the creator published.
    #[test]
    fn rollback_gives_back_the_collection_slot() {
        let mut l = NfdLedger::new();
        let mut cbody = 1u32.to_be_bytes().to_vec(); // cap of exactly one
        cbody.extend_from_slice(&[0xee; 32]);
        l.apply(&rec(SUB_COLLECTION, &cbody), &ctx(100, Some(addr(7)))).unwrap();
        let cid = [100u8; 32];
        let _block_one = l.take_block_undo();

        l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(102, Some(addr(7)))).unwrap();
        assert_eq!(l.collection_of(&cid).unwrap().minted, 1);
        // Cap is full, so a second mint is refused.
        assert!(l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(103, Some(addr(7)))).is_err());

        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.collection_of(&cid).unwrap().minted, 0, "the slot must be returned");
        assert_eq!(l.collection_count(), 1, "the collection itself survives");

        // And the freed slot is genuinely usable again.
        l.apply(&rec(SUB_MINT, &coll_mint_body(&cid)), &ctx(104, Some(addr(7)))).unwrap();
        assert_eq!(l.collection_of(&cid).unwrap().minted, 1);
    }

    #[test]
    fn rollback_removes_a_collection_it_created() {
        let mut l = NfdLedger::new();
        let mut cbody = 0u32.to_be_bytes().to_vec();
        cbody.extend_from_slice(&[0xee; 32]);
        l.apply(&rec(SUB_COLLECTION, &cbody), &ctx(100, Some(addr(7)))).unwrap();
        assert_eq!(l.collection_count(), 1);

        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.collection_count(), 0);
    }

    #[test]
    fn rollback_restores_a_replaced_key_and_clears_a_first_one() {
        let mut l = NfdLedger::new();
        // First announcement: there was nothing before it.
        l.apply(&rec(SUB_KEYANNOUNCE, &[0x11; 32]), &ctx(1, Some(addr(7)))).unwrap();
        let first = l.take_block_undo();

        // Second announcement replaces it.
        l.apply(&rec(SUB_KEYANNOUNCE, &[0x22; 32]), &ctx(2, Some(addr(7)))).unwrap();
        assert_eq!(l.enc_pubkey_of(&pk(7)), Some([0x22; 32]));

        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.enc_pubkey_of(&pk(7)), Some([0x11; 32]), "the replaced key comes back");

        l.rollback_block(first);
        assert_eq!(l.enc_pubkey_of(&pk(7)), None, "the first announcement leaves no entry");
    }

    /// Ignore, never destroy, extended to the undo log: a record that changed
    /// nothing must not leave an inverse behind, or a rollback would "undo" a
    /// mutation that never happened.
    #[test]
    fn skipped_records_record_no_undo() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        let _ = l.take_block_undo();

        // Every one of these must be refused, and none may touch the log.
        assert!(l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(9)))).is_err()); // duplicate id
        assert!(l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(2, None)).is_err()); // no sender
        assert!(l.apply(&rec(SUB_TRANSFER, &transfer_body(1, 5)), &ctx(3, Some(addr(9)))).is_err()); // not the owner
        assert!(l.apply(&rec(SUB_TRANSFER, &transfer_body(8, 5)), &ctx(4, Some(addr(7)))).is_err()); // unknown nfd
        assert!(l.apply(&rec(SUB_MINT, b"short"), &ctx(5, Some(addr(7)))).is_err()); // malformed

        assert!(!l.has_pending_undo(), "a skipped record must leave nothing to undo");
        assert_eq!(l.owner_of(&[1; 32]), Some(pk(7)));
    }

    #[test]
    fn commission_set_is_creator_only_and_down_only() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap(); // collection id = [5;32]
        let payout = pk(9);
        l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 1000, payout)), &ctx(6, Some(creator))).unwrap();
        assert_eq!(l.commission_of(&cid), Some((1000, payout)));
        // lower: ok
        l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 400, payout)), &ctx(7, Some(creator))).unwrap();
        assert_eq!(l.commission_of(&cid), Some((400, payout)));
        // raise: refused
        assert!(l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 900, payout)), &ctx(8, Some(creator))).is_err());
        assert_eq!(l.commission_of(&cid), Some((400, payout)));
        // non-creator: refused
        assert!(l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 100, payout)), &ctx(9, Some(addr(3)))).is_err());
        assert_eq!(l.commission_of(&cid), Some((400, payout)));
    }

    #[test]
    fn transfer_requires_the_commission_to_be_paid() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap();
        let payout = pk(9);
        l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 500, payout)), &ctx(6, Some(creator))).unwrap();
        // mint an item into the collection (owner = creator); mint id = [10;32]
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(10, Some(creator))).unwrap();
        assert_eq!(l.owner_of(&[10; 32]), Some(pk(7)));
        // transfer body: mint_txid([10;32]) | new_owner(pk(2)) | wrapkey(32)
        let mut tbody = [10u8; 32].to_vec();
        tbody.extend_from_slice(&pk(2));
        tbody.extend_from_slice(&[0u8; 32]);
        // no payment: refused, owner unchanged
        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(11, Some(creator))).is_err());
        assert_eq!(l.owner_of(&[10; 32]), Some(pk(7)));
        // underpaid: refused
        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx_pay(11, Some(creator), pay(payout, 499))).is_err());
        assert_eq!(l.owner_of(&[10; 32]), Some(pk(7)));
        // paid in full to payout: ownership moves
        l.apply(&rec(SUB_TRANSFER, &tbody), &ctx_pay(11, Some(creator), pay(payout, 500))).unwrap();
        assert_eq!(l.owner_of(&[10; 32]), Some(pk(2)));
    }

    #[test]
    fn commission_set_rolls_back() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap();
        let payout = pk(9);
        l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 1000, payout)), &ctx(6, Some(creator))).unwrap();
        let undo1 = l.take_block_undo(); // CollectionCreated + CommissionSet{prev:None}
        l.apply(&rec(SUB_COMMISSION, &commission_body(cid, 400, payout)), &ctx(7, Some(creator))).unwrap();
        let undo2 = l.take_block_undo();
        assert_eq!(l.commission_of(&cid), Some((400, payout)));
        l.rollback_block(undo2);
        assert_eq!(l.commission_of(&cid), Some((1000, payout)));
        l.rollback_block(undo1);
        assert_eq!(l.commission_of(&cid), None); // collection gone
    }

    #[test]
    fn collection_rarity_config_roundtrips() {
        let mut l = NfdLedger::new();
        // plain collection, no rarity config
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(1, Some(addr(7)))).unwrap();
        assert_eq!(l.rarity_of(&[1; 32]), None);
        // blind-pack collection carrying the rarity config
        let mut body = collection_body(100);
        body.extend_from_slice(&40u16.to_be_bytes()); // tier_count
        body.extend_from_slice(&10_000u32.to_be_bytes()); // ur_basic_ppm (1%)
        body.extend_from_slice(&100_000u32.to_be_bytes()); // ur_progressive_ppm (10%)
        body.extend_from_slice(&3u16.to_be_bytes()); // ur_count
        l.apply(&rec(SUB_COLLECTION, &body), &ctx(2, Some(addr(7)))).unwrap();
        assert_eq!(
            l.rarity_of(&[2; 32]),
            Some(RarityConfig { tier_count: 40, ur_basic_ppm: 10_000, ur_progressive_ppm: 100_000, ur_count: 3 })
        );
        // a trailing config of the wrong length is rejected (not silently kept)
        let mut bad = collection_body(1);
        bad.extend_from_slice(&[0xaa; 5]);
        assert!(l.apply(&rec(SUB_COLLECTION, &bad), &ctx(3, Some(addr(7)))).is_err());
    }

    fn seed_of(k: u32) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"test-seed");
        h.update(k.to_le_bytes());
        let d = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&d);
        s
    }

    #[test]
    fn reveal_roll_is_deterministic_and_fair() {
        let cfg = RarityConfig { tier_count: 40, ur_basic_ppm: 10_000, ur_progressive_ppm: 100_000, ur_count: 3 };
        let s = [9u8; 32];
        assert_eq!(resolve_reveal(&s, &cfg), resolve_reveal(&s, &cfg)); // deterministic

        let n = 40_000u32;
        let (mut t1, mut t2, mut ur) = (0u32, 0u32, 0u32);
        for k in 0..n {
            let o = resolve_reveal(&seed_of(k), &cfg);
            assert!(o.base_tier >= 1 && o.base_tier <= 40);
            if let Some(u) = o.ur_tier {
                assert!(u >= 1 && u <= 3);
            }
            if o.base_tier == 1 {
                t1 += 1;
            }
            if o.base_tier == 2 {
                t2 += 1;
            }
            if o.ur_tier.is_some() {
                ur += 1;
            }
        }
        let (p1, p2, pur) = (t1 as f64 / n as f64, t2 as f64 / n as f64, ur as f64 / n as f64);
        assert!((0.45..0.55).contains(&p1), "tier1 share {p1}");
        assert!((0.20..0.30).contains(&p2), "tier2 share {p2}");
        assert!((0.006..0.016).contains(&pur), "ur rate {pur}"); // ~1%
    }

    #[test]
    fn reveal_respects_caps() {
        // 100% gate + 100% progressive -> always UR, UR tier pinned at the cap.
        let cfg = RarityConfig { tier_count: 3, ur_basic_ppm: 1_000_000, ur_progressive_ppm: 1_000_000, ur_count: 2 };
        let o = resolve_reveal(&[7u8; 32], &cfg);
        assert!(o.base_tier >= 1 && o.base_tier <= 3);
        assert_eq!(o.ur_tier, Some(2));
        // no UR configured -> never ultra-rare
        let none = RarityConfig { tier_count: 5, ur_basic_ppm: 1_000_000, ur_progressive_ppm: 0, ur_count: 0 };
        assert_eq!(resolve_reveal(&[1u8; 32], &none).ur_tier, None);
    }

    fn perc_collection_body() -> Vec<u8> {
        let mut b = collection_body(0);
        b.extend_from_slice(&40u16.to_be_bytes());
        b.extend_from_slice(&10_000u32.to_be_bytes());
        b.extend_from_slice(&100_000u32.to_be_bytes());
        b.extend_from_slice(&3u16.to_be_bytes());
        b
    }

    #[test]
    fn reveal_commits_resolves_at_seed_block_and_rolls_back() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_COLLECTION, &perc_collection_body()), &ctx(5, Some(creator))).unwrap();
        // a sealed pack minted into the Perc collection (id = [10;32], owner = creator)
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(10, Some(creator))).unwrap();
        assert_eq!(l.revealed_of(&[10; 32]), None); // sealed
        assert!(!l.reveal_pending(&[10; 32])); // not pending until a reveal is committed

        // a standalone (non-Perc) item cannot be revealed
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(20, Some(creator))).unwrap();
        assert!(l.apply(&rec(SUB_REVEAL, &[20u8; 32].to_vec()), &ctx(21, Some(creator))).is_err());

        // commit the reveal (ctx height is 100 -> seed height 106); stays sealed
        let reveal_body = [10u8; 32].to_vec();
        l.apply(&rec(SUB_REVEAL, &reveal_body), &ctx(11, Some(creator))).unwrap();
        assert_eq!(l.revealed_of(&[10; 32]), None);
        assert!(l.reveal_pending(&[10; 32])); // committed but not resolved -> pending
        // non-owner can't reveal, and a second commit while pending is refused
        assert!(l.apply(&rec(SUB_REVEAL, &reveal_body), &ctx(12, Some(addr(3)))).is_err());
        assert!(l.apply(&rec(SUB_REVEAL, &reveal_body), &ctx(13, Some(creator))).is_err());

        let _ = l.take_block_undo(); // clear prior undo so we capture only the resolution
        // nothing resolves before the seed block
        assert!(l.resolve_due(105, &[0x42; 32]).is_empty());
        assert_eq!(l.revealed_of(&[10; 32]), None);
        // the seed block resolves it
        let delta = l.resolve_due(106, &[0x42; 32]);
        assert!(!delta.is_empty());
        let out = l.revealed_of(&[10; 32]).expect("revealed");
        assert!(out.base_tier >= 1 && out.base_tier <= 40);
        assert!(!l.reveal_pending(&[10; 32])); // resolved -> no longer pending
        let undo_resolve = l.take_block_undo();

        // reorg of the seed block: the resolution undoes, re-sealing + re-pending
        l.rollback_block(undo_resolve);
        assert_eq!(l.revealed_of(&[10; 32]), None);
        assert!(l.reveal_pending(&[10; 32])); // reorg re-pends it
        // re-resolving with a different seed-block hash still resolves (and is
        // deterministic for that hash)
        assert!(!l.resolve_due(106, &[0x99; 32]).is_empty());
        assert!(l.revealed_of(&[10; 32]).is_some());
    }

    // A flat Perc config: tier_count 1, no ultra-rares, so every reveal resolves
    // to tier 1 deterministically — gives two same-tier inputs to forge.
    fn perc_collection_body_flat() -> Vec<u8> {
        let mut b = collection_body(0);
        b.extend_from_slice(&1u16.to_be_bytes()); // tier_count = 1
        b.extend_from_slice(&0u32.to_be_bytes()); // ur_basic_ppm
        b.extend_from_slice(&0u32.to_be_bytes()); // ur_progressive_ppm
        b.extend_from_slice(&0u16.to_be_bytes()); // ur_count = 0
        b
    }

    // Build a Perc collection (id [5;32], creator) with two revealed tier-1 packs
    // (ids [10;32], [11;32]) owned by the creator, ready to forge.
    fn ledger_with_two_revealed_packs() -> NfdLedger {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_COLLECTION, &perc_collection_body_flat()), &ctx(5, Some(creator))).unwrap();
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(10, Some(creator))).unwrap();
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(11, Some(creator))).unwrap();
        l.apply(&rec(SUB_REVEAL, &[10u8; 32].to_vec()), &ctx(12, Some(creator))).unwrap();
        l.apply(&rec(SUB_REVEAL, &[11u8; 32].to_vec()), &ctx(13, Some(creator))).unwrap();
        l.resolve_due(106, &[0x42; 32]); // both resolve to tier 1
        assert_eq!(l.revealed_of(&[10; 32]).unwrap().base_tier, 1);
        assert_eq!(l.revealed_of(&[11; 32]).unwrap().base_tier, 1);
        let _ = l.take_block_undo();
        l
    }

    fn forge_body(a: [u8; 32], b: [u8; 32], cid: [u8; 32]) -> Vec<u8> {
        let mut v = a.to_vec();
        v.extend_from_slice(&b);
        v.extend_from_slice(&cid);
        v
    }

    #[test]
    fn forge_burns_inputs_creates_sealed_result_and_resolves_above_minimum() {
        let mut l = ledger_with_two_revealed_packs();
        let creator = addr(7);
        let cid = [5u8; 32];

        // Commit the forge (forge txid [30;32], height 100 -> seed height 106).
        l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx(30, Some(creator))).unwrap();

        // Both inputs burned; the result pack exists, sealed, owned by the forger.
        assert!(l.get(&[10; 32]).is_none());
        assert!(l.get(&[11; 32]).is_none());
        assert_eq!(l.owner_of(&[30; 32]), Some(pk(7)));
        assert_eq!(l.revealed_of(&[30; 32]), None); // sealed until its seed block
        assert!(l.forge_pending(&[30; 32]));
        // A forge result cannot be opened via the normal reveal path.
        assert!(l.apply(&rec(SUB_REVEAL, &[30u8; 32].to_vec()), &ctx(31, Some(creator))).is_err());

        let _ = l.take_block_undo();
        // Nothing resolves before the seed block.
        assert!(l.resolve_due(105, &[0x42; 32]).is_empty());
        assert_eq!(l.revealed_of(&[30; 32]), None);
        // The seed block resolves it to at least input_tier + 1 (guaranteed upgrade).
        let delta = l.resolve_due(106, &[0x42; 32]);
        assert!(!delta.is_empty());
        let out = l.revealed_of(&[30; 32]).expect("forge resolved");
        assert!(out.base_tier >= 2, "forge is always an upgrade: {}", out.base_tier);
        assert_eq!(out.ur_tier, None);
        assert!(!l.forge_pending(&[30; 32]));

        // Reorg of the seed block re-seals + re-pends the forge result.
        let undo_resolve = l.take_block_undo();
        l.rollback_block(undo_resolve);
        assert_eq!(l.revealed_of(&[30; 32]), None);
        assert!(l.forge_pending(&[30; 32]));
    }

    #[test]
    fn forge_commit_rolls_back_restoring_the_burned_inputs() {
        let mut l = ledger_with_two_revealed_packs();
        let creator = addr(7);
        let cid = [5u8; 32];
        l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx(30, Some(creator))).unwrap();
        assert!(l.get(&[10; 32]).is_none() && l.get(&[30; 32]).is_some());

        // Reorg the forge-commit block: inputs come back exactly, result vanishes.
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.owner_of(&[10; 32]), Some(pk(7)));
        assert_eq!(l.revealed_of(&[10; 32]).unwrap().base_tier, 1);
        assert_eq!(l.owner_of(&[11; 32]), Some(pk(7)));
        assert!(l.get(&[30; 32]).is_none());
        assert!(!l.forge_pending(&[30; 32]));
    }

    #[test]
    fn forge_rejects_bad_inputs() {
        let cid = [5u8; 32];
        let creator = addr(7);
        // not the owner
        let mut l = ledger_with_two_revealed_packs();
        assert!(l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx(30, Some(addr(3)))).is_err());
        assert!(l.get(&[10; 32]).is_some()); // nothing burned on a rejected forge

        // same pack twice
        let mut l = ledger_with_two_revealed_packs();
        assert!(l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [10; 32], cid)), &ctx(30, Some(creator))).is_err());

        // an unrevealed input (mint a fresh sealed pack, don't reveal it)
        let mut l = ledger_with_two_revealed_packs();
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(14, Some(creator))).unwrap(); // [14;32] sealed
        assert!(l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [14; 32], cid)), &ctx(30, Some(creator))).is_err());

        // trailing bytes rejected
        let mut l = ledger_with_two_revealed_packs();
        let mut body = forge_body([10; 32], [11; 32], cid);
        body.push(0);
        assert!(l.apply(&rec(SUB_FORGE, &body), &ctx(30, Some(creator))).is_err());
    }

    #[test]
    fn forge_tier_bump_is_always_at_least_one_and_halves() {
        assert_eq!(forge_tier_bump(&[0x00; 32]), 1); // first flip tail -> +1
        assert_eq!(forge_tier_bump(&[0xff; 32]), FORGE_MAX_BUMP); // all heads -> capped
        let mut seed = [0u8; 32];
        seed[0] = 0b1011_1111; // one head then tail -> +2
        assert_eq!(forge_tier_bump(&seed), 2);
        // distribution: ~50% +1, ~25% +2 over pseudo-random seeds
        let n = 40_000u32;
        let (mut k1, mut k2) = (0u32, 0u32);
        for i in 0..n {
            let mut h = Sha256::new();
            h.update(b"forge-idx-dist");
            h.update(i.to_le_bytes());
            let d = h.finalize();
            let mut s = [0u8; 32];
            s.copy_from_slice(&d);
            match forge_tier_bump(&s) {
                1 => k1 += 1,
                2 => k2 += 1,
                _ => {}
            }
        }
        let p1 = k1 as f64 / n as f64;
        let p2 = k2 as f64 / n as f64;
        assert!((p1 - 0.5).abs() < 0.02, "P(+1)={p1}");
        assert!((p2 - 0.25).abs() < 0.02, "P(+2)={p2}");
    }

    #[test]
    fn forge_fee_creator_only_and_freely_settable() {
        let mut l = ledger_with_two_revealed_packs();
        let creator = addr(7);
        let cid = [5u8; 32];
        let payout = pk(9);
        // A non-creator cannot set the forge fee.
        assert!(l.apply(&rec(SUB_FORGE_FEE, &commission_body(cid, 100, payout)), &ctx(40, Some(addr(3)))).is_err());
        assert_eq!(l.forge_fee_of(&cid), None);
        // The creator sets it (100) in one block, then RAISES it (250) in the
        // next (freely settable, not down-only).
        l.apply(&rec(SUB_FORGE_FEE, &commission_body(cid, 100, payout)), &ctx(41, Some(creator))).unwrap();
        assert_eq!(l.forge_fee_of(&cid), Some((100, payout)));
        let _ = l.take_block_undo(); // seal the 100-set block
        l.apply(&rec(SUB_FORGE_FEE, &commission_body(cid, 250, payout)), &ctx(42, Some(creator))).unwrap();
        assert_eq!(l.forge_fee_of(&cid), Some((250, payout)));
        // Rolling back only the raise restores the previous amount exactly.
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.forge_fee_of(&cid), Some((100, payout)));
    }

    #[test]
    fn forge_requires_the_set_fee_to_be_paid() {
        let cid = [5u8; 32];
        let creator = addr(7);
        let payout = pk(9);

        // With a fee set, a forge that pays nothing is rejected and burns nothing.
        let mut l = ledger_with_two_revealed_packs();
        l.apply(&rec(SUB_FORGE_FEE, &commission_body(cid, 100, payout)), &ctx(41, Some(creator))).unwrap();
        let _ = l.take_block_undo();
        assert!(l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx(30, Some(creator))).is_err());
        assert!(l.get(&[10; 32]).is_some());

        // Underpaying is rejected.
        assert!(l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx_pay(30, Some(creator), pay(payout, 99))).is_err());
        assert!(l.get(&[10; 32]).is_some());

        // Paying the fee (to the payout) lets the forge through.
        l.apply(&rec(SUB_FORGE, &forge_body([10; 32], [11; 32], cid)), &ctx_pay(30, Some(creator), pay(payout, 100))).unwrap();
        assert!(l.get(&[10; 32]).is_none());
        assert_eq!(l.owner_of(&[30; 32]), Some(pk(7)));
    }

    // --- Primary mint price (0x0E) -----------------------------------------

    #[test]
    fn mint_price_opens_public_mint_and_creator_stays_free() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let payout = pk(9);
        // Uncapped collection [5;32], creator addr(7).
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap();
        let cid = [5u8; 32];
        // No price yet: a non-creator cannot mint.
        assert!(l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(10, Some(addr(3)))).is_err());
        // Creator sets a 1000-duff primary price paid to pk(9).
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(11, Some(creator))).unwrap();
        assert_eq!(l.mint_price_of(&cid), Some((1000, payout)));
        // A public mint that pays nothing is rejected.
        assert!(l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(12, Some(addr(3)))).is_err());
        // Underpaying is rejected.
        assert!(l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx_pay(13, Some(addr(3)), pay(payout, 999))).is_err());
        // Paying the price lets a non-creator mint; the pack is theirs.
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx_pay(14, Some(addr(3)), pay(payout, 1000))).unwrap();
        assert_eq!(l.owner_of(&[14; 32]), Some(pk(3)));
        assert_eq!(l.collection_of(&cid).unwrap().minted, 1);
        // The creator still mints FREE (no payment needed).
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx(15, Some(creator))).unwrap();
        assert_eq!(l.owner_of(&[15; 32]), Some(pk(7)));
        assert_eq!(l.collection_of(&cid).unwrap().minted, 2);
    }

    #[test]
    fn mint_price_is_creator_only_and_down_only() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let payout = pk(9);
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap();
        let cid = [5u8; 32];
        // A non-creator cannot set the price.
        assert!(l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(11, Some(addr(3)))).is_err());
        assert_eq!(l.mint_price_of(&cid), None);
        // Creator sets 1000, seals the block, then a RAISE to 2000 is rejected.
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(11, Some(creator))).unwrap();
        let _ = l.take_block_undo();
        assert!(l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 2000, payout)), &ctx(12, Some(creator))).is_err());
        assert_eq!(l.mint_price_of(&cid), Some((1000, payout)));
        // A LOWER to 500 is allowed (down-only).
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 500, payout)), &ctx(13, Some(creator))).unwrap();
        assert_eq!(l.mint_price_of(&cid), Some((500, payout)));
    }

    #[test]
    fn mint_price_rolls_back() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let payout = pk(9);
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(creator))).unwrap();
        let cid = [5u8; 32];
        let _ = l.take_block_undo(); // seal the collection-create so only the price-set rolls back
        // Setting from None: a reorg of that block restores None.
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(11, Some(creator))).unwrap();
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.mint_price_of(&cid), None);
        // Set 1000, seal, lower to 500, then reorg only the lower: 1000 is back.
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(12, Some(creator))).unwrap();
        let _ = l.take_block_undo();
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 500, payout)), &ctx(13, Some(creator))).unwrap();
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.mint_price_of(&cid), Some((1000, payout)));
    }

    #[test]
    fn public_mint_still_respects_the_cap() {
        let mut l = NfdLedger::new();
        let creator = addr(7);
        let payout = pk(9);
        // Cap 1.
        l.apply(&rec(SUB_COLLECTION, &collection_body(1)), &ctx(5, Some(creator))).unwrap();
        let cid = [5u8; 32];
        l.apply(&rec(SUB_MINTPRICE, &commission_body(cid, 1000, payout)), &ctx(6, Some(creator))).unwrap();
        // A paying public mint fills the cap.
        l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx_pay(7, Some(addr(3)), pay(payout, 1000))).unwrap();
        // The next paying public mint is rejected: minted out.
        assert!(l.apply(&rec(SUB_MINT, &mint_into_body(cid)), &ctx_pay(8, Some(addr(4)), pay(payout, 1000))).is_err());
    }

    // --- Marketplace (list / cancel / buy) ---------------------------------

    fn list_body(item_id: u8, price: u64, payout: Addr21, expiry: u64) -> Vec<u8> {
        let mut b = vec![item_id; 32];
        b.extend_from_slice(&price.to_be_bytes());
        b.extend_from_slice(&payout);
        b.extend_from_slice(&expiry.to_be_bytes());
        b
    }
    // A ledger with one plain minted item [20;32] in collection [5;32], owned by
    // the seller addr(7). The collection creator is also addr(7).
    fn ledger_with_one_item() -> NfdLedger {
        let mut l = NfdLedger::new();
        let seller = addr(7);
        l.apply(&rec(SUB_COLLECTION, &collection_body(0)), &ctx(5, Some(seller))).unwrap();
        l.apply(&rec(SUB_MINT, &mint_into_body([5u8; 32])), &ctx(20, Some(seller))).unwrap();
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(7)));
        let _ = l.take_block_undo();
        l
    }

    #[test]
    fn listing_locks_the_item_and_cancel_unlocks_it() {
        let mut l = ledger_with_one_item();
        let seller = addr(7);
        // Only the owner may list.
        assert!(l.apply(&rec(SUB_LIST, &list_body(20, 1000, pk(7), 0)), &ctx(21, Some(addr(3)))).is_err());
        // The owner lists it.
        l.apply(&rec(SUB_LIST, &list_body(20, 1000, pk(7), 0)), &ctx(21, Some(seller))).unwrap();
        assert!(l.is_listed(&[20; 32]));
        assert_eq!(l.listing_of(&[20; 32]).map(|x| x.price), Some(1000));
        // While listed it is LOCKED: a transfer is refused.
        assert!(l.apply(&rec(SUB_TRANSFER, &transfer_body(20, 9)), &ctx(22, Some(seller))).is_err());
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(7)));
        let _ = l.take_block_undo();
        // Cancel unlocks it; now a transfer works.
        l.apply(&rec(SUB_CANCEL, &[20u8; 32].to_vec()), &ctx(23, Some(seller))).unwrap();
        assert!(!l.is_listed(&[20; 32]));
        l.apply(&rec(SUB_TRANSFER, &transfer_body(20, 9)), &ctx(24, Some(seller))).unwrap();
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(9)));
    }

    #[test]
    fn listing_and_cancel_roll_back() {
        let mut l = ledger_with_one_item();
        let seller = addr(7);
        l.apply(&rec(SUB_LIST, &list_body(20, 1000, pk(7), 0)), &ctx(21, Some(seller))).unwrap();
        // Reorg the list block: the item is no longer listed.
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert!(!l.is_listed(&[20; 32]));
        // List again, seal that block, then cancel and reorg the cancel: re-listed.
        l.apply(&rec(SUB_LIST, &list_body(20, 1000, pk(7), 0)), &ctx(22, Some(seller))).unwrap();
        let _ = l.take_block_undo();
        l.apply(&rec(SUB_CANCEL, &[20u8; 32].to_vec()), &ctx(23, Some(seller))).unwrap();
        assert!(!l.is_listed(&[20; 32]));
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert!(l.is_listed(&[20; 32]));
    }

    #[test]
    fn buy_pays_seller_and_commission_then_moves_ownership() {
        let mut l = ledger_with_one_item();
        let seller = addr(7);
        let buyer = addr(3);
        // Creator sets a 200-duff commission to pk(2); seller nets 1000 - 200 = 800.
        l.apply(&rec(SUB_COMMISSION, &commission_body([5u8; 32], 200, pk(2))), &ctx(25, Some(seller))).unwrap();
        l.apply(&rec(SUB_LIST, &list_body(20, 1000, pk(7), 0)), &ctx(26, Some(seller))).unwrap();
        let _ = l.take_block_undo();

        // Paying nothing is rejected.
        assert!(l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx(27, Some(buyer))).is_err());
        // Paying the seller but not the commission is rejected.
        assert!(l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx_pay(27, Some(buyer), pay(pk(7), 800))).is_err());
        // Paying the commission but underpaying the seller is rejected.
        let mut underpay = pay(pk(2), 200);
        { let mut h = [0u8; 20]; h.copy_from_slice(&pk(7)[1..21]); underpay.insert((pk(7)[0], h), 799); }
        assert!(l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx_pay(27, Some(buyer), underpay)).is_err());
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(7))); // nothing moved on a rejected buy

        // Paying both (commission to pk(2), net to pk(7)) settles the sale.
        let mut full = pay(pk(2), 200);
        { let mut h = [0u8; 20]; h.copy_from_slice(&pk(7)[1..21]); full.insert((pk(7)[0], h), 800); }
        l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx_pay(27, Some(buyer), full.clone())).unwrap();
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(3))); // now the buyer's
        assert!(!l.is_listed(&[20; 32]));

        // Reorg the buy: ownership returns to the seller and it is re-listed.
        let undo = l.take_block_undo();
        l.rollback_block(undo);
        assert_eq!(l.owner_of(&[20; 32]), Some(pk(7)));
        assert!(l.is_listed(&[20; 32]));
    }

    #[test]
    fn buy_rejects_expired_and_owner_self_buy() {
        let mut l = ledger_with_one_item();
        let seller = addr(7);
        // Expires at height 100; ctx height is 100, so it is expired at buy time.
        l.apply(&rec(SUB_LIST, &list_body(20, 500, pk(7), 100)), &ctx(26, Some(seller))).unwrap();
        let _ = l.take_block_undo();
        assert!(l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx_pay(27, Some(addr(3)), pay(pk(7), 500))).is_err());
        // The owner cannot buy their own listing.
        assert!(l.apply(&rec(SUB_BUY, &[20u8; 32].to_vec()), &ctx_pay(27, Some(seller), pay(pk(7), 500))).is_err());
    }
}
