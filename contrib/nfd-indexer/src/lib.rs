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

use dvxp_core::codec::Address;
use dvxp_core::registry::{RecordContext, RecordHandler};
use dvxp_core::varint::Cursor;
use dvxp_core::{Ignored, Record, TYPE_NFD};
use std::collections::HashMap;

const SUB_MINT: u8 = 0x01;
const SUB_TRANSFER: u8 = 0x02;
const SUB_KEYANNOUNCE: u8 = 0x03;
const SUB_COLLECTION: u8 = 0x04;
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
}

/// A collection: creator-owned, capped, with public metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub creator: Addr21,
    pub max_supply: u32, // 0 = uncapped
    pub meta_ptr: [u8; 32],
    pub minted: u32,
}

/// The NFD ownership ledger. Keyed by mint txid (the collectible's id).
#[derive(Default)]
pub struct NfdLedger {
    nfds: HashMap<[u8; 32], Nfd>,
    collections: HashMap<[u8; 32], Collection>, // collection id (create txid) -> collection
    keys: HashMap<Addr21, [u8; 32]>,            // address -> announced X25519 encryption pubkey
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
    pub fn collection_count(&self) -> usize {
        self.collections.len()
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

        // Collection rules: only the creator may mint into it, and not past the cap.
        if let Some(cid) = collection_ref {
            let col = self.collections.get_mut(&cid).ok_or(Ignored::RuleViolation("unknown collection"))?;
            if col.creator != owner {
                return Err(Ignored::RuleViolation("only the collection creator may mint into it"));
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
            },
        );
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
        let nfd = self.nfds.get_mut(&mint_txid).ok_or(Ignored::RuleViolation("unknown nfd"))?;
        if nfd.owner != sender {
            return Err(Ignored::RuleViolation("sender is not the current owner"));
        }
        nfd.owner = new_owner;
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
        self.keys.insert(addr, enc_pubkey);
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
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        if self.collections.contains_key(&ctx.txid) {
            return Err(Ignored::RuleViolation("duplicate collection id for this tx"));
        }
        let creator = Self::sender(ctx)?;
        self.collections.insert(ctx.txid, Collection { creator, max_supply, meta_ptr, minted: 0 });
        let mut d = vec![SUB_COLLECTION];
        d.extend_from_slice(&ctx.txid);
        d.extend_from_slice(&creator);
        Ok(d)
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

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::registry::{Outcome, Registry};
    use dvxp_core::MAGIC;

    fn addr(b: u8) -> Address {
        Address { kind: 0, hash160: [b; 20] }
    }
    fn pk(b: u8) -> Addr21 {
        packed(&addr(b))
    }
    fn ctx(txid: u8, sender: Option<Address>) -> RecordContext {
        RecordContext { height: 100, tx_index: 1, txid: [txid; 32], block_time: 0, sender }
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
    fn rec(subtype: u8, body: &[u8]) -> Record {
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
}
