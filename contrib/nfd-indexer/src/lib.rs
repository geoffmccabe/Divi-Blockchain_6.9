//! NFD / Divi Collectibles indexer handler (record type `0x02`).
//!
//! A `dvxp-core` [`RecordHandler`] that replays the NFD records into an
//! **address-based** ownership ledger (spec §2b — ownership is an address, never
//! a coin, so staking can't touch it). The shared crate does the envelope
//! parsing, skip/halt decisions, dispatch and fingerprint; this file only knows
//! the NFD body layout and the ownership rules.
//!
//! Body layouts (spec §2, matching the wallet's `nfd_record.rs`):
//!   MINT 0x01:  arweave_ptr(32) | content_hash(32) | flags(1) | [thumb_ptr(32)]
//!   TRANSFER 0x02: mint_txid(32) | new_owner(20) | wrapkey_ptr(32)
//!   KEY-ANNOUNCE 0x03: enc_pubkey(32)

use dvxp_core::registry::{RecordContext, RecordHandler};
use dvxp_core::varint::Cursor;
use dvxp_core::{Ignored, Record, TYPE_NFD};
use std::collections::HashMap;

const SUB_MINT: u8 = 0x01;
const SUB_TRANSFER: u8 = 0x02;
const SUB_KEYANNOUNCE: u8 = 0x03;
const FLAG_HAS_THUMB: u8 = 0x02;

/// One collectible's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nfd {
    pub owner: [u8; 20],
    pub arweave_ptr: [u8; 32],
    pub content_hash: [u8; 32],
    pub thumb_ptr: Option<[u8; 32]>,
    pub mint_height: u64,
    pub mint_tx_index: u32,
}

/// The NFD ownership ledger. Keyed by mint txid (the collectible's id).
#[derive(Default)]
pub struct NfdLedger {
    nfds: HashMap<[u8; 32], Nfd>,
    keys: HashMap<[u8; 20], [u8; 32]>, // address -> announced X25519 encryption pubkey
}

impl NfdLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, mint_txid: &[u8; 32]) -> Option<&Nfd> {
        self.nfds.get(mint_txid)
    }
    pub fn owner_of(&self, mint_txid: &[u8; 32]) -> Option<[u8; 20]> {
        self.nfds.get(mint_txid).map(|n| n.owner)
    }
    pub fn enc_pubkey_of(&self, addr: &[u8; 20]) -> Option<[u8; 32]> {
        self.keys.get(addr).copied()
    }
    pub fn owned_by(&self, addr: &[u8; 20]) -> Vec<[u8; 32]> {
        let mut ids: Vec<_> = self.nfds.iter().filter(|(_, n)| &n.owner == addr).map(|(id, _)| *id).collect();
        ids.sort_unstable(); // deterministic
        ids
    }
    pub fn count(&self) -> usize {
        self.nfds.len()
    }

    fn sender(ctx: &RecordContext) -> Result<[u8; 20], Ignored> {
        ctx.sender.map(|a| a.hash160).ok_or(Ignored::RuleViolation("no resolvable sender"))
    }

    fn apply_mint(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let arweave_ptr = read32(&mut c)?;
        let content_hash = read32(&mut c)?;
        let flags = c.read_u8().map_err(|_| Ignored::Malformed("flags"))?;
        let thumb_ptr = if flags & FLAG_HAS_THUMB != 0 { Some(read32(&mut c)?) } else { None };
        if !c.is_empty() {
            return Err(Ignored::TrailingBytes);
        }
        // The id is the mint txid; one OP_META record per tx is relay policy, not
        // consensus, so refuse a second mint under the same txid rather than let
        // it silently overwrite the first (deterministic + safe).
        if self.nfds.contains_key(&ctx.txid) {
            return Err(Ignored::RuleViolation("duplicate mint id for this tx"));
        }
        let owner = Self::sender(ctx)?;
        self.nfds.insert(
            ctx.txid,
            Nfd { owner, arweave_ptr, content_hash, thumb_ptr, mint_height: ctx.height, mint_tx_index: ctx.tx_index },
        );
        let mut d = vec![SUB_MINT];
        d.extend_from_slice(&ctx.txid);
        d.extend_from_slice(&owner);
        Ok(d)
    }

    fn apply_transfer(&mut self, body: &[u8], ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
        let mut c = Cursor::new(body);
        let mint_txid = read32(&mut c)?;
        let no = c.read_bytes(20).map_err(|_| Ignored::Malformed("new_owner"))?;
        let mut new_owner = [0u8; 20];
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
    use dvxp_core::codec::Address;
    use dvxp_core::registry::{Outcome, Registry};
    use dvxp_core::MAGIC;

    fn addr(b: u8) -> Address {
        Address { kind: 0, hash160: [b; 20] }
    }
    fn ctx(txid: u8, sender: Option<Address>) -> RecordContext {
        RecordContext { height: 100, tx_index: 1, txid: [txid; 32], block_time: 0, sender }
    }
    fn mint_body(thumb: bool) -> Vec<u8> {
        let mut b = vec![0xaa; 32]; // arweave_ptr
        b.extend_from_slice(&[0xbb; 32]); // content_hash
        b.push(if thumb { 0x03 } else { 0x01 }); // flags
        if thumb {
            b.extend_from_slice(&[0xcc; 32]); // thumb_ptr
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
        assert_eq!(l.owner_of(&[1; 32]), Some([7; 20]));
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
    fn transfer_by_owner_moves_it_but_by_others_is_ignored() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();

        let mut tbody = vec![1u8; 32]; // mint_txid
        tbody.extend_from_slice(&[9u8; 20]); // new_owner
        tbody.extend_from_slice(&[0u8; 32]); // wrapkey_ptr

        // a stranger cannot transfer it
        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(5)))).is_err());
        assert_eq!(l.owner_of(&[1; 32]), Some([7; 20]));

        // the owner can
        l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(7)))).unwrap();
        assert_eq!(l.owner_of(&[1; 32]), Some([9; 20]));
    }

    #[test]
    fn duplicate_mint_id_does_not_overwrite() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_MINT, &mint_body(false)), &ctx(1, Some(addr(7)))).unwrap();
        // a second mint record under the SAME txid is rejected, not applied
        assert!(l.apply(&rec(SUB_MINT, &mint_body(true)), &ctx(1, Some(addr(9)))).is_err());
        assert_eq!(l.owner_of(&[1; 32]), Some([7; 20]));
    }

    #[test]
    fn transfer_of_unknown_nfd_is_ignored() {
        let mut l = NfdLedger::new();
        let mut tbody = vec![0xffu8; 32];
        tbody.extend_from_slice(&[9u8; 20]);
        tbody.extend_from_slice(&[0u8; 32]);
        assert!(l.apply(&rec(SUB_TRANSFER, &tbody), &ctx(2, Some(addr(7)))).is_err());
    }

    #[test]
    fn key_announce_records_pubkey() {
        let mut l = NfdLedger::new();
        l.apply(&rec(SUB_KEYANNOUNCE, &[0x42u8; 32]), &ctx(1, Some(addr(7)))).unwrap();
        assert_eq!(l.enc_pubkey_of(&[7; 20]), Some([0x42; 32]));
    }

    #[test]
    fn malformed_and_trailing_are_rejected() {
        let mut l = NfdLedger::new();
        assert!(l.apply(&rec(SUB_MINT, &[0u8; 10]), &ctx(1, Some(addr(7)))).is_err());
        let mut long = mint_body(false);
        long.push(0x00); // trailing byte
        assert!(l.apply(&rec(SUB_MINT, &long), &ctx(1, Some(addr(7)))).is_err());
        assert!(l.apply(&rec(0x09, &[]), &ctx(1, Some(addr(7)))).is_err()); // unknown subtype
    }

    #[test]
    fn works_through_the_shared_registry() {
        let mut reg = Registry::new();
        reg.register(Box::new(NfdLedger::new())).unwrap();
        // wrap a mint body in a full DVXP payload and dispatch it
        let mut payload = MAGIC.to_vec();
        payload.extend_from_slice(&[0x01, TYPE_NFD, SUB_MINT]);
        payload.extend_from_slice(&mint_body(false));
        let out = reg.process(&payload, &ctx(1, Some(addr(7)))).unwrap();
        assert!(matches!(out, Outcome::Applied { record_type: TYPE_NFD, .. }));
    }
}
