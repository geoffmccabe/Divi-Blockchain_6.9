//! DVXP record type `0x05` — Divi Names.
//!
//! Rides in the same `OP_META` envelope as PoE (0x01), NFD (0x02), PoE batch
//! (0x03) and DMT (0x04). **No fork of any kind is required**: a node that never
//! upgrades relays, validates and stores every one of these transactions
//! correctly and stays in consensus permanently. It simply cannot resolve names.
//!
//! ## Trust model, and what must never be claimed in UI
//!
//! This is an overlay. The chain **carries and orders** the records; software
//! interprets them into a registry. The network does not validate name ownership
//! and no opcode could make it. Accurate: *"permanently recorded and ordered by
//! the Divi chain."* Never: *"the network enforces this."*
//!
//! ## Body layouts
//!
//! Every subtype except COMMIT starts with a length-prefixed name:
//! `name_len(1) | name(name_len)`.

use dvxp_core::codec::Address;
use dvxp_core::varint::{write_varint, Cursor, VarintError};
use dvxp_core::{MAGIC, SUPPORTED_VERSION};

/// The DVXP record type byte for Divi Names.
pub const TYPE_NAME: u8 = 0x05;

pub const SUB_COMMIT: u8 = 0x01;
pub const SUB_REGISTER: u8 = 0x02;
pub const SUB_TRANSFER: u8 = 0x03;
pub const SUB_SET_RECORD: u8 = 0x04;
pub const SUB_CLEAR_RECORD: u8 = 0x05;
pub const SUB_SET_PRIMARY: u8 = 0x06;
pub const SUB_RENEW: u8 = 0x07;
pub const SUB_LIST: u8 = 0x08;
pub const SUB_BUY: u8 = 0x09;
pub const SUB_DELIST: u8 = 0x0A;

// ── Record keys ───────────────────────────────────────────────────────────
// One-byte keys rather than ENS's string keys, because the whole OP_META
// payload is about 599 bytes and a string key would spend a third of a record
// on the word "description".

/// Divi address (21 bytes). The actual human-readable-address payoff.
pub const KEY_DIVI_ADDRESS: u8 = 0x01;
/// EVM address: 20 raw bytes, optionally followed by a varint chain id
/// (mirrors ENSIP-11, so existing multichain wallet code maps across).
pub const KEY_EVM_ADDRESS: u8 = 0x02;
/// Any other chain: varint SLIP-44 coin type, then the raw address bytes
/// (mirrors ENSIP-9).
pub const KEY_CHAIN_ADDRESS: u8 = 0x03;
/// An ENS name, e.g. `geoff.eth`.
pub const KEY_ENS_NAME: u8 = 0x10;
pub const KEY_TELEGRAM: u8 = 0x20;
pub const KEY_X_HANDLE: u8 = 0x21;
pub const KEY_EMAIL: u8 = 0x22;
pub const KEY_URL: u8 = 0x23;
/// 32-byte Arweave transaction id for an avatar image.
pub const KEY_AVATAR: u8 = 0x24;
/// Phone number. **Never plaintext** — see [`key_requires_privacy`].
pub const KEY_PHONE: u8 = 0x30;
/// 32-byte Arweave transaction id for a JSON profile holding everything that
/// does not belong on-chain: long text, many records, or private fields
/// encrypted to the owner's key. This is the escape valve that keeps the
/// on-chain footprint small and the record set unbounded.
pub const KEY_PROFILE_PTR: u8 = 0x40;
/// Arbitrary string key, ENSIP-5 style, for anything not foreseen here.
/// Value is `key_len(1) | key | value...`.
pub const KEY_CUSTOM: u8 = 0xFF;

/// Longest value a single record key may carry. Well under the ~599-byte
/// payload so several records fit in one transaction.
pub const MAX_VALUE_LEN: usize = 160;

/// Keys whose value must never be written to the chain in the clear.
///
/// A permanent public chain plus a phone number is a doxxing and SIM-swap gift,
/// and unlike a website you cannot take it down, ever. Store a salted
/// commitment (which proves a number somebody already knows and reveals nothing)
/// or a blob encrypted to chosen readers. This function exists so the rule is
/// enforced by code in every implementation rather than remembered by whoever
/// writes the next wallet.
pub fn key_requires_privacy(key: u8) -> bool {
    key == KEY_PHONE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// Body did not parse: bad lengths, bad varints, truncation.
    Malformed(&'static str),
    /// Parsed cleanly but left unconsumed bytes. A record must describe its own
    /// end exactly, or two implementations can disagree about what it said.
    TrailingBytes,
    UnknownSubtype(u8),
    ValueTooLong,
    /// Longer than the charset permits, so it cannot be length-prefixed safely.
    NameTooLong,
}

impl From<VarintError> for RecordError {
    fn from(_: VarintError) -> Self {
        RecordError::Malformed("truncated or non-canonical body")
    }
}

/// One key/value pair attached to a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: u8,
    pub value: Vec<u8>,
}

/// A decoded Divi Names record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameRecord {
    Commit { hash160: [u8; 20] },
    Register { salt: Vec<u8>, name: Vec<u8> },
    Transfer { name: Vec<u8>, new_owner: Address },
    SetRecord { name: Vec<u8>, entries: Vec<Entry> },
    ClearRecord { name: Vec<u8>, keys: Vec<u8> },
    SetPrimary { name: Vec<u8> },
    Renew { name: Vec<u8> },
    /// `price` is in satoshi-equivalent smallest units of DIVI.
    /// `min_lifetime_blocks` is the window during which the seller CANNOT
    /// withdraw the listing, which is what stops the Counterparty dispenser
    /// attack where a seller takes the payment and keeps the asset.
    List { name: Vec<u8>, price: u64, min_lifetime_blocks: u64 },
    Buy { name: Vec<u8> },
    Delist { name: Vec<u8> },
}

impl NameRecord {
    pub fn subtype(&self) -> u8 {
        match self {
            NameRecord::Commit { .. } => SUB_COMMIT,
            NameRecord::Register { .. } => SUB_REGISTER,
            NameRecord::Transfer { .. } => SUB_TRANSFER,
            NameRecord::SetRecord { .. } => SUB_SET_RECORD,
            NameRecord::ClearRecord { .. } => SUB_CLEAR_RECORD,
            NameRecord::SetPrimary { .. } => SUB_SET_PRIMARY,
            NameRecord::Renew { .. } => SUB_RENEW,
            NameRecord::List { .. } => SUB_LIST,
            NameRecord::Buy { .. } => SUB_BUY,
            NameRecord::Delist { .. } => SUB_DELIST,
        }
    }

    /// The name this record acts on, or `None` for COMMIT (which deliberately
    /// hides it — that is the entire point of the commit).
    pub fn name(&self) -> Option<&[u8]> {
        match self {
            NameRecord::Commit { .. } => None,
            NameRecord::Register { name, .. }
            | NameRecord::Transfer { name, .. }
            | NameRecord::SetRecord { name, .. }
            | NameRecord::ClearRecord { name, .. }
            | NameRecord::SetPrimary { name }
            | NameRecord::Renew { name }
            | NameRecord::List { name, .. }
            | NameRecord::Buy { name }
            | NameRecord::Delist { name } => Some(name),
        }
    }
}

/// ⚠ The length prefix is one byte. A caller handing over something longer than
/// the charset allows must be refused, not silently truncated into a DIFFERENT
/// valid-looking name: `name.len() as u8` on a 300-byte input wraps to 44 and
/// would register something the user never asked for.
fn write_name(out: &mut Vec<u8>, name: &[u8]) -> Result<(), RecordError> {
    if name.is_empty() {
        return Err(RecordError::Malformed("empty name"));
    }
    if name.len() > crate::charset::NAME_MAX_LEN {
        return Err(RecordError::NameTooLong);
    }
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    Ok(())
}

fn read_name(c: &mut Cursor) -> Result<Vec<u8>, RecordError> {
    let len = c.read_u8()? as usize;
    if len == 0 {
        return Err(RecordError::Malformed("empty name"));
    }
    // Refuse on the way in, not just on the way out. A name longer than the
    // charset permits can never be valid, so decoding it only spends memory on
    // somebody else's junk.
    if len > crate::charset::NAME_MAX_LEN {
        return Err(RecordError::NameTooLong);
    }
    Ok(c.read_bytes(len)?.to_vec())
}

/// Encode a record body (everything after the 7-byte DVXP header).
pub fn encode_body(rec: &NameRecord) -> Result<Vec<u8>, RecordError> {
    let mut out = Vec::new();
    match rec {
        NameRecord::Commit { hash160 } => out.extend_from_slice(hash160),
        NameRecord::Register { salt, name } => {
            if salt.len() != crate::commit::SALT_LEN {
                return Err(RecordError::Malformed("salt must be 20 bytes"));
            }
            out.extend_from_slice(salt);
            write_name(&mut out, name)?;
        }
        NameRecord::Transfer { name, new_owner } => {
            write_name(&mut out, name)?;
            new_owner.write(&mut out);
        }
        NameRecord::SetRecord { name, entries } => {
            write_name(&mut out, name)?;
            if entries.is_empty() {
                return Err(RecordError::Malformed("no entries"));
            }
            for e in entries {
                if e.value.len() > MAX_VALUE_LEN {
                    return Err(RecordError::ValueTooLong);
                }
                out.push(e.key);
                out.push(e.value.len() as u8);
                out.extend_from_slice(&e.value);
            }
        }
        NameRecord::ClearRecord { name, keys } => {
            write_name(&mut out, name)?;
            if keys.is_empty() {
                return Err(RecordError::Malformed("no keys"));
            }
            out.extend_from_slice(keys);
        }
        NameRecord::SetPrimary { name }
        | NameRecord::Renew { name }
        | NameRecord::Buy { name }
        | NameRecord::Delist { name } => write_name(&mut out, name)?,
        NameRecord::List { name, price, min_lifetime_blocks } => {
            write_name(&mut out, name)?;
            write_varint(&mut out, *price);
            write_varint(&mut out, *min_lifetime_blocks);
        }
    }
    Ok(out)
}

/// Encode a complete OP_META payload: `"DVXP" | version | 0x05 | subtype | body`.
pub fn encode_payload(rec: &NameRecord) -> Result<Vec<u8>, RecordError> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&MAGIC);
    out.push(SUPPORTED_VERSION);
    out.push(TYPE_NAME);
    out.push(rec.subtype());
    out.extend_from_slice(&encode_body(rec)?);
    Ok(out)
}

/// Decode a record body given its subtype.
pub fn decode_body(subtype: u8, body: &[u8]) -> Result<NameRecord, RecordError> {
    let mut c = Cursor::new(body);
    let rec = match subtype {
        SUB_COMMIT => {
            let b = c.read_bytes(20)?;
            let mut hash160 = [0u8; 20];
            hash160.copy_from_slice(b);
            NameRecord::Commit { hash160 }
        }
        SUB_REGISTER => {
            let salt = c.read_bytes(crate::commit::SALT_LEN)?.to_vec();
            let name = read_name(&mut c)?;
            NameRecord::Register { salt, name }
        }
        SUB_TRANSFER => {
            let name = read_name(&mut c)?;
            let new_owner = Address::read(&mut c)?;
            NameRecord::Transfer { name, new_owner }
        }
        SUB_SET_RECORD => {
            let name = read_name(&mut c)?;
            let mut entries = Vec::new();
            while !c.is_empty() {
                let key = c.read_u8()?;
                let len = c.read_u8()? as usize;
                if len > MAX_VALUE_LEN {
                    return Err(RecordError::ValueTooLong);
                }
                entries.push(Entry { key, value: c.read_bytes(len)?.to_vec() });
            }
            if entries.is_empty() {
                return Err(RecordError::Malformed("no entries"));
            }
            NameRecord::SetRecord { name, entries }
        }
        SUB_CLEAR_RECORD => {
            let name = read_name(&mut c)?;
            let mut keys = Vec::new();
            while !c.is_empty() {
                keys.push(c.read_u8()?);
            }
            if keys.is_empty() {
                return Err(RecordError::Malformed("no keys"));
            }
            NameRecord::ClearRecord { name, keys }
        }
        SUB_SET_PRIMARY => NameRecord::SetPrimary { name: read_name(&mut c)? },
        SUB_RENEW => NameRecord::Renew { name: read_name(&mut c)? },
        SUB_LIST => {
            let name = read_name(&mut c)?;
            let price = c.read_varint()?;
            let min_lifetime_blocks = c.read_varint()?;
            NameRecord::List { name, price, min_lifetime_blocks }
        }
        SUB_BUY => NameRecord::Buy { name: read_name(&mut c)? },
        SUB_DELIST => NameRecord::Delist { name: read_name(&mut c)? },
        other => return Err(RecordError::UnknownSubtype(other)),
    };
    if !c.is_empty() {
        return Err(RecordError::TrailingBytes);
    }
    Ok(rec)
}

/// Decode a complete OP_META payload. Returns `Ok(None)` when the payload is
/// simply not a Divi Names record (another protocol's, or not DVXP at all),
/// which is a skip, never an error.
pub fn decode_payload(payload: &[u8]) -> Result<Option<NameRecord>, RecordError> {
    if payload.len() < dvxp_core::HEADER_LEN || payload[0..4] != MAGIC {
        return Ok(None);
    }
    if payload[4] != SUPPORTED_VERSION || payload[5] != TYPE_NAME {
        return Ok(None);
    }
    decode_body(payload[6], &payload[dvxp_core::HEADER_LEN..]).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::codec::ADDRESS_P2PKH;

    fn roundtrip(rec: NameRecord) {
        let payload = encode_payload(&rec).expect("encode");
        let back = decode_payload(&payload).expect("decode").expect("is a name record");
        assert_eq!(back, rec);
    }

    #[test]
    fn every_subtype_roundtrips() {
        roundtrip(NameRecord::Commit { hash160: [0x11; 20] });
        roundtrip(NameRecord::Register { salt: vec![0xAB; 20], name: b"GEOFF".to_vec() });
        roundtrip(NameRecord::Transfer {
            name: b"GEOFF".to_vec(),
            new_owner: Address { kind: ADDRESS_P2PKH, hash160: [3; 20] },
        });
        roundtrip(NameRecord::SetRecord {
            name: b"GEOFF".to_vec(),
            entries: vec![
                Entry { key: KEY_DIVI_ADDRESS, value: vec![0; 21] },
                Entry { key: KEY_TELEGRAM, value: b"geoffmccabe".to_vec() },
            ],
        });
        roundtrip(NameRecord::ClearRecord {
            name: b"GEOFF".to_vec(),
            keys: vec![KEY_TELEGRAM, KEY_EMAIL],
        });
        roundtrip(NameRecord::SetPrimary { name: b"GEOFF".to_vec() });
        roundtrip(NameRecord::Renew { name: b"GEOFF".to_vec() });
        roundtrip(NameRecord::List {
            name: b"GEOFF".to_vec(),
            price: 250_000_00000000,
            min_lifetime_blocks: 720,
        });
        roundtrip(NameRecord::Buy { name: b"GEOFF".to_vec() });
        roundtrip(NameRecord::Delist { name: b"GEOFF".to_vec() });
    }

    #[test]
    fn a_foreign_record_is_a_skip_not_an_error() {
        // A DMT record (type 0x04) must decode as "not mine", never as garbage.
        let mut dmt = MAGIC.to_vec();
        dmt.extend_from_slice(&[SUPPORTED_VERSION, 0x04, 0x01]);
        assert_eq!(decode_payload(&dmt), Ok(None));
        assert_eq!(decode_payload(b"not dvxp at all"), Ok(None));
        assert_eq!(decode_payload(&[]), Ok(None));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut payload = encode_payload(&NameRecord::SetPrimary { name: b"GEOFF".to_vec() }).unwrap();
        payload.push(0x00);
        assert_eq!(decode_payload(&payload), Err(RecordError::TrailingBytes));
    }

    #[test]
    fn truncated_bodies_are_rejected_not_guessed() {
        let full = encode_payload(&NameRecord::Transfer {
            name: b"GEOFF".to_vec(),
            new_owner: Address { kind: ADDRESS_P2PKH, hash160: [3; 20] },
        })
        .unwrap();
        for cut in dvxp_core::HEADER_LEN..full.len() {
            assert!(decode_payload(&full[..cut]).is_err(), "should reject truncation at {cut}");
        }
    }

    #[test]
    fn unknown_subtypes_are_named_not_swallowed() {
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[SUPPORTED_VERSION, TYPE_NAME, 0x7F]);
        assert_eq!(decode_payload(&p), Err(RecordError::UnknownSubtype(0x7F)));
    }

    #[test]
    fn oversized_values_are_refused_on_encode_and_decode() {
        let rec = NameRecord::SetRecord {
            name: b"GEOFF".to_vec(),
            entries: vec![Entry { key: KEY_URL, value: vec![b'x'; MAX_VALUE_LEN + 1] }],
        };
        assert_eq!(encode_payload(&rec), Err(RecordError::ValueTooLong));
    }

    #[test]
    fn empty_entry_and_key_lists_are_malformed() {
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[SUPPORTED_VERSION, TYPE_NAME, SUB_SET_RECORD]);
        p.push(5);
        p.extend_from_slice(b"GEOFF");
        assert!(matches!(decode_payload(&p), Err(RecordError::Malformed(_))));
    }

    /// A 300-byte name must be refused, not wrapped into a shorter, different,
    /// perfectly valid-looking name by the one-byte length prefix.
    #[test]
    fn an_over_long_name_is_refused_not_truncated() {
        let rec = NameRecord::SetPrimary { name: vec![b'A'; 300] };
        assert_eq!(encode_payload(&rec), Err(RecordError::NameTooLong));
        assert_eq!(
            encode_payload(&NameRecord::SetPrimary { name: vec![b'A'; crate::charset::NAME_MAX_LEN] })
                .map(|p| p.len()),
            Ok(dvxp_core::HEADER_LEN + 1 + crate::charset::NAME_MAX_LEN)
        );
        assert!(matches!(
            encode_payload(&NameRecord::SetPrimary { name: vec![] }),
            Err(RecordError::Malformed(_))
        ));
    }

    /// Encoding refuses what decoding refuses, so a record this build writes is
    /// always one it can read back.
    #[test]
    fn empty_entry_and_key_lists_are_refused_on_encode_too() {
        assert!(matches!(
            encode_payload(&NameRecord::SetRecord { name: b"GEOFF".to_vec(), entries: vec![] }),
            Err(RecordError::Malformed(_))
        ));
        assert!(matches!(
            encode_payload(&NameRecord::ClearRecord { name: b"GEOFF".to_vec(), keys: vec![] }),
            Err(RecordError::Malformed(_))
        ));
    }

    /// Decoding must refuse an over-long name too, or a stranger can make every
    /// indexer allocate for a name that could never be registered.
    #[test]
    fn decode_refuses_an_over_long_name() {
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[SUPPORTED_VERSION, TYPE_NAME, SUB_SET_PRIMARY]);
        p.push(200);
        p.extend_from_slice(&[b'A'; 200]);
        assert_eq!(decode_payload(&p), Err(RecordError::NameTooLong));
    }

    #[test]
    fn phone_is_flagged_as_privacy_sensitive() {
        assert!(key_requires_privacy(KEY_PHONE));
        assert!(!key_requires_privacy(KEY_TELEGRAM));
        assert!(!key_requires_privacy(KEY_DIVI_ADDRESS));
    }

    /// A whole registration record must fit comfortably in one OP_META output.
    #[test]
    fn records_fit_the_payload_budget() {
        let longest = encode_payload(&NameRecord::Register {
            salt: vec![0; 20],
            name: vec![b'A'; crate::charset::NAME_MAX_LEN],
        })
        .unwrap();
        assert!(longest.len() < 100, "register record is {} bytes", longest.len());
    }
}
