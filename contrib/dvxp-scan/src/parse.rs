//! Reading a block, without knowing where it came from.
//!
//! These are the pure half of talking to a node: given the JSON a node returns,
//! turn it into the shapes [`crate::driver`] applies. No I/O, no feature gate.
//!
//! **This is deliberately not inside the `rpc` feature.** The wallet drives the
//! scanner in-process from its own node connection and compiles no HTTP client
//! at all, but it must interpret a block *identically* to the explorer, which
//! does. Two copies of "which output is a record and who sent it" is exactly the
//! divergence this crate exists to prevent, so there is one copy and both hosts
//! call it.

use std::collections::BTreeMap;

use dmt_indexer::ledger::state::{addr_key, AddrKey};
use dvxp_core::codec::{Address, ADDRESS_P2PKH, ADDRESS_P2SH};
use serde_json::Value;

/// Divi's `OP_RETURN` opcode, called `OP_META` on this chain.
pub const OP_META: u8 = 0x6a;

/// Divi's address version bytes, all four of them.
///
/// Mainnet only was a real bug: the scanner could not resolve a single sender on
/// testnet or regtest, so every record was skipped for having no sender, and the
/// overlay was untestable on exactly the networks you would want to test it on
/// before going near mainnet.
///
/// Accepting all four does NOT weaken the guard against other chains. The kind
/// byte stored on-chain is a protocol-level type, P2PKH or P2SH, not a network
/// prefix; the network is context the reader already has. Bitcoin's 0 and 5 stay
/// refused, which is the case that actually matters.
pub const MAIN_P2PKH: u8 = 30;
pub const MAIN_P2SH: u8 = 13;
pub const TEST_P2PKH: u8 = 139;
pub const TEST_P2SH: u8 = 19;

/// Extract the pushed payload from an `OP_META` output script.
///
/// Only the two push forms Divi's relay policy actually produces are accepted. A
/// truncated push is refused rather than guessed at: a partial payload that
/// happened to parse would be a record nobody wrote.
pub fn op_meta_payload(script_hex: &str) -> Option<Vec<u8>> {
    let b = hex_to_bytes(script_hex)?;
    if b.len() < 2 || b[0] != OP_META {
        return None;
    }
    let (off, len) = match b[1] {
        0x4c => (3usize, *b.get(2)? as usize), // OP_PUSHDATA1
        n if n <= 75 => (2usize, n as usize),
        _ => return None,
    };
    b.get(off..off + len).map(|s| s.to_vec())
}

/// Every `OP_META` payload carried by one transaction, in output order.
pub fn payloads_in_tx(vout: &[Value]) -> Vec<Vec<u8>> {
    vout.iter()
        .filter_map(|o| op_meta_payload(o["scriptPubKey"]["hex"].as_str()?))
        .collect()
}

/// Everything a transaction pays, plus what it provably destroys.
///
/// DMT needs this: the overlay cannot escrow DIVI, but it can insist the payment
/// appears in the same transaction as the record, which is what makes a priced
/// mint atomic instead of a promise.
pub fn payments_of(vout: &[Value]) -> (BTreeMap<AddrKey, u64>, u64) {
    let mut payments = BTreeMap::new();
    let mut burned = 0u64;
    for o in vout {
        let duffs = (o["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
        if duffs == 0 {
            continue;
        }
        match o["scriptPubKey"]["addresses"].as_array().and_then(|a| a.first()) {
            Some(a) => {
                if let Some(addr) = a.as_str().and_then(addr_from_str) {
                    *payments.entry(addr_key(addr)).or_insert(0) += duffs;
                }
            }
            // No address means provably unspendable, which is a burn.
            None => burned += duffs,
        }
    }
    (payments, burned)
}

/// The address named by one output, if it has one.
pub fn address_of_output(o: &Value) -> Option<Address> {
    o["scriptPubKey"]["addresses"]
        .as_array()?
        .first()?
        .as_str()
        .and_then(addr_from_str)
}

pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Displayed hashes are byte-reversed relative to the raw hash, which is a
/// convention rather than a fact about the data, and a source of very confusing
/// bugs when it is applied inconsistently. Applied here, once, for txids and
/// block hashes alike.
pub fn hash_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(b) = hex_to_bytes(hex) {
        for (i, byte) in b.iter().rev().enumerate().take(32) {
            out[i] = *byte;
        }
    }
    out
}

/// Base58Check to a canonical 21-byte address.
///
/// Only Divi's own version bytes are accepted. An address from another chain is
/// refused rather than reinterpreted, because a hash160 is a hash160 on every
/// chain and silently accepting one would attribute a record to an address its
/// owner cannot spend from.
pub fn addr_from_str(s: &str) -> Option<Address> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = [0u8; 25];
    for ch in s.bytes() {
        let val = ALPHABET.iter().position(|&c| c == ch)? as u32;
        let mut carry = val;
        for byte in num.iter_mut().rev() {
            let cur = (*byte as u32) * 58 + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let kind = match num[0] {
        MAIN_P2PKH => ADDRESS_P2PKH, // mainnet, addresses beginning "D"
        MAIN_P2SH => ADDRESS_P2SH,
        TEST_P2PKH => ADDRESS_P2PKH, // testnet and regtest, "x" or "y"
        TEST_P2SH => ADDRESS_P2SH,
        _ => return None,
    };
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(num.get(1..21)?);
    Some(Address { kind, hash160 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::MAGIC;
    use serde_json::json;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn extracts_a_short_push() {
        let script = format!("6a04{}", hex(&MAGIC));
        assert_eq!(op_meta_payload(&script).as_deref(), Some(MAGIC.as_slice()));
    }

    #[test]
    fn extracts_a_pushdata1() {
        let body = vec![0xab; 100];
        let script = format!("6a4c64{}", hex(&body));
        assert_eq!(op_meta_payload(&script), Some(body));
    }

    #[test]
    fn ignores_scripts_that_are_not_data_outputs() {
        assert_eq!(op_meta_payload("76a914aabb88ac"), None);
        assert_eq!(op_meta_payload(""), None);
        assert_eq!(op_meta_payload("6a"), None);
    }

    #[test]
    fn a_truncated_push_is_refused_not_guessed() {
        assert_eq!(op_meta_payload("6a4c64aabbcc"), None);
    }

    #[test]
    fn decodes_a_real_divi_address() {
        let a = addr_from_str("DPqBoHatvxSTvxdCyEMWtRoRtEt2xjcHUb").unwrap();
        assert_eq!(a.kind, ADDRESS_P2PKH);
    }

    #[test]
    fn refuses_addresses_from_other_chains() {
        assert!(addr_from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_none());
    }

    /// Regtest and testnet addresses must resolve, or the scanner cannot see a
    /// sender on either network and skips every record for having none. That
    /// made the overlay untestable anywhere except mainnet, which is the one
    /// place you would want it proven before, not after.
    #[test]
    fn decodes_regtest_and_testnet_addresses() {
        let a = addr_from_str("yCsJe6YGB4My3xiQjyUU4dC2Gc7v1H8Cna")
            .expect("a regtest address must resolve");
        assert_eq!(a.kind, ADDRESS_P2PKH);
    }

    #[test]
    fn hashes_are_reversed_exactly_once() {
        let displayed = "00".repeat(31) + "ff";
        let b = hash_bytes(&displayed);
        assert_eq!(b[0], 0xff, "the last displayed byte becomes the first raw byte");
        assert_eq!(b[31], 0x00);
    }

    #[test]
    fn payments_separate_addressed_outputs_from_burns() {
        let vout = vec![
            json!({ "value": 1.0, "scriptPubKey": { "addresses": ["DPqBoHatvxSTvxdCyEMWtRoRtEt2xjcHUb"] } }),
            json!({ "value": 0.5, "scriptPubKey": {} }),
            json!({ "value": 0.0, "scriptPubKey": {} }),
        ];
        let (payments, burned) = payments_of(&vout);
        assert_eq!(payments.len(), 1);
        assert_eq!(payments.values().next(), Some(&100_000_000));
        assert_eq!(burned, 50_000_000);
    }
}
