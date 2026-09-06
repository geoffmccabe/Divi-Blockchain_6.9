//! Talking to a Divi node, and turning a block into something the driver can
//! apply.
//!
//! Optional, behind the `rpc` feature. The wallet drives the driver from its own
//! node connection and compiles none of this.
//!
//! ## Throttling is not a nicety here
//!
//! A previous scanner ran twelve workers at roughly 1,170 blocks per second,
//! saturated the node's RPC threads and took the public explorer offline. Divi
//! allocates one node thread per application connection, so a scanner that helps
//! itself to the pool starves staking and the wallet. Every call in this module
//! goes through [`Throttle`], and the default deliberately leaves the node most
//! of its capacity.

use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use dmt_indexer::ledger::state::addr_key;
use dvxp_core::codec::{Address, ADDRESS_P2PKH, ADDRESS_P2SH};
use serde_json::{json, Value};

use crate::driver::{BlockInput, TxPayload};

/// Divi's `OP_RETURN` opcode, called `OP_META` on this chain.
pub const OP_META: u8 = 0x6a;

#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    /// The node answered, and said no.
    Node(String),
    /// The answer was not shaped the way the field expects.
    Malformed(&'static str),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(e) => write!(f, "cannot reach the node: {e}"),
            RpcError::Node(e) => write!(f, "node refused: {e}"),
            RpcError::Malformed(w) => write!(f, "unexpected answer shape: {w}"),
        }
    }
}

/// A minimum gap between calls, so the scanner cannot monopolise the node.
#[derive(Debug)]
pub struct Throttle {
    min_gap: Duration,
    last: Option<Instant>,
}

impl Throttle {
    pub fn new(min_gap: Duration) -> Self {
        Self { min_gap, last: None }
    }

    /// Roughly 250 calls a second. Fast enough to catch up in minutes from a
    /// genesis height, slow enough that the node keeps its own threads.
    pub fn polite() -> Self {
        Self::new(Duration::from_micros(4_000))
    }

    /// No waiting. For tests and for a node nobody else is using.
    pub fn unlimited() -> Self {
        Self::new(Duration::ZERO)
    }

    fn wait(&mut self) {
        if let Some(last) = self.last {
            let elapsed = last.elapsed();
            if elapsed < self.min_gap {
                sleep(self.min_gap - elapsed);
            }
        }
        self.last = Some(Instant::now());
    }
}

pub struct Node {
    url: String,
    auth: String,
    agent: ureq::Agent,
    throttle: Throttle,
    calls: u64,
}

impl Node {
    pub fn new(url: impl Into<String>, user: &str, pass: &str, throttle: Throttle) -> Self {
        Self {
            url: url.into(),
            auth: format!("Basic {}", base64(format!("{user}:{pass}").as_bytes())),
            // ONE pooled connection, deliberately.
            //
            // Divi allocates a node thread per application connection, and the
            // default pool is small. Building a fresh request per call (which is
            // what `ureq::post` on its own does) opens a new TCP connection every
            // time, so a scanner making three calls per block churns through
            // connections at exactly the rate that starves staking and wedges
            // the node's RPC. Holding one agent keeps the whole scan to a single
            // connection, and as a side effect removes a TCP handshake from every
            // call, which is most of the per-call cost.
            agent: ureq::AgentBuilder::new()
                .max_idle_connections(1)
                .max_idle_connections_per_host(1)
                .timeout_read(Duration::from_secs(30))
                .timeout_write(Duration::from_secs(30))
                .build(),
            throttle,
            calls: 0,
        }
    }

    /// How many RPC calls have been made. Worth logging: it is the number that
    /// predicts whether the node is about to have a bad time.
    pub fn call_count(&self) -> u64 {
        self.calls
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.throttle.wait();
        self.calls += 1;

        let body = json!({ "jsonrpc": "1.0", "id": "dvxp", "method": method, "params": params });
        let resp = self
            .agent
            .post(&self.url)
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());

        let text = match resp {
            Ok(r) => r.into_string().map_err(|e| RpcError::Transport(e.to_string()))?,
            // The node answers RPC-level errors with a 500 and a JSON body, so
            // that is an answer rather than a transport failure.
            Err(ureq::Error::Status(_, r)) => {
                r.into_string().map_err(|e| RpcError::Transport(e.to_string()))?
            }
            Err(e) => return Err(RpcError::Transport(e.to_string())),
        };

        let v: Value =
            serde_json::from_str(&text).map_err(|e| RpcError::Transport(e.to_string()))?;
        if !v["error"].is_null() {
            return Err(RpcError::Node(
                v["error"]["message"].as_str().unwrap_or("rpc error").to_string(),
            ));
        }
        Ok(v["result"].clone())
    }

    pub fn block_count(&mut self) -> Result<u64, RpcError> {
        self.call("getblockcount", json!([]))?
            .as_u64()
            .ok_or(RpcError::Malformed("getblockcount"))
    }

    pub fn block_hash(&mut self, height: u64) -> Result<String, RpcError> {
        self.call("getblockhash", json!([height]))?
            .as_str()
            .map(str::to_string)
            .ok_or(RpcError::Malformed("getblockhash"))
    }

    /// Fetch one block, reduced to the overlay records it carries.
    ///
    /// Most blocks contain no data output at all, so the expensive work (a
    /// prevout lookup per record-bearing transaction) is only done for the few
    /// that do.
    pub fn block_at(&mut self, height: u64) -> Result<BlockInput, RpcError> {
        let hash_hex = self.block_hash(height)?;
        let block = self.call("getblock", json!([hash_hex.clone()]))?;
        let time = block["time"].as_i64().unwrap_or(0);

        let txids: Vec<String> = block["tx"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();

        let mut payloads = Vec::new();
        for (tx_index, txid_s) in txids.iter().enumerate() {
            let tx = match self.call("getrawtransaction", json!([txid_s, 1])) {
                Ok(v) => v,
                // A transaction the node will not return is not a reason to
                // invent state. Skip it and keep the reason visible upstream by
                // leaving the block short rather than pretending it was empty.
                Err(_) => continue,
            };
            let vout = tx["vout"].as_array().cloned().unwrap_or_default();

            // Cheap pre-filter: no data output means nothing here concerns us,
            // and resolving a sender costs another round trip.
            let scripts: Vec<Vec<u8>> = vout
                .iter()
                .filter_map(|o| op_meta_payload(o["scriptPubKey"]["hex"].as_str()?))
                .collect();
            if scripts.is_empty() {
                continue;
            }

            let sender = self.sender_of(&tx);
            let (payments, burned) = payments_of(&vout);
            let txid = hash_bytes(txid_s);

            for payload in scripts {
                payloads.push(TxPayload {
                    tx_index: tx_index as u32,
                    txid,
                    payload,
                    sender,
                    payments: payments.clone(),
                    burned,
                });
            }
        }

        Ok(BlockInput { height, hash: hash_bytes(&hash_hex), time, payloads })
    }

    /// The address funding `vin[0]`: the deterministic sender rule.
    ///
    /// Divi has no SegWit, which is usually a limitation and here is not: the
    /// prevout's script carries the address directly, so the sender of a record
    /// is unambiguous.
    fn sender_of(&mut self, tx: &Value) -> Option<Address> {
        let vin0 = tx["vin"].as_array()?.first()?;
        let prev_txid = vin0["txid"].as_str()?.to_string();
        let n = vin0["vout"].as_u64()? as usize;
        let prev = self.call("getrawtransaction", json!([prev_txid, 1])).ok()?;
        let a = prev["vout"].as_array()?.get(n)?["scriptPubKey"]["addresses"]
            .as_array()?
            .first()?
            .as_str()?
            .to_string();
        addr_from_str(&a)
    }
}

/// Everything a transaction pays, plus what it provably destroys.
///
/// DMT needs this: the overlay cannot escrow DIVI, but it can insist the payment
/// appears in the same transaction as the record, which is what makes a priced
/// mint atomic instead of a promise.
fn payments_of(vout: &[Value]) -> (BTreeMap<dmt_indexer::ledger::state::AddrKey, u64>, u64) {
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

pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
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
    let mut num = vec![0u8; 25];
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
        30 => ADDRESS_P2PKH, // Divi P2PKH: addresses beginning "D"
        13 => ADDRESS_P2SH,
        _ => return None,
    };
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(num.get(1..21)?);
    Some(Address { kind, hash160 })
}

/// Hand-rolled so the crate does not pull a dependency in for one header.
fn base64(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::MAGIC;

    #[test]
    fn extracts_a_short_push() {
        // OP_META, push 4, "DVXP"
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
        // Claims 100 bytes, supplies 3.
        assert_eq!(op_meta_payload("6a4c64aabbcc"), None);
    }

    #[test]
    fn decodes_a_real_divi_address() {
        let a = addr_from_str("DPqBoHatvxSTvxdCyEMWtRoRtEt2xjcHUb").unwrap();
        assert_eq!(a.kind, ADDRESS_P2PKH);
    }

    #[test]
    fn refuses_addresses_from_other_chains() {
        // A Bitcoin P2PKH address: right shape, wrong version byte.
        assert!(addr_from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_none());
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
            json!({ "value": 0.5, "scriptPubKey": {} }), // no address: burned
            json!({ "value": 0.0, "scriptPubKey": {} }), // the data output itself
        ];
        let (payments, burned) = payments_of(&vout);
        assert_eq!(payments.len(), 1);
        assert_eq!(payments.values().next(), Some(&100_000_000));
        assert_eq!(burned, 50_000_000);
    }

    #[test]
    fn base64_matches_the_known_encoding() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
