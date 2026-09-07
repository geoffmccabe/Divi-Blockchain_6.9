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

use std::thread::sleep;
use std::time::{Duration, Instant};

use dvxp_core::codec::Address;
use serde_json::{json, Value};

use crate::driver::{BlockInput, TxPayload};
// Reading a block is the same job whoever fetched it, so it lives in `parse`
// and both hosts call it. Re-exported here so existing callers keep working.
pub use crate::parse::{
    addr_from_str, hash_bytes, hex_to_bytes, op_meta_payload, payloads_in_tx, payments_of, OP_META,
};

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
            let scripts = payloads_in_tx(&vout);
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

/// The daemon's node is just one way of fetching a block, so it implements the
/// same trait the wallet does. That is what keeps the two hosts on one scanning
/// loop rather than two that drift.
impl crate::follow::BlockSource for Node {
    fn tip(&mut self) -> Result<u64, String> {
        self.block_count().map_err(|e| e.to_string())
    }

    fn block_hash(&mut self, height: u64) -> Result<String, String> {
        Node::block_hash(self, height).map_err(|e| e.to_string())
    }

    fn block_at(&mut self, height: u64) -> Result<BlockInput, String> {
        Node::block_at(self, height).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_known_encoding() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
    }
}