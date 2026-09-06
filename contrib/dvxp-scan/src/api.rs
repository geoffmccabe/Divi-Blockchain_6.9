//! A small read-only HTTP layer over [`crate::query`].
//!
//! The explorer, the wallet's faster paths and anything else that wants overlay
//! data all ask the same questions, so they are answered in one place instead of
//! each service hitting the node and interpreting records for itself.
//!
//! ## Deliberately hand-rolled, and deliberately read-only
//!
//! No web framework. This serves a fixed set of GET routes and returns JSON, and
//! a framework would add a dependency tree to a crate that DD69 vendors and has
//! to build standalone with no network. Every route is a read: there is nothing
//! here that can change state, which is what makes running it without
//! authentication on a loopback bind reasonable.
//!
//! **Bind to loopback unless you have thought about it.** The data is public
//! (it is all on the chain) but the service is not hardened, and an index is an
//! easy thing to hammer.
//!
//! ## Sync state travels with everything
//!
//! Every response carries `height`, `tip`, `behind`, `halted` and the
//! fingerprint alongside its payload. A client must never present balances as
//! live when they are not, and the only way to guarantee it can tell is to make
//! the answer impossible to read without the caveat attached.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use dmt_indexer::ledger::state::AddrKey;
use serde_json::{json, Value};

use crate::driver::Overlay;
use crate::query;
use crate::rpc::addr_from_str;
use crate::store::sync_state;

/// Shared handle: the scanner writes, the server reads.
#[derive(Clone)]
pub struct Shared {
    pub overlay: Arc<RwLock<Overlay>>,
    /// The node's chain tip, so "behind" is meaningful even while catching up.
    pub tip: Arc<AtomicU64>,
}

impl Shared {
    pub fn new(overlay: Overlay) -> Self {
        Self { overlay: Arc::new(RwLock::new(overlay)), tip: Arc::new(AtomicU64::new(0)) }
    }
}

/// Start the server on its own thread and return the address it bound to.
///
/// Returning the bound address matters for tests and for port 0: the caller
/// should report where it actually landed, not where it hoped to.
pub fn serve(bind: &str, shared: Shared) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let s = shared.clone();
            // One thread per connection. This is a handful of local readers,
            // not a public endpoint; a pool would be more machinery than the
            // problem deserves.
            std::thread::spawn(move || {
                let _ = handle(stream, &s);
            });
        }
    });
    Ok(addr)
}

fn handle(mut stream: TcpStream, shared: &Shared) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    if method != "GET" {
        return respond(&mut stream, 405, &json!({ "error": "read-only: GET only" }));
    }

    let (path, query_string) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    let (status, body) = route(path, query_string, shared);
    respond(&mut stream, status, &body)
}

fn route(path: &str, qs: &str, shared: &Shared) -> (u16, Value) {
    let overlay = match shared.overlay.read() {
        Ok(o) => o,
        // A poisoned lock means a scanner thread panicked mid-block. Serving
        // from that state would be serving something nobody can vouch for.
        Err(_) => {
            return (
                503,
                json!({ "error": "index unavailable: the scanner failed mid-block" }),
            )
        }
    };
    let tip = shared.tip.load(Ordering::Relaxed);
    let sync = sync_state(&overlay, tip);

    let meta = json!({
        "height": sync.height,
        "tip": sync.tip,
        "behind": sync.behind(),
        "fingerprint": sync.fingerprint,
        "halted": sync.halted,
        "haltReason": sync.halt_reason,
        "trustworthy": sync.trustworthy(),
    });

    let mut segments = path.trim_matches('/').split('/');
    let head = segments.next().unwrap_or("");
    let arg = segments.next().unwrap_or("");

    let payload: Result<Value, (u16, &str)> = match (head, arg) {
        ("", _) | ("sync", _) => Ok(json!({})),

        ("tokens", "") => Ok(json!({
            "tokens": query::all_tokens(&overlay).iter().map(token_json).collect::<Vec<_>>(),
        })),

        ("token", id) => match query::parse_token_id(id) {
            None => Err((400, "token id must be height:tx_index")),
            Some(t) => match query::token_meta(&overlay, t) {
                None => Err((404, "no such token")),
                Some(m) => Ok(json!({
                    "token": token_json(&m),
                    "history": query::token_history(&overlay, t, limit_of(qs, 50))
                        .iter().map(history_json).collect::<Vec<_>>(),
                })),
            },
        },

        ("balances", _) => match addresses_of(qs) {
            Err(bad) => Err((400, bad)),
            Ok(addrs) => Ok(json!({
                "balances": query::balances(&overlay, &addrs).iter().map(|b| json!({
                    "tokenId": query::token_id_string(b.token),
                    "amount": b.amount.to_string(),
                })).collect::<Vec<_>>(),
            })),
        },

        ("history", _) => match addresses_of(qs) {
            Err(bad) => Err((400, bad)),
            Ok(addrs) => Ok(json!({
                "events": query::history(&overlay, &addrs, limit_of(qs, 50))
                    .iter().map(history_json).collect::<Vec<_>>(),
            })),
        },

        ("ticker", name) if !name.is_empty() => {
            let s = query::ticker_status(&overlay, name.as_bytes());
            Ok(json!({
                "ticker": name,
                "taken": s.taken,
                "owner": s.owner.map(addr_json),
                "bound": s.bound,
                "priceDuffs": s.price_duffs.map(|p| p.to_string()),
            }))
        }

        ("mint-terms", id) => match query::parse_token_id(id) {
            None => Err((400, "token id must be height:tx_index")),
            Some(t) => match query::mint_terms(&overlay, t, sync.height) {
                None => Err((404, "no open mint for that token")),
                Some(m) => Ok(json!({
                    "nextPriceDuffs": m.next_price_duffs.to_string(),
                    "cap": m.cap.map(|c| c.to_string()),
                    "minted": m.minted.to_string(),
                    "remaining": m.remaining.map(|r| r.to_string()),
                    "perMint": m.per_mint.to_string(),
                    "heightStart": m.height_start,
                    "heightEnd": m.height_end,
                    "openNow": m.open_now,
                })),
            },
        },

        // One request per block page, rather than one per transaction in it.
        ("block", h) => match h.parse::<u64>() {
            Err(_) => Err((400, "block must be a height")),
            Ok(height) => {
                let a = query::block_activity(&overlay, height);
                Ok(json!({
                    "height": height,
                    "minted": a.minted.iter().map(nfd_json).collect::<Vec<_>>(),
                    "transferred": a.transferred.iter().map(nfd_json).collect::<Vec<_>>(),
                    "collections": a.collections.iter().map(hash_hex).collect::<Vec<_>>(),
                    "tokenEvents": a.token_events.iter().map(history_json).collect::<Vec<_>>(),
                    "empty": a.is_empty(),
                }))
            }
        },

        // A transaction page needs this rather than looking its txid up as a
        // collectible id: that finds mints and misses every transfer.
        ("tx", id) => match hash_arg(id) {
            None => Err((400, "txid must be 64 hex characters")),
            Some(txid) => {
                let a = query::tx_activity(&overlay, &txid);
                Ok(json!({
                    "txid": id,
                    "minted": a.minted.iter().map(nfd_json).collect::<Vec<_>>(),
                    "transferred": a.transferred.iter().map(nfd_json).collect::<Vec<_>>(),
                    "collections": a.collections.iter().map(hash_hex).collect::<Vec<_>>(),
                    "tokenEvents": a.token_events.iter().map(history_json).collect::<Vec<_>>(),
                    "empty": a.is_empty(),
                }))
            }
        },

        ("nfd", id) => match hash_arg(id) {
            None => Err((400, "id must be 64 hex characters")),
            Some(h) => match query::nfd(&overlay, &h) {
                None => Err((404, "no such collectible")),
                Some(n) => Ok(json!({ "nfd": nfd_json(&n) })),
            },
        },

        // With an owner: what that address holds. With a q: a search. With
        // neither: the latest mints, which is what a front page wants.
        ("nfds", _) => {
            let limit = limit_of(qs, 60);
            let list = match (param(qs, "owner"), param(qs, "q")) {
                (Some(_), _) => match single_address(qs) {
                    Err(bad) => return finish(Err((400, bad)), meta),
                    Ok(a) => query::nfds_owned_by(&overlay, a),
                },
                (None, Some(q)) => query::search_nfds(&overlay, &percent_decode(q), limit),
                (None, None) => query::recent_nfds(&overlay, limit),
            };
            Ok(json!({ "nfds": list.iter().map(nfd_json).collect::<Vec<_>>() }))
        }

        ("collection", id) => match hash_arg(id) {
            None => Err((400, "id must be 64 hex characters")),
            Some(h) => match query::collection(&overlay, &h) {
                None => Err((404, "no such collection")),
                Some(c) => Ok(json!({
                    "collection": {
                        "id": hash_hex(&c.id),
                        "creator": addr_json(c.creator),
                        "maxSupply": c.max_supply,
                        "minted": c.minted,
                        "metaPtr": hash_hex(&c.meta_ptr),
                    },
                    "members": query::collection_members(&overlay, &h)
                        .iter().map(nfd_json).collect::<Vec<_>>(),
                })),
            },
        },

        _ => Err((404, "no such route")),
    };

    finish(payload, meta)
}

fn finish(payload: Result<Value, (u16, &str)>, meta: Value) -> (u16, Value) {
    match payload {
        Err((status, message)) => (status, json!({ "error": message, "sync": meta })),
        Ok(Value::Object(mut map)) => {
            map.insert("sync".into(), meta);
            (200, Value::Object(map))
        }
        Ok(other) => (200, json!({ "data": other, "sync": meta })),
    }
}

/// Minimal percent-decoding for a search term.
///
/// Only what a query string needs: `%XX` and `+`. Not a general URI decoder,
/// and deliberately not pretending to be one.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Amounts go out as STRINGS, deliberately.
///
/// A token with 8 decimals and a large supply exceeds what a JavaScript number
/// can hold exactly, and silently rounding somebody's balance in transit is not
/// acceptable. The client parses the string and divides by `decimals` for
/// display only.
fn token_json(m: &query::TokenMeta) -> Value {
    json!({
        "tokenId": query::token_id_string(m.token),
        "ticker": String::from_utf8_lossy(&m.ticker),
        "decimals": m.decimals,
        "totalSupply": m.total_supply.to_string(),
        "maxSupply": m.max_supply.map(|c| c.to_string()),
        "supplyLocked": m.supply_locked,
        "issuer": addr_json(m.issuer),
        "mintOpen": m.mint_open,
        "genesisTxid": m.genesis_txid.map(|t| hash_hex(&t)),
        // The chain carries a ticker, not a display name. Anything richer lives
        // behind this pointer; a client that has not resolved it should show
        // the ticker rather than invent a name.
        "metadataPtr": m.metadata_ptr.map(|p| hash_hex(&p)),
    })
}

fn history_json(h: &query::HistoryEntry) -> Value {
    json!({
        "kind": h.kind.as_str(),
        "tokenId": query::token_id_string(h.token),
        "counterparty": h.counterparty.map(addr_json),
        "amount": h.amount.to_string(),
        "height": h.height,
        "txid": hash_hex(&h.txid),
        "blockTime": h.block_time,
    })
}

fn nfd_json(n: &query::NfdView) -> Value {
    json!({
        "id": hash_hex(&n.id),
        "owner": addr_json(n.owner),
        "arweavePtr": hash_hex(&n.arweave_ptr),
        "contentHash": hash_hex(&n.content_hash),
        "thumbPtr": n.thumb_ptr.map(|t| hash_hex(&t)),
        "collectionId": n.collection_id.map(|c| hash_hex(&c)),
        "mintHeight": n.mint_height,
    })
}

/// Addresses go out as `kind:hash160-hex` rather than base58.
///
/// Re-encoding base58check here would mean a second implementation of it in
/// this crate, and two implementations of an address format is exactly the kind
/// of duplication that eventually disagrees. The caller that needs a display
/// address already has one.
fn addr_json(a: AddrKey) -> Value {
    Value::String(format!("{}:{}", a.0, hex(&a.1)))
}

/// Back to the byte order people read hashes in.
fn hash_hex(raw: &[u8; 32]) -> String {
    let mut r = *raw;
    r.reverse();
    hex(&r)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

fn param<'a>(qs: &'a str, key: &str) -> Option<&'a str> {
    qs.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

fn limit_of(qs: &str, default: usize) -> usize {
    param(qs, "limit")
        .and_then(|v| v.parse().ok())
        // A caller asking for everything is usually a caller that has not
        // thought about it. Cap rather than fall over.
        .map(|n: usize| n.clamp(1, 1000))
        .unwrap_or(default)
}

fn addresses_of(qs: &str) -> Result<Vec<AddrKey>, &'static str> {
    let raw = param(qs, "addresses").ok_or("addresses parameter required")?;
    let mut out = Vec::new();
    for a in raw.split(',').filter(|s| !s.is_empty()) {
        let parsed = addr_from_str(a).ok_or("not a Divi address")?;
        out.push(dmt_indexer::ledger::state::addr_key(parsed));
    }
    if out.is_empty() {
        return Err("at least one address required");
    }
    Ok(out)
}

fn single_address(qs: &str) -> Result<AddrKey, &'static str> {
    let raw = param(qs, "owner").ok_or("owner parameter required")?;
    let parsed = addr_from_str(raw).ok_or("not a Divi address")?;
    Ok(dmt_indexer::ledger::state::addr_key(parsed))
}

/// A 64-character hex hash, in display order, converted back to raw bytes.
fn hash_arg(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = crate::rpc::hex_to_bytes(s)?;
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate().take(32) {
        out[i] = *b;
    }
    Some(out)
}

fn respond(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let text = serde_json::to_string(body)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n{text}",
        text.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_handles_what_a_search_box_sends() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%41%42"), "AB");
        // A stray percent is kept rather than swallowed: mangling a search term
        // silently is worse than returning nothing for it.
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn addresses_round_trip_through_the_form_we_emit() {
        let a: AddrKey = (0, [0xab; 20]);
        let shown = addr_json(a);
        let text = shown.as_str().unwrap();
        assert_eq!(query::hex_to_addr(text), Some(a));
        assert_eq!(query::hex_to_addr("nonsense"), None);
        assert_eq!(query::hex_to_addr("0:tooshort"), None);
    }

    #[test]
    fn nfds_answers_three_different_questions() {
        let shared = Shared::new(Overlay::new());
        // No parameters: the latest mints, empty here but a valid answer.
        let (status, body) = route("/nfds", "", &shared);
        assert_eq!(status, 200);
        assert!(body["nfds"].as_array().unwrap().is_empty());
        // A search term is accepted.
        assert_eq!(route("/nfds", "q=abc", &shared).0, 200);
        // A bad owner is still refused rather than silently treated as a search.
        assert_eq!(route("/nfds", "owner=notanaddress", &shared).0, 400);
    }

    #[test]
    fn query_parameters_are_read_and_limits_are_capped() {
        assert_eq!(param("a=1&b=2", "b"), Some("2"));
        assert_eq!(param("a=1", "missing"), None);
        assert_eq!(limit_of("limit=10", 50), 10);
        assert_eq!(limit_of("", 50), 50);
        assert_eq!(limit_of("limit=999999", 50), 1000, "an absurd limit is capped");
        assert_eq!(limit_of("limit=0", 50), 1, "and a nonsensical one is floored");
    }

    #[test]
    fn addresses_must_actually_be_divi_addresses() {
        assert!(addresses_of("").is_err(), "the parameter is required");
        assert!(
            addresses_of("addresses=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_err(),
            "a Bitcoin address is refused rather than reinterpreted"
        );
        assert!(addresses_of("addresses=DPqBoHatvxSTvxdCyEMWtRoRtEt2xjcHUb").is_ok());
    }

    #[test]
    fn hash_arguments_round_trip_through_display_order() {
        let raw = [7u8; 32];
        let shown = hash_hex(&raw);
        assert_eq!(shown.len(), 64);
        assert_eq!(hash_arg(&shown), Some(raw));
        assert_eq!(hash_arg("too short"), None);
    }

    #[test]
    fn an_empty_index_still_answers_with_its_sync_state() {
        let shared = Shared::new(Overlay::new());
        let (status, body) = route("/sync", "", &shared);
        assert_eq!(status, 200);
        assert_eq!(body["sync"]["height"], 0);
        assert_eq!(body["sync"]["halted"], false);
        assert_eq!(body["sync"]["trustworthy"], true, "an empty index at tip 0 is current");
    }

    #[test]
    fn unknown_routes_and_bad_ids_are_refused_clearly() {
        let shared = Shared::new(Overlay::new());
        assert_eq!(route("/nonsense", "", &shared).0, 404);
        assert_eq!(route("/token/not-an-id", "", &shared).0, 400);
        assert_eq!(route("/token/1:0", "", &shared).0, 404);
        assert_eq!(route("/nfd/zz", "", &shared).0, 400);
        assert_eq!(route("/balances", "", &shared).0, 400);
    }

    /// Every response carries the caveat, including the failures. A client that
    /// only ever sees data cannot know when not to trust it.
    #[test]
    fn even_an_error_carries_the_sync_state() {
        let shared = Shared::new(Overlay::new());
        let (status, body) = route("/token/9:9", "", &shared);
        assert_eq!(status, 404);
        assert!(body["sync"]["fingerprint"].is_string());
    }
}
