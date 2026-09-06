//! The overlay indexer daemon.
//!
//! Catches up from the genesis height, then follows the tip for as long as it
//! runs, rolling back and re-applying when the chain reorganises, and serving
//! the read API the whole time.
//!
//! Its predecessor scanned once and exited, which was enough to prove the
//! parsers worked and not enough to run anything: a restart rescanned from
//! zero, a reorg silently left the wrong answer in place, and nothing throttled
//! the node.
//!
//! Configuration is entirely environment variables, because this runs as a
//! service next to a node and a config file is one more thing to get out of
//! sync with the unit file:
//!
//! ```text
//! DIVI_RPC_URL     default http://127.0.0.1:51473/
//! DIVI_RPC_USER    required
//! DIVI_RPC_PASS    required
//! START_HEIGHT     genesis height for the overlay (default 0)
//! SNAPSHOT         where to publish progress (default /var/lib/divi-scan/overlay.json)
//! API_BIND         read API address (default 127.0.0.1:8710, empty disables it)
//! POLL_SECONDS     how often to look for a new block (default 20)
//! RPC_GAP_MICROS   minimum gap between RPC calls (default 4000, about 250/sec)
//! SNAPSHOT_EVERY   blocks between snapshot writes while catching up (default 5000)
//! ALLOW_PLACEHOLDER_TREASURY=1   run with the treasury unset (regtest only)
//! ```

use std::env;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::thread::sleep;
use std::time::Duration;

use dvxp_scan::api::{self, Shared};
use dvxp_scan::driver::{Overlay, ScanError};
use dvxp_scan::rpc::{Node, Throttle};
use dvxp_scan::store::Snapshot;

/// Exit code for a halt. Distinct from an ordinary failure so a supervisor can
/// tell "upgrade me" apart from "the node went away", and refuse to restart-loop
/// on the former.
const EXIT_HALTED: u8 = 2;
/// Exit code for losing the node.
const EXIT_NO_NODE: u8 = 3;
/// Exit code for a configuration that would produce wrong answers.
const EXIT_MISCONFIGURED: u8 = 4;

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn main() -> ExitCode {
    let url = env::var("DIVI_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:51473/".into());
    let user = env::var("DIVI_RPC_USER").unwrap_or_default();
    let pass = env::var("DIVI_RPC_PASS").unwrap_or_default();
    if user.is_empty() {
        eprintln!("DIVI_RPC_USER and DIVI_RPC_PASS must be set");
        return ExitCode::from(1);
    }

    // The treasury address is still the all-zero placeholder, and the token
    // creation fee is checked against it. That means a payment to an address
    // nobody controls currently satisfies the fee, so an index run against a
    // real chain in this state would record token issuances that never really
    // paid for anything. dmt-indexer provides the guard; this is the thing that
    // was supposed to call it.
    if !dmt_indexer::config::treasury_is_configured()
        && env::var("ALLOW_PLACEHOLDER_TREASURY").as_deref() != Ok("1")
    {
        eprintln!("refusing to start: the DMT treasury address is still the placeholder.");
        eprintln!("Registry fees are checked against it, so every fee check would pass");
        eprintln!("against an address nobody controls. Set TREASURY_HASH160 in");
        eprintln!("dmt-indexer/src/config.rs, or set ALLOW_PLACEHOLDER_TREASURY=1 for regtest.");
        return ExitCode::from(EXIT_MISCONFIGURED);
    }

    let start = env_u64("START_HEIGHT", 0);
    let poll = Duration::from_secs(env_u64("POLL_SECONDS", 20));
    let gap = Duration::from_micros(env_u64("RPC_GAP_MICROS", 4_000));
    let snapshot_every = env_u64("SNAPSHOT_EVERY", 5_000).max(1);
    let snapshot = Snapshot::new(
        env::var("SNAPSHOT").unwrap_or_else(|_| "/var/lib/divi-scan/overlay.json".into()),
    );
    let api_bind = env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:8710".into());

    let mut node = Node::new(url, &user, &pass, Throttle::new(gap));
    let shared = Shared::new(Overlay::new());

    let mut tip = match node.block_count() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_NO_NODE);
        }
    };
    shared.tip.store(tip, Ordering::Relaxed);

    // Served from the start, so a client can watch the catch-up rather than
    // getting connection refused for however long it takes.
    if !api_bind.is_empty() {
        match api::serve(&api_bind, shared.clone()) {
            Ok(addr) => println!("read API on http://{addr}/"),
            Err(e) => {
                eprintln!("cannot bind the read API on {api_bind}: {e}");
                return ExitCode::from(EXIT_MISCONFIGURED);
            }
        }
    }

    if start == 0 {
        eprintln!(
            "warning: START_HEIGHT is 0, so this will replay the entire chain. \
             Set it to the overlay genesis height once that is chosen."
        );
    }
    println!("catching up {start} -> {tip}, snapshot at {}", snapshot.path().display());

    let mut next = start;
    loop {
        while next <= tip {
            // Fetched OUTSIDE the lock. A block costs several RPC round trips
            // and readers should not wait on the network for them.
            let block = match node.block_at(next) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("lost the node at height {next}: {e}");
                    let o = shared.overlay.read().expect("scanner owns the only writer");
                    let _ = snapshot.write(&o, tip);
                    return ExitCode::from(EXIT_NO_NODE);
                }
            };

            let outcome = {
                let mut o = shared.overlay.write().expect("scanner owns the only writer");
                o.apply_block(&block)
            };

            match outcome {
                Ok(summary) => {
                    // Skips are facts about the chain, not noise. The previous
                    // scanner discarded them, so a rejected record left no
                    // trace anywhere and could not be investigated afterwards.
                    for (tx_index, reason) in &summary.skipped {
                        println!("  skip height {next} tx {tx_index}: {reason:?}");
                    }
                }
                Err(ScanError::Halted(h)) | Err(ScanError::AlreadyHalted(h)) => {
                    eprintln!("HALT at height {next}: {h:?}");
                    eprintln!("This build cannot read that record. Upgrade, then restart.");
                    let o = shared.overlay.read().expect("scanner owns the only writer");
                    let _ = snapshot.write(&o, tip);
                    return ExitCode::from(EXIT_HALTED);
                }
                Err(other) => {
                    eprintln!("cannot continue at height {next}: {other:?}");
                    let o = shared.overlay.read().expect("scanner owns the only writer");
                    let _ = snapshot.write(&o, tip);
                    return ExitCode::from(EXIT_HALTED);
                }
            }

            if next % snapshot_every == 0 || next == tip {
                let o = shared.overlay.read().expect("scanner owns the only writer");
                let _ = snapshot.write(&o, tip);
                println!(
                    "  {next}/{tip}  collectibles {}  tokens {}  events {}  rpc calls {}",
                    o.nfd.count(),
                    o.dmt.ledger.state.tokens.len(),
                    o.log.token_event_count() + o.log.nfd_event_count(),
                    node.call_count()
                );
            }
            next += 1;
        }

        // Caught up. Wait for the chain to move, then check it did not move
        // sideways underneath us.
        sleep(poll);
        tip = match node.block_count() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("lost the node while idle: {e}");
                return ExitCode::from(EXIT_NO_NODE);
            }
        };
        shared.tip.store(tip, Ordering::Relaxed);

        match check_for_reorg(&mut node, &shared) {
            Ok(Some(rolled_back_to)) => {
                println!("reorg: rolled back to {rolled_back_to}, re-applying from there");
                next = rolled_back_to + 1;
            }
            Ok(None) => {}
            Err(Fatal::Reorg(e)) => {
                // Deeper than the retained window. Serving state we cannot
                // justify is the one thing worse than being unavailable.
                eprintln!("reorg deeper than the undo window: {e:?}");
                eprintln!("Resync from START_HEIGHT is required.");
                return ExitCode::from(EXIT_HALTED);
            }
            Err(Fatal::NoNode(e)) => {
                eprintln!("lost the node while checking for a reorg: {e}");
                return ExitCode::from(EXIT_NO_NODE);
            }
        }
    }
}

enum Fatal {
    NoNode(String),
    Reorg(ScanError),
}

/// Has the chain replaced blocks we already applied?
///
/// Compares the hash the node reports at our tip with the one we recorded.
/// Matching means nothing moved. Differing means we walk back until the hashes
/// agree again and unwind to there. Divi caps reorgs at 100 blocks and the undo
/// window retains 200, so this search is bounded by design rather than by hope.
///
/// Returns the height rolled back to, or `None` if nothing changed.
fn check_for_reorg(node: &mut Node, shared: &Shared) -> Result<Option<u64>, Fatal> {
    let (our_tip, our_hash, oldest) = {
        let o = shared.overlay.read().expect("scanner owns the only writer");
        let Some(tip) = o.tip() else { return Ok(None) };
        let Some(hash) = o.hash_at(tip) else { return Ok(None) };
        (tip, hash, o.oldest_undo_height().unwrap_or(tip))
    };

    if hash_matches(node, our_tip, our_hash)? {
        return Ok(None);
    }

    // Walk back through what we still retain, looking for the fork point. The
    // node is asked outside the lock; only the rollback itself takes the writer.
    let mut height = our_tip;
    while height > oldest {
        height -= 1;
        let stored = {
            let o = shared.overlay.read().expect("scanner owns the only writer");
            match o.hash_at(height) {
                Some(h) => h,
                None => break,
            }
        };
        if hash_matches(node, height, stored)? {
            let mut o = shared.overlay.write().expect("scanner owns the only writer");
            o.rollback_to(height).map_err(Fatal::Reorg)?;
            return Ok(Some(height));
        }
    }

    Err(Fatal::Reorg(ScanError::BeyondUndoWindow { requested: oldest, oldest }))
}

fn hash_matches(node: &mut Node, height: u64, expected: [u8; 32]) -> Result<bool, Fatal> {
    let hex = node.block_hash(height).map_err(|e| Fatal::NoNode(e.to_string()))?;
    Ok(dvxp_scan::rpc::hash_bytes(&hex) == expected)
}
