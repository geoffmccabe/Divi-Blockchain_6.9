//! The overlay indexer daemon.
//!
//! Catches up from the genesis height, then follows the tip for as long as it
//! runs, rolling back and re-applying when the chain reorganises.
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
//! POLL_SECONDS     how often to look for a new block (default 20)
//! RPC_GAP_MICROS   minimum gap between RPC calls (default 4000, about 250/sec)
//! SNAPSHOT_EVERY   blocks between snapshot writes while catching up (default 5000)
//! ```

use std::env;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::Duration;

use dvxp_scan::driver::{Overlay, ScanError};
use dvxp_scan::rpc::{Node, Throttle};
use dvxp_scan::store::Snapshot;

/// Exit code for a halt. Distinct from an ordinary failure so a supervisor can
/// tell "upgrade me" apart from "the node went away", and refuse to restart-loop
/// on the former.
const EXIT_HALTED: u8 = 2;
/// Exit code for losing the node.
const EXIT_NO_NODE: u8 = 3;

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

    let start = env_u64("START_HEIGHT", 0);
    let poll = Duration::from_secs(env_u64("POLL_SECONDS", 20));
    let gap = Duration::from_micros(env_u64("RPC_GAP_MICROS", 4_000));
    let snapshot_every = env_u64("SNAPSHOT_EVERY", 5_000).max(1);
    let snapshot = Snapshot::new(
        env::var("SNAPSHOT").unwrap_or_else(|_| "/var/lib/divi-scan/overlay.json".into()),
    );

    let mut node = Node::new(url, &user, &pass, Throttle::new(gap));
    let mut overlay = Overlay::new();

    let mut tip = match node.block_count() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_NO_NODE);
        }
    };

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
            match apply_one(&mut node, &mut overlay, next) {
                Ok(()) => {}
                Err(Fatal::Halted(reason)) => {
                    eprintln!("HALT at height {next}: {reason}");
                    eprintln!("This build cannot read that record. Upgrade, then restart.");
                    let _ = snapshot.write(&overlay, tip);
                    return ExitCode::from(EXIT_HALTED);
                }
                Err(Fatal::NoNode(e)) => {
                    eprintln!("lost the node at height {next}: {e}");
                    let _ = snapshot.write(&overlay, tip);
                    return ExitCode::from(EXIT_NO_NODE);
                }
                Err(Fatal::Reorg(e)) => {
                    // Deeper than the retained window. Serving state we cannot
                    // justify is the one thing worse than being unavailable.
                    eprintln!("cannot unwind the chain: {e:?}");
                    eprintln!("Resync from START_HEIGHT is required.");
                    let _ = snapshot.write(&overlay, tip);
                    return ExitCode::from(EXIT_HALTED);
                }
            }

            if next % snapshot_every == 0 || next == tip {
                let _ = snapshot.write(&overlay, tip);
                println!(
                    "  {next}/{tip}  collectibles {}  tokens {}  rpc calls {}",
                    overlay.nfd.count(),
                    overlay.dmt.ledger.state.tokens.len(),
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
                let _ = snapshot.write(&overlay, tip);
                return ExitCode::from(EXIT_NO_NODE);
            }
        };

        match check_for_reorg(&mut node, &mut overlay) {
            Ok(Some(rolled_back_to)) => {
                println!("reorg: rolled back to {rolled_back_to}, re-applying from there");
                next = rolled_back_to + 1;
                let _ = snapshot.write(&overlay, tip);
            }
            Ok(None) => {}
            Err(Fatal::Reorg(e)) => {
                eprintln!("reorg deeper than the undo window: {e:?}");
                eprintln!("Resync from START_HEIGHT is required.");
                let _ = snapshot.write(&overlay, tip);
                return ExitCode::from(EXIT_HALTED);
            }
            Err(Fatal::NoNode(e)) => {
                eprintln!("lost the node while checking for a reorg: {e}");
                return ExitCode::from(EXIT_NO_NODE);
            }
            Err(Fatal::Halted(r)) => {
                eprintln!("HALT: {r}");
                return ExitCode::from(EXIT_HALTED);
            }
        }
    }
}

enum Fatal {
    Halted(String),
    NoNode(String),
    Reorg(ScanError),
}

fn apply_one(node: &mut Node, overlay: &mut Overlay, height: u64) -> Result<(), Fatal> {
    let block = node.block_at(height).map_err(|e| Fatal::NoNode(e.to_string()))?;
    match overlay.apply_block(&block) {
        Ok(summary) => {
            // Skips are facts about the chain, not noise. The previous scanner
            // discarded them, which meant a rejected record left no trace
            // anywhere and could not be investigated after the fact.
            for (tx_index, reason) in &summary.skipped {
                println!("  skip height {height} tx {tx_index}: {reason:?}");
            }
            Ok(())
        }
        Err(ScanError::Halted(h)) | Err(ScanError::AlreadyHalted(h)) => {
            Err(Fatal::Halted(format!("{h:?}")))
        }
        Err(other) => Err(Fatal::Reorg(other)),
    }
}

/// Has the chain replaced blocks we already applied?
///
/// Compares the hash the node reports at our tip with the one we recorded.
/// Matching means nothing moved. Differing means we walk back until the hashes
/// agree again and unwind to there. Divi caps reorgs at 100 blocks and the undo
/// window retains 200, so this search is bounded by design rather than by hope.
///
/// Returns the height rolled back to, or `None` if nothing changed.
fn check_for_reorg(node: &mut Node, overlay: &mut Overlay) -> Result<Option<u64>, Fatal> {
    let Some(our_tip) = overlay.tip() else {
        return Ok(None);
    };
    let Some(our_hash) = overlay.hash_at(our_tip) else {
        return Ok(None);
    };

    if hash_matches(node, our_tip, our_hash)? {
        return Ok(None);
    }

    // Walk back through what we still retain, looking for the fork point.
    let oldest = overlay.oldest_undo_height().unwrap_or(our_tip);
    let mut height = our_tip;
    while height > oldest {
        height -= 1;
        let Some(stored) = overlay.hash_at(height) else { break };
        if hash_matches(node, height, stored)? {
            overlay.rollback_to(height).map_err(Fatal::Reorg)?;
            return Ok(Some(height));
        }
    }

    Err(Fatal::Reorg(ScanError::BeyondUndoWindow { requested: oldest, oldest }))
}

fn hash_matches(node: &mut Node, height: u64, expected: [u8; 32]) -> Result<bool, Fatal> {
    let hex = node.block_hash(height).map_err(|e| Fatal::NoNode(e.to_string()))?;
    Ok(dvxp_scan::rpc::hash_bytes(&hex) == expected)
}
