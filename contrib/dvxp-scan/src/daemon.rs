//! The overlay indexer daemon: catch up, follow the tip, serve the read API.
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

use crate::api::{self, Shared};
use crate::driver::Overlay;
use crate::follow::{FollowError, Follower};
use crate::rpc::{Node, Throttle};
use crate::store::Snapshot;

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

/// Run the indexer until it stops, and return the code it stopped with.
///
/// Lives in the library rather than the binary so any host can run exactly this
/// daemon rather than reimplementing it. The explorer does: its own binary is a
/// two-line shim around this call, which is what stopped it carrying a second
/// scanner that could drift.
pub fn run_daemon() -> ExitCode {
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
    // Blocks applied before the scanner pauses, publishes progress and lets the
    // node breathe. It used to control only how often a snapshot was written;
    // now it is the slice size too, which is the more useful knob: it is the
    // dial between catching up fast and leaving the node alone.
    let slice = env_u64("SNAPSHOT_EVERY", 500).max(1);
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

    // The shared follower, not a loop of its own. The wallet drives the same
    // one from its own node connection; two copies would drift.
    let mut follower = Follower::new(start);

    loop {
        loop {
            // The writer lock is held only for the slice, so the read API keeps
            // answering between slices rather than blocking for a whole catch-up.
            let outcome = {
                let mut o = shared.overlay.write().expect("scanner owns the only writer");
                follower.catch_up(&mut o, &mut node, slice)
            };
            let progress = match outcome {
                Ok(p) => p,
                Err(FollowError::Source(e)) => {
                    eprintln!("lost the node: {e}");
                    let o = shared.overlay.read().expect("scanner owns the only writer");
                    let _ = snapshot.write(&o, tip);
                    return ExitCode::from(EXIT_NO_NODE);
                }
                Err(e @ FollowError::Fatal(_)) => {
                    eprintln!("HALT: {e}");
                    let o = shared.overlay.read().expect("scanner owns the only writer");
                    let _ = snapshot.write(&o, tip);
                    return ExitCode::from(EXIT_HALTED);
                }
            };

            tip = progress.tip;
            shared.tip.store(tip, Ordering::Relaxed);
            // Skips are facts about the chain, not noise. The first scanner
            // discarded them, so a rejected record left no trace anywhere.
            for (height, tx_index, why) in &progress.skipped {
                println!("  skip height {height} tx {tx_index}: {why:?}");
            }

            if progress.applied > 0 {
                let o = shared.overlay.read().expect("scanner owns the only writer");
                let _ = snapshot.write(&o, tip);
                println!(
                    "  {}/{tip}  collectibles {}  tokens {}  events {}  rpc calls {}",
                    progress.height,
                    o.nfd.count(),
                    o.dmt.ledger.state.tokens.len(),
                    o.log.token_event_count() + o.log.nfd_event_count(),
                    node.call_count()
                );
            }
            if progress.caught_up {
                break;
            }
        }

        // Caught up. Wait for the chain to move, then check it did not move
        // sideways underneath us.
        sleep(poll);
        let reorg = {
            let mut o = shared.overlay.write().expect("scanner owns the only writer");
            follower.check_for_reorg(&mut o, &mut node)
        };
        match reorg {
            Ok(Some(height)) => {
                println!("reorg: rolled back to {height}, re-applying from there");
            }
            Ok(None) => {}
            Err(FollowError::Source(e)) => {
                eprintln!("lost the node while checking for a reorg: {e}");
                return ExitCode::from(EXIT_NO_NODE);
            }
            Err(e @ FollowError::Fatal(_)) => {
                eprintln!("{e}");
                return ExitCode::from(EXIT_HALTED);
            }
        }
    }
}

