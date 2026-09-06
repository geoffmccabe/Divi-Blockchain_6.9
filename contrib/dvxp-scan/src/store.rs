//! Publishing where the index has got to.
//!
//! Readers must never present balances as live when they are not, so the
//! snapshot always carries enough to answer "as of which block, and can this be
//! trusted", not just the data itself.
//!
//! Deliberately a plain file written through a temporary and renamed into place.
//! A reader either sees the previous snapshot or the new one, never half of
//! either, and the node keeps no database dependency it would have to build.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dvxp_core::registry::Fingerprint;
use serde_json::{json, Value};

use crate::driver::Overlay;

/// Where the index has got to, and whether it can be believed.
///
/// This mirrors the `sync_state()` query the wallet interface calls **required**:
/// behind the tip means stale, halted means refuse to act.
#[derive(Debug, Clone)]
pub struct SyncState {
    pub height: u64,
    pub tip: u64,
    pub fingerprint: String,
    pub halted: bool,
    pub halt_reason: Option<String>,
}

impl SyncState {
    pub fn behind(&self) -> u64 {
        self.tip.saturating_sub(self.height)
    }

    /// Whether a wallet should be willing to spend from this state. Two blocks
    /// of slack absorbs the ordinary case of a block arriving mid-scan; beyond
    /// that a balance shown could already have been spent.
    pub fn trustworthy(&self) -> bool {
        !self.halted && self.behind() <= 2
    }
}

pub struct Snapshot {
    path: PathBuf,
}

impl Snapshot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the current state of the index.
    ///
    /// Fingerprint is published as hex on purpose: it only works as a
    /// cross-check between independent implementations if a human can actually
    /// read it off two machines and compare.
    pub fn write(&self, overlay: &Overlay, tip: u64) -> io::Result<()> {
        let sync = sync_state(overlay, tip);
        let doc = json!({
            "height": sync.height,
            "tip": sync.tip,
            "behind": sync.behind(),
            "fingerprint": sync.fingerprint,
            "halted": sync.halted,
            "haltReason": sync.halt_reason,
            "trustworthy": sync.trustworthy(),
            "oldestRevertibleHeight": overlay.oldest_undo_height(),
            "builtAt": now(),
            "nfd": {
                "collectibles": overlay.nfd.count(),
                "collections": overlay.nfd.collection_count(),
            },
            "dmt": {
                "tokens": overlay.dmt.ledger.state.tokens.len(),
                "tickers": overlay.dmt.ledger.state.tickers.len(),
                "balances": overlay.dmt.ledger.state.balances.len(),
            },
        });
        self.write_value(&doc)
    }

    fn write_value(&self, doc: &Value) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(doc)?)?;
        fs::rename(&tmp, &self.path)
    }
}

pub fn sync_state(overlay: &Overlay, tip: u64) -> SyncState {
    SyncState {
        height: overlay.tip().unwrap_or(0),
        tip,
        fingerprint: overlay.fingerprint().hex(),
        halted: overlay.is_halted(),
        halt_reason: overlay.halt_reason().map(|h| format!("{h:?}")),
    }
}

pub fn genesis_fingerprint_hex() -> String {
    Fingerprint::genesis().hex()
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behind_and_trust_track_the_tip() {
        let mut s = SyncState {
            height: 100,
            tip: 100,
            fingerprint: String::new(),
            halted: false,
            halt_reason: None,
        };
        assert_eq!(s.behind(), 0);
        assert!(s.trustworthy());

        s.tip = 102;
        assert!(s.trustworthy(), "two blocks of slack is tolerated");

        s.tip = 103;
        assert!(!s.trustworthy(), "beyond that a balance could already be spent");
    }

    #[test]
    fn a_halted_index_is_never_trustworthy_however_current_it_looks() {
        let s = SyncState {
            height: 100,
            tip: 100,
            fingerprint: String::new(),
            halted: true,
            halt_reason: Some("unsupported version".into()),

        };
        assert_eq!(s.behind(), 0);
        assert!(!s.trustworthy());
    }

    #[test]
    fn a_snapshot_round_trips_through_the_filesystem() {
        let dir = std::env::temp_dir().join("dvxp-scan-test");
        let path = dir.join("overlay.json");
        let snap = Snapshot::new(&path);
        let overlay = Overlay::new();
        snap.write(&overlay, 42).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["tip"], 42);
        assert_eq!(v["height"], 0);
        assert_eq!(v["halted"], false);
        assert_eq!(v["fingerprint"], genesis_fingerprint_hex());
        let _ = fs::remove_file(&path);
    }
}
