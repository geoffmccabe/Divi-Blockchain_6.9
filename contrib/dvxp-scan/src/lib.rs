//! # `dvxp-scan` — the shared block scanner for Divi overlay protocols
//!
//! `docs/INDEXER-ARCHITECTURE.md` asked for the scanner to be built once, in
//! one place, rather than per protocol. This is that crate.
//!
//! ## Library first, daemon second
//!
//! The wallet embeds the indexer and scans its own node, so that a self-custody
//! wallet never depends on a server we operate: a user must never hold tokens
//! the chain agrees are theirs and see nothing because our machine is down. That
//! means the scanner has to be callable **in-process**, driven by the wallet's
//! own supervisor, which controls when it runs so it never competes with staking
//! for RPC threads.
//!
//! So the useful part of this crate is [`driver::Overlay`], which is pure: hand
//! it blocks, it applies them. Fetching those blocks over JSON-RPC is the
//! optional `rpc` feature. Depend on the crate with `default-features = false`
//! to get the rules without the I/O.
//!
//! ```text
//! wallet    ->  its own node connection  ->  Overlay::apply_block
//! explorer  ->  rpc::Node (this crate)   ->  Overlay::apply_block
//! ```
//!
//! Same rules, same fingerprint, two very different hosts.
//!
//! ## What it fixes
//!
//! The previous scanner lived in the explorer and had three problems that only
//! show up in production: it ran once and exited, it never handled a reorg, and
//! its fingerprint covered collectibles but not tokens. All three are addressed
//! here, and the reorg one needed a matching change in `nfd-indexer`, which had
//! no undo log at all.

pub mod driver;
pub mod events;
pub mod query;

#[cfg(feature = "rpc")]
pub mod rpc;

#[cfg(feature = "rpc")]
pub mod store;

#[cfg(feature = "rpc")]
pub mod api;

#[cfg(feature = "rpc")]
pub mod daemon;

#[cfg(feature = "rpc")]
pub use daemon::run_daemon;

pub use driver::{BlockInput, BlockSummary, Overlay, ScanError, TxPayload};

/// Blocks Divi produces per day at its 60-second target. Useful for reporting
/// how far behind an index is in time rather than in blocks, which is what a
/// person actually wants to know.
pub const BLOCKS_PER_DAY: u64 = 1_440;
