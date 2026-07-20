//! Compiled-in protocol constants (spec §7.3.3, §9.3).
//!
//! **Everything here is baked into the binary and never fetched at runtime.**
//! Changing any of it is a spec version bump with a published activation
//! height — announced in advance, identical for everyone, effective at a known
//! block. A value that can change under a user mid-transaction is a consensus
//! parameter in all but name; Counterparty fetches its rules from a URL and its
//! own source comments acknowledge the hijack surface. We do not.
//!
//! This is also why there is no spork here. Divi's spork mechanism is a single
//! hardcoded key with no multisig and no timelock, and hanging protocol
//! economics on it would both deepen an existing weakness and undermine the
//! promise that anyone may build on this layer (spec §11.1).

use dvxp_core::codec::{Address, ADDRESS_P2PKH};

/// Height at which DMT records start counting. Records below it are ignored, so
/// the ledger has one unambiguous origin and every implementation replays the
/// same range (spec §9.6).
///
/// ⚠ PLACEHOLDER — set to the real height when the first indexer is deployed.
pub const GENESIS_HEIGHT: u64 = 0;

/// Divi Love treasury, recipient of both registry fees (spec §7.3.1).
///
/// ⚠ PLACEHOLDER — Geoff must supply the real address before any deployment.
/// A wrong address here silently sends every registry fee somewhere
/// unrecoverable, so [`treasury_is_configured`] gates startup rather than
/// letting a default slip into production.
pub const TREASURY_HASH160: [u8; 20] = [0u8; 20];

pub fn treasury() -> Address {
    Address { kind: ADDRESS_P2PKH, hash160: TREASURY_HASH160 }
}

/// False while the treasury address is still the placeholder. A deployment must
/// refuse to start on `false` — losing fees to an unspendable address is silent
/// and irreversible.
pub fn treasury_is_configured() -> bool {
    TREASURY_HASH160 != [0u8; 20]
}

/// Confirmations a NAME COMMIT must have before its ISSUE may reveal the ticker
/// (spec §7.2). Twelve blocks is ~12 minutes on Divi's 60-second blocks, versus
/// ~2 hours on Bitcoin — this is what makes commit-reveal practical here.
///
/// The delay converts a mempool race, which an attacker wins by paying a higher
/// fee, into a 12-block reorg, which they cannot win. Divi's hard 100-block
/// max-reorg cap makes that absolute.
pub const MIN_COMMIT_DEPTH: u64 = 12;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_treasury_is_detected() {
        // Guards against shipping the default. If someone sets a real address,
        // this flips to true and the deployment check passes.
        assert!(!treasury_is_configured(), "placeholder must not read as configured");
    }

    #[test]
    fn commit_depth_matches_the_spec() {
        assert_eq!(MIN_COMMIT_DEPTH, 12);
    }
}
