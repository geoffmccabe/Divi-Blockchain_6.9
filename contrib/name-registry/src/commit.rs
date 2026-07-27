//! Commit-reveal registration.
//!
//! Names are first-come-first-served, so a plain registration is trivially
//! front-run: an observer sees a valuable name in the mempool and pays a higher
//! fee to grab it first. Namecoin solved this in 2011 and Runes reimplemented
//! the same idea in 2024 (using a Taproot witness, which Divi does not have and
//! does not need — the mechanism is a maturity rule, not a script rule).
//!
//! 1. Broadcast a COMMIT carrying `Hash160(salt ‖ name)` with a 20-byte salt.
//! 2. Wait [`MIN_COMMIT_DEPTH`] confirmations.
//! 3. Broadcast REGISTER revealing the name and salt, **from the same address**.
//!
//! An attacker who learns the name at reveal time cannot use it: claiming it
//! needs *their own* commit already 12 blocks deep, and they learned it seconds
//! ago. **The delay converts a mempool race, winnable by fee-bumping, into a
//! 12-block reorg, which is not winnable.** Divi's 100-block max-reorg cap makes
//! that absolute.
//!
//! On Divi this costs about 12 minutes rather than 2 hours: 60-second blocks
//! make anti-front-running registration genuinely practical here in a way it
//! never was on Bitcoin.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Confirmations a commit must have before its reveal is accepted.
pub const MIN_COMMIT_DEPTH: u64 = 12;

/// How long a commit stays usable.
///
/// ⚠ Without an expiry, commits accumulate forever in every indexer's state.
/// A commit carries NO registration fee, only a transaction fee, so flooding
/// the chain with them is cheap, and each one would sit in every wallet's index
/// permanently. That is a slow disk-filling attack on everyone who runs this.
///
/// About three days on 60-second blocks: far longer than the twelve blocks a
/// legitimate reveal needs, short enough that spam ages out.
pub const COMMIT_EXPIRY_BLOCKS: u64 = 4320;

/// Salt length in bytes.
///
/// 20, not Namecoin's original 8. Theirs was brute-forceable against the
/// published hash, letting an attacker learn the name *during* the waiting
/// window; they treated lengthening it as a security fix. We start where they
/// finished.
pub const SALT_LEN: usize = 20;

/// `Hash160(salt ‖ name)` = RIPEMD160(SHA256(...)), the same construction Divi
/// already uses for addresses.
pub fn commit_hash(salt: &[u8; SALT_LEN], name: &[u8]) -> [u8; 20] {
    let mut pre = Vec::with_capacity(SALT_LEN + name.len());
    pre.extend_from_slice(salt);
    pre.extend_from_slice(name);
    let sha = Sha256::digest(&pre);
    let out = Ripemd160::digest(sha);
    let mut h = [0u8; 20];
    h.copy_from_slice(&out);
    h
}

/// Whether a reveal may be accepted: the hash must match, and the commit must be
/// buried at least [`MIN_COMMIT_DEPTH`] blocks.
///
/// The caller is still responsible for the two checks this function cannot see:
/// the commit must come from the SAME address as the reveal, and a commit may be
/// consumed only once.
pub fn reveal_is_mature(
    commit_height: u64,
    current_height: u64,
    committed: &[u8; 20],
    salt: &[u8; SALT_LEN],
    name: &[u8],
) -> bool {
    if !window_is_open(commit_height, current_height) {
        return false;
    }
    &commit_hash(salt, name) == committed
}

/// Is `current_height` inside the window where a commit may be revealed:
/// at least [`MIN_COMMIT_DEPTH`] deep, and not yet expired.
pub fn window_is_open(commit_height: u64, current_height: u64) -> bool {
    if current_height < commit_height {
        return false;
    }
    let depth = current_height - commit_height;
    depth >= MIN_COMMIT_DEPTH && depth <= COMMIT_EXPIRY_BLOCKS
}

/// A commit this old can never be used again and may be dropped from state.
pub fn is_expired(commit_height: u64, current_height: u64) -> bool {
    current_height.saturating_sub(commit_height) > COMMIT_EXPIRY_BLOCKS
}

/// Confirmations still needed before a commit can be revealed.
pub fn blocks_remaining(commit_height: u64, current_height: u64) -> u64 {
    let depth = current_height.saturating_sub(commit_height);
    MIN_COMMIT_DEPTH.saturating_sub(depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [0xAB; SALT_LEN];

    #[test]
    fn hash_is_deterministic_and_name_sensitive() {
        assert_eq!(commit_hash(&SALT, b"GEOFF"), commit_hash(&SALT, b"GEOFF"));
        assert_ne!(commit_hash(&SALT, b"GEOFF"), commit_hash(&SALT, b"GEOFE"));
        assert_ne!(commit_hash(&SALT, b"GEOFF"), commit_hash(&[0x01; SALT_LEN], b"GEOFF"));
    }

    /// The salt must actually be mixed in, not appended in a way that lets a
    /// different (salt, name) split produce the same hash. Length-prefix-free
    /// concatenation is safe here only because the salt is FIXED length.
    #[test]
    fn fixed_length_salt_prevents_ambiguous_splits() {
        let a = commit_hash(&SALT, b"ABCDEF");
        let mut shifted = SALT;
        shifted[SALT_LEN - 1] = b'A';
        let b = commit_hash(&shifted, b"BCDEF");
        assert_ne!(a, b);
    }

    #[test]
    fn reveal_needs_the_full_maturity_window() {
        let h = 1000;
        for depth in 0..MIN_COMMIT_DEPTH {
            assert!(!reveal_is_mature(h, h + depth, &commit_hash(&SALT, b"GEOFF"), &SALT, b"GEOFF"));
        }
        assert!(reveal_is_mature(
            h,
            h + MIN_COMMIT_DEPTH,
            &commit_hash(&SALT, b"GEOFF"),
            &SALT,
            b"GEOFF"
        ));
    }

    #[test]
    fn reveal_rejects_a_mismatched_name_or_salt() {
        let h = 1000;
        let committed = commit_hash(&SALT, b"GEOFF");
        assert!(!reveal_is_mature(h, h + 50, &committed, &SALT, b"SOMEONEELSE"));
        assert!(!reveal_is_mature(h, h + 50, &committed, &[0x00; SALT_LEN], b"GEOFF"));
    }

    /// A commit that appears to be from the future is nonsense, not "mature".
    #[test]
    fn a_commit_ahead_of_the_tip_is_never_mature() {
        let committed = commit_hash(&SALT, b"GEOFF");
        assert!(!reveal_is_mature(2000, 1000, &committed, &SALT, b"GEOFF"));
    }

    /// A commit that nobody revealed must stop being usable, so indexers can
    /// drop it instead of carrying cheap spam forever.
    #[test]
    fn a_commit_expires() {
        let h = 1000;
        let committed = commit_hash(&SALT, b"GEOFF");
        assert!(reveal_is_mature(h, h + COMMIT_EXPIRY_BLOCKS, &committed, &SALT, b"GEOFF"));
        assert!(!reveal_is_mature(h, h + COMMIT_EXPIRY_BLOCKS + 1, &committed, &SALT, b"GEOFF"));
        assert!(!is_expired(h, h + COMMIT_EXPIRY_BLOCKS));
        assert!(is_expired(h, h + COMMIT_EXPIRY_BLOCKS + 1));
    }

    #[test]
    fn the_window_has_both_edges() {
        let h = 500;
        assert!(!window_is_open(h, h + MIN_COMMIT_DEPTH - 1));
        assert!(window_is_open(h, h + MIN_COMMIT_DEPTH));
        assert!(window_is_open(h, h + COMMIT_EXPIRY_BLOCKS));
        assert!(!window_is_open(h, h + COMMIT_EXPIRY_BLOCKS + 1));
        assert!(!window_is_open(h, h - 1));
    }

    #[test]
    fn countdown_reaches_zero_and_stays_there() {
        assert_eq!(blocks_remaining(100, 100), MIN_COMMIT_DEPTH);
        assert_eq!(blocks_remaining(100, 105), MIN_COMMIT_DEPTH - 5);
        assert_eq!(blocks_remaining(100, 112), 0);
        assert_eq!(blocks_remaining(100, 999), 0);
    }
}
