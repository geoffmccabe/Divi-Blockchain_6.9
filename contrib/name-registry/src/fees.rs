//! Length-tiered registration and renewal pricing.
//!
//! **Scaling here means scaling by name LENGTH, not by DIVI's market price.**
//! The length is present in the record itself, so the fee is a pure lookup table
//! computed identically by every implementation from chain data alone. No
//! oracle, no price feed, no external input, no trusted party.
//!
//! Flat pricing is what produced Namecoin's outcome: of roughly 120,000 names
//! registered, a Princeton study found 28 in genuine use. A squatter does not
//! buy the average name, they buy the ~200 valuable short ones, so a flat fee
//! hands them the entire premium namespace at commodity cost.
//!
//! ## These are governance constants, never a spork
//!
//! The table is compiled into the software. Changing it is a spec version bump
//! with a published activation height: announced in advance, identical for
//! everyone, effective at a known block. A live/remote-settable fee is rejected
//! outright — Divi's spork mechanism is a single hardcoded key with no multisig
//! and no timelock, and a fee that can change under a user mid-transaction is a
//! consensus parameter in everything but name.

/// Registration price in whole DIVI, by name length.
///
/// Returns `None` for a length outside the registrable range, which is a
/// programming error at the call site: validate the charset first.
pub fn registration_divi(len: usize) -> Option<u64> {
    Some(match len {
        3 => 50_000,
        4 => 20_000,
        5 => 10_000,
        6..=8 => 5_000,
        9..=16 => 2_000,
        17..=32 => 1_000,
        _ => return None,
    })
}

/// Yearly renewal price in whole DIVI.
///
/// Deliberately equal to the registration price. **Recurring cost is what
/// actually deters squatting**; a one-time fee merely sets the squatter's entry
/// price and they price it into resale. This is the Namecoin community's own
/// conclusion ("the solution to squatting is to raise renewal fees"), applied
/// from day one instead of after the namespace is already gone.
pub fn renewal_divi(len: usize) -> Option<u64> {
    registration_divi(len)
}

/// Blocks in a registration term. Divi targets 60-second blocks, so this is
/// about one year.
pub const TERM_BLOCKS: u64 = 525_600;

/// Grace period after expiry during which ONLY the previous owner may renew.
/// About 90 days.
pub const GRACE_BLOCKS: u64 = 129_600;

/// After the grace period the name is released by a declining-price auction
/// rather than a first-come land grab at a single block, which would be won by
/// whoever automates fastest. About 21 days.
pub const RELEASE_DECAY_BLOCKS: u64 = 30_240;

/// The premium a name starts at when released, on top of the normal
/// registration price, decaying linearly to zero over [`RELEASE_DECAY_BLOCKS`].
pub const RELEASE_START_PREMIUM_DIVI: u64 = 100_000;

/// Price in whole DIVI to claim a name `blocks_since_release` into its
/// declining-price release. Integer arithmetic only: every implementation must
/// reach the same number, and floating point does not guarantee that.
pub fn release_price_divi(len: usize, blocks_since_release: u64) -> Option<u64> {
    let base = registration_divi(len)?;
    if blocks_since_release >= RELEASE_DECAY_BLOCKS {
        return Some(base);
    }
    let remaining = RELEASE_DECAY_BLOCKS - blocks_since_release;
    let premium = RELEASE_START_PREMIUM_DIVI
        .saturating_mul(remaining)
        / RELEASE_DECAY_BLOCKS;
    Some(base.saturating_add(premium))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_cost_far_more() {
        assert_eq!(registration_divi(3), Some(50_000));
        assert_eq!(registration_divi(4), Some(20_000));
        assert_eq!(registration_divi(5), Some(10_000));
        assert_eq!(registration_divi(8), Some(5_000));
        assert_eq!(registration_divi(9), Some(2_000));
        assert_eq!(registration_divi(32), Some(1_000));
    }

    #[test]
    fn price_never_increases_with_length() {
        let mut prev = u64::MAX;
        for len in 3..=32 {
            let p = registration_divi(len).unwrap();
            assert!(p <= prev, "length {len} costs more than a shorter name");
            prev = p;
        }
    }

    #[test]
    fn out_of_range_lengths_have_no_price() {
        assert_eq!(registration_divi(2), None);
        assert_eq!(registration_divi(33), None);
        assert_eq!(registration_divi(0), None);
    }

    #[test]
    fn release_premium_decays_to_the_base_price() {
        let len = 5;
        let base = registration_divi(len).unwrap();
        let start = release_price_divi(len, 0).unwrap();
        assert_eq!(start, base + RELEASE_START_PREMIUM_DIVI);
        let mid = release_price_divi(len, RELEASE_DECAY_BLOCKS / 2).unwrap();
        assert!(mid > base && mid < start);
        assert_eq!(release_price_divi(len, RELEASE_DECAY_BLOCKS).unwrap(), base);
        // Past the window it stays at the base price, never below.
        assert_eq!(release_price_divi(len, u64::MAX).unwrap(), base);
    }

    #[test]
    fn release_price_is_monotonically_decreasing() {
        let mut prev = u64::MAX;
        for step in (0..RELEASE_DECAY_BLOCKS).step_by(1_000) {
            let p = release_price_divi(6, step).unwrap();
            assert!(p <= prev);
            prev = p;
        }
    }
}
