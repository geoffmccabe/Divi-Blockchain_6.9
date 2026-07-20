//! Protocol fees (spec §7.3.1, §7.3.2, §7.3.3).
//!
//! Every value here is a COMPILED-IN CONSTANT. Nothing is fetched at runtime and
//! nothing is settable by a key. Changing a fee is a spec version bump with a
//! published activation height -- announced and identical for everyone, never
//! instant and silent. See §7.3.3 for why a spork was rejected.
//!
//! Note the scaling is by ticker LENGTH, not by DIVI's market price: length is
//! present in the record, so no oracle or external input is ever required.

use crate::ticker;

/// Duffs per DIVI.
pub const COIN: u64 = 100_000_000;

/// Creating a token (spec §7.3.1).
pub const TOKEN_CREATION_DIVI: u64 = 10_000;

/// Ticker registration by length (spec §7.3.2).
const TICKER_FEE_DIVI: &[(usize, u64)] = &[(3, 50_000), (4, 20_000), (5, 10_000)];
/// Applies to lengths 6..=MAX_LEN.
const TICKER_FEE_DIVI_LONG: u64 = 5_000;

pub fn token_creation_fee_duffs() -> u64 {
    TOKEN_CREATION_DIVI * COIN
}

/// Registration fee for a ticker of the given length.
///
/// Returns `None` for lengths outside the legal range, so a caller can never
/// silently price an invalid ticker.
pub fn ticker_fee_duffs(len: usize) -> Option<u64> {
    if !(ticker::MIN_LEN..=ticker::MAX_LEN).contains(&len) {
        return None;
    }
    let divi = TICKER_FEE_DIVI
        .iter()
        .find(|(l, _)| *l == len)
        .map(|(_, fee)| *fee)
        .unwrap_or(TICKER_FEE_DIVI_LONG);
    Some(divi * COIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_specified_schedule() {
        assert_eq!(ticker_fee_duffs(3), Some(50_000 * COIN));
        assert_eq!(ticker_fee_duffs(4), Some(20_000 * COIN));
        assert_eq!(ticker_fee_duffs(5), Some(10_000 * COIN));
        for len in 6..=8 {
            assert_eq!(ticker_fee_duffs(len), Some(5_000 * COIN), "len {len}");
        }
        assert_eq!(token_creation_fee_duffs(), 10_000 * COIN);
    }

    #[test]
    fn illegal_lengths_have_no_price() {
        for len in [0usize, 1, 2, 9, 12, 100] {
            assert_eq!(ticker_fee_duffs(len), None, "len {len}");
        }
    }

    /// Shorter must never be cheaper -- that inversion is the squatting hole.
    #[test]
    fn price_is_monotonically_non_increasing_with_length() {
        let fees: Vec<u64> = (ticker::MIN_LEN..=ticker::MAX_LEN)
            .map(|l| ticker_fee_duffs(l).unwrap())
            .collect();
        for pair in fees.windows(2) {
            assert!(pair[0] >= pair[1], "fees must not rise with length: {pair:?}");
        }
        assert!(fees[0] > *fees.last().unwrap(), "short tickers must cost more");
    }

    #[test]
    fn no_fee_overflows_u64() {
        for len in ticker::MIN_LEN..=ticker::MAX_LEN {
            assert!(ticker_fee_duffs(len).unwrap() < u64::MAX / 2);
        }
    }
}
