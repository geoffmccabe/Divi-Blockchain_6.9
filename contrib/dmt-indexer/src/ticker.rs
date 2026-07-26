//! Ticker charset, length, and normalised reserved-name matching (spec §7.2.1, §7.6).
//!
//! **These rules now live in the shared `name-registry` crate.** A DMT ticker is
//! simply a short Divi Name, so there is exactly one namespace and exactly one
//! copy of the impersonation defence (see `docs/DIVI-NAMES-PLAN.md` §1). This
//! module is a thin adapter that pins the ticker length bound and keeps the
//! previous public API, so nothing downstream of DMT changed.
//!
//! Behaviour is unchanged: 3 to 8 characters, `A-Z` `0-9` `!#^-_+.`, first
//! character a letter, no lowercase, reserved names matched after folding
//! lookalikes and then stripping punctuation (in that order — the step order is
//! load-bearing, see `name_registry::charset::normalise`).

pub use name_registry::charset::{is_reserved, normalise, RESERVED};

use name_registry::charset::{self, NameError};

/// Inclusive length bounds for a TICKER (spec §7.2.1). Human readable addresses
/// use the same rules with a larger bound; see `name_registry::charset`.
pub const MIN_LEN: usize = charset::MIN_LEN;
pub const MAX_LEN: usize = charset::TICKER_MAX_LEN;

/// Retained under its original name so DMT code and tests read unchanged.
pub type TickerError = NameError;

/// Charset and length only -- does not consult the reserved list.
pub fn validate_charset(ticker: &[u8]) -> Result<(), TickerError> {
    charset::validate_charset_max(ticker, MAX_LEN)
}

/// Full check: charset, length, and reserved collision.
pub fn validate(ticker: &[u8]) -> Result<(), TickerError> {
    charset::validate_ticker(ticker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared crate carries the exhaustive rule tests. What matters HERE is
    /// that DMT's own bounds did not move when the rules were hoisted out, so
    /// these are the boundary cases specific to tickers.
    #[test]
    fn ticker_length_bounds_are_unchanged() {
        assert_eq!(MIN_LEN, 3);
        assert_eq!(MAX_LEN, 8);
        assert_eq!(validate(b"AB"), Err(TickerError::TooShort));
        assert!(validate(b"ABC").is_ok());
        assert!(validate(b"ABCDEFGH").is_ok());
        assert_eq!(validate(b"ABCDEFGHI"), Err(TickerError::TooLong));
    }

    /// A name long enough to be a good HRA is still NOT a valid ticker. This is
    /// the one place the two bounds could silently drift together.
    #[test]
    fn long_names_are_still_refused_as_tickers() {
        assert_eq!(validate(b"GEOFFMCCABE"), Err(TickerError::TooLong));
    }

    #[test]
    fn reserved_and_charset_defences_still_apply() {
        assert_eq!(validate(b"DIVI"), Err(TickerError::Reserved));
        assert_eq!(validate(b"D!VI"), Err(TickerError::Reserved));
        assert_eq!(validate(b"divi"), Err(TickerError::Lowercase));
        assert_eq!(validate("DIVI\u{0430}".as_bytes()), Err(TickerError::BadCharacter));
        assert_eq!(validate(b"1ABC"), Err(TickerError::MustStartWithLetter));
        assert!(validate_charset(b"DIVI").is_ok());
    }
}
