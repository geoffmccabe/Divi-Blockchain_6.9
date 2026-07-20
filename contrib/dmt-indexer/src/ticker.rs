//! Ticker charset, length, and normalised reserved-name matching (spec §7.2.1, §7.6).
//!
//! This is the impersonation-defence module. The rules here are protocol-level
//! precisely because they are small, fixed, and must give byte-identical answers
//! in every implementation.

/// Inclusive length bounds (spec §7.2.1).
pub const MIN_LEN: usize = 3;
pub const MAX_LEN: usize = 8;

/// Allowed punctuation (spec §7.2.1).
const PUNCT: &[u8] = b"!#^-_+.";

/// Names nobody may register, protecting the chain's own identity (spec §7.6).
pub const RESERVED: &[&str] = &["DIVI", "DIVIX", "DMT", "NFD", "POE"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickerError {
    TooShort,
    TooLong,
    BadCharacter,
    /// Lowercase is never valid -- case-folding is a duplicate-identity bug
    /// source, so `DIVI` and `divi` can never become different tokens.
    Lowercase,
    MustStartWithLetter,
    /// Collides with a reserved name after normalisation.
    Reserved,
}

fn is_upper(b: u8) -> bool {
    b.is_ascii_uppercase()
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn is_punct(b: u8) -> bool {
    PUNCT.contains(&b)
}

/// Charset and length only -- does not consult the reserved list.
pub fn validate_charset(ticker: &[u8]) -> Result<(), TickerError> {
    if ticker.len() < MIN_LEN {
        return Err(TickerError::TooShort);
    }
    if ticker.len() > MAX_LEN {
        return Err(TickerError::TooLong);
    }
    for &b in ticker {
        if b.is_ascii_lowercase() {
            return Err(TickerError::Lowercase);
        }
        if !(is_upper(b) || is_digit(b) || is_punct(b)) {
            return Err(TickerError::BadCharacter);
        }
    }
    if !is_upper(ticker[0]) {
        return Err(TickerError::MustStartWithLetter);
    }
    Ok(())
}

/// Normalise for reserved-name comparison (spec §7.6).
///
/// **Step order is load-bearing.** `!` is both punctuation and a letter
/// lookalike. Folding must happen BEFORE punctuation is stripped, or `D!VI`
/// reduces to `DVI` and fails to collide with `DIVI` -- the exact impersonation
/// this exists to stop. Reversing these two steps leaves a live hole that a
/// naive test suite still passes.
pub fn normalise(ticker: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ticker.len());
    for &b in ticker {
        // 1. fold lookalikes to letters
        let folded = match b {
            b'0' => b'O',
            b'1' | b'!' => b'I',
            b'2' => b'Z',
            b'5' => b'S',
            b'8' => b'B',
            other => other,
        };
        // 2. then drop any punctuation that survived folding
        if is_punct(folded) {
            continue;
        }
        out.push(folded);
    }
    out
}

/// True if `ticker` collides with a reserved name once normalised.
pub fn is_reserved(ticker: &[u8]) -> bool {
    let candidate = normalise(ticker);
    RESERVED
        .iter()
        .any(|r| normalise(r.as_bytes()) == candidate)
}

/// Full check: charset, length, and reserved collision.
pub fn validate(ticker: &[u8]) -> Result<(), TickerError> {
    validate_charset(ticker)?;
    if is_reserved(ticker) {
        return Err(TickerError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_tickers() {
        for t in [&b"GOLD"[..], b"ABC", b"TICKET1", b"A-B_C", b"X.Y+Z", b"ABCDEFGH"] {
            assert!(validate(t).is_ok(), "should accept {}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn enforces_length_bounds() {
        assert_eq!(validate(b"AB"), Err(TickerError::TooShort));
        assert_eq!(validate(b"ABCDEFGHI"), Err(TickerError::TooLong));
        assert!(validate(b"ABC").is_ok());
        assert!(validate(b"ABCDEFGH").is_ok());
    }

    #[test]
    fn rejects_lowercase_and_foreign_characters() {
        assert_eq!(validate(b"divi"), Err(TickerError::Lowercase));
        assert_eq!(validate(b"GoLD"), Err(TickerError::Lowercase));
        assert_eq!(validate(b"AB C"), Err(TickerError::BadCharacter));
        assert_eq!(validate(b"AB*C"), Err(TickerError::BadCharacter));
        // Non-ASCII cannot appear at all -- the Unicode homoglyph class is
        // structurally impossible, not merely discouraged.
        assert_eq!(validate("DIVI\u{0430}".as_bytes()), Err(TickerError::BadCharacter));
    }

    #[test]
    fn must_start_with_a_letter() {
        assert_eq!(validate(b"1ABC"), Err(TickerError::MustStartWithLetter));
        assert_eq!(validate(b"-ABC"), Err(TickerError::MustStartWithLetter));
        assert_eq!(validate(b"!ABC"), Err(TickerError::MustStartWithLetter));
    }

    #[test]
    fn reserved_names_are_blocked_outright() {
        for r in RESERVED {
            assert_eq!(validate(r.as_bytes()), Err(TickerError::Reserved), "{r}");
        }
    }

    /// The whole point of §7.6: punctuation and digit variants must not slip past.
    #[test]
    fn reserved_blocks_impersonation_variants() {
        let attacks: &[&[u8]] = &[
            b"D1VI",   // digit one for I
            b"D!VI",   // bang for I -- only caught if folding precedes stripping
            b"DIVI.",  // trailing dot
            b"D-IVI",  // embedded hyphen
            b"D.I.V.I",
            b"DIV_I",
            b"D!V!",   // both I's replaced
            b"0IVI",   // zero for O... normalises to OIVI, not DIVI
            b"DMT-",
            b"N.F.D",
            b"P0E",    // zero for O
            b"D1V1X",
        ];
        for a in attacks {
            let blocked = is_reserved(a);
            // 0IVI is genuinely a different word (OIVI); assert the rest.
            if *a == b"0IVI" {
                assert!(!blocked, "OIVI is not DIVI");
                continue;
            }
            assert!(blocked, "should be reserved: {}", String::from_utf8_lossy(a));
        }
    }

    /// Regression guard for the step-order bug. If someone "simplifies" the
    /// normaliser by stripping punctuation first, this fails.
    #[test]
    fn bang_folds_before_punctuation_is_stripped() {
        assert_eq!(normalise(b"D!VI"), b"DIVI".to_vec());
        assert_ne!(normalise(b"D!VI"), b"DVI".to_vec());
        assert!(is_reserved(b"D!VI"));
    }

    #[test]
    fn normalisation_does_not_over_reach() {
        // Ordinary names that merely contain a folded character stay distinct.
        assert!(!is_reserved(b"GOLD1"));
        assert!(!is_reserved(b"DIVE"));
        assert!(!is_reserved(b"DIV"));
        assert!(validate(b"D1VE").is_ok());
    }

    #[test]
    fn charset_check_is_independent_of_reservation() {
        // A reserved name is still charset-valid; the two checks are separable
        // so callers can report the precise reason.
        assert!(validate_charset(b"DIVI").is_ok());
        assert_eq!(validate(b"DIVI"), Err(TickerError::Reserved));
    }
}
