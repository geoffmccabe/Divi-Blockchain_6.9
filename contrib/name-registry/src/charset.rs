//! Name charset, length, and normalised reserved-name matching.
//!
//! This is the impersonation-defence module and it is shared by EVERY consumer
//! of a Divi name: human readable addresses, DMT token tickers, the wallet, the
//! explorer, and any third-party indexer. The rules are protocol-level precisely
//! because they are small, fixed, and must give byte-identical answers in every
//! implementation.
//!
//! Moved here from `dmt-indexer/src/ticker.rs` when the two namespaces were
//! unified (see `docs/DIVI-NAMES-PLAN.md` §1). `ticker.rs` is now a thin
//! re-export so DMT keeps its exact previous behaviour.
//!
//! ## Why uppercase-only ASCII, forever
//!
//! Because the set is ASCII-only, the entire **Unicode homoglyph attack class is
//! structurally impossible** — no Cyrillic `о` rendering as `o`, no zero-width
//! joiners, no right-to-left overrides. ENS has this problem and cannot fix it.
//! We do not have it, for free, and it must not be given up later for prettier
//! names. Wallets render lowercase for looks; the record stores uppercase, so
//! `geoff`, `Geoff` and `GEOFF` can never be three different people.

/// Inclusive minimum length. The 2-and-under range is excluded rather than
/// priced: 26 single letters and ~1,300 two-character combinations is a tiny
/// namespace with no legitimate advantage over a 3-character name, so allowing
/// them creates a pure land-grab. Excluding them avoids the fight.
pub const MIN_LEN: usize = 3;

/// Longest DMT token ticker. A token's full name belongs in its metadata, not
/// its ticker.
pub const TICKER_MAX_LEN: usize = 8;

/// Longest human readable address. Personal and organisation names want room;
/// 32 is generous while still fitting comfortably in the ~599-byte payload.
pub const NAME_MAX_LEN: usize = 32;

/// Allowed punctuation.
const PUNCT: &[u8] = b"!#^-_+.";

/// Names nobody may register, protecting the chain's own identity.
pub const RESERVED: &[&str] = &["DIVI", "DIVIX", "DMT", "NFD", "POE"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    TooShort,
    TooLong,
    BadCharacter,
    /// Lowercase is never valid -- case-folding is a duplicate-identity bug
    /// source, so `DIVI` and `divi` can never become different names.
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
///
/// `max_len` is a parameter rather than a constant because the two namespaces
/// share every rule EXCEPT their upper bound: a ticker is simply a short name.
pub fn validate_charset_max(name: &[u8], max_len: usize) -> Result<(), NameError> {
    if name.len() < MIN_LEN {
        return Err(NameError::TooShort);
    }
    if name.len() > max_len {
        return Err(NameError::TooLong);
    }
    for &b in name {
        if b.is_ascii_lowercase() {
            return Err(NameError::Lowercase);
        }
        if !(is_upper(b) || is_digit(b) || is_punct(b)) {
            return Err(NameError::BadCharacter);
        }
    }
    if !is_upper(name[0]) {
        return Err(NameError::MustStartWithLetter);
    }
    Ok(())
}

/// Normalise for reserved-name comparison.
///
/// **Step order is load-bearing.** `!` is both punctuation and a letter
/// lookalike. Folding must happen BEFORE punctuation is stripped, or `D!VI`
/// reduces to `DVI` and fails to collide with `DIVI` -- the exact impersonation
/// this exists to stop. Reversing these two steps leaves a live hole that a
/// naive test suite still passes.
pub fn normalise(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    for &b in name {
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

/// True if `name` collides with a reserved name once normalised.
pub fn is_reserved(name: &[u8]) -> bool {
    let candidate = normalise(name);
    RESERVED.iter().any(|r| normalise(r.as_bytes()) == candidate)
}

/// Full check against an explicit upper bound: charset, length, reserved.
pub fn validate_max(name: &[u8], max_len: usize) -> Result<(), NameError> {
    validate_charset_max(name, max_len)?;
    if is_reserved(name) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

/// Full check for a human readable address (up to [`NAME_MAX_LEN`]).
pub fn validate_name(name: &[u8]) -> Result<(), NameError> {
    validate_max(name, NAME_MAX_LEN)
}

/// Full check for a DMT token ticker (up to [`TICKER_MAX_LEN`]).
pub fn validate_ticker(name: &[u8]) -> Result<(), NameError> {
    validate_max(name, TICKER_MAX_LEN)
}

/// A name typed by a user, folded to the canonical on-chain form.
///
/// Only case is changed. Anything else stays as typed so that validation
/// reports the real problem instead of silently "fixing" a name into a
/// different one, which is how a user ends up owning something they did not
/// mean to buy.
pub fn canonicalise(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for t in [&b"GOLD"[..], b"ABC", b"TICKET1", b"A-B_C", b"X.Y+Z", b"ABCDEFGH"] {
            assert!(validate_ticker(t).is_ok(), "should accept {}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn enforces_length_bounds() {
        assert_eq!(validate_ticker(b"AB"), Err(NameError::TooShort));
        assert_eq!(validate_ticker(b"ABCDEFGHI"), Err(NameError::TooLong));
        assert!(validate_ticker(b"ABC").is_ok());
        assert!(validate_ticker(b"ABCDEFGH").is_ok());
    }

    /// The unification: a 9-character string is too long for a ticker but a
    /// perfectly ordinary human readable address.
    #[test]
    fn names_may_be_longer_than_tickers() {
        assert_eq!(validate_ticker(b"GEOFFMCCABE"), Err(NameError::TooLong));
        assert!(validate_name(b"GEOFFMCCABE").is_ok());
        assert!(validate_name(&[b'A'; NAME_MAX_LEN]).is_ok());
        assert_eq!(validate_name(&[b'A'; NAME_MAX_LEN + 1]), Err(NameError::TooLong));
    }

    #[test]
    fn rejects_lowercase_and_foreign_characters() {
        assert_eq!(validate_ticker(b"divi"), Err(NameError::Lowercase));
        assert_eq!(validate_ticker(b"GoLD"), Err(NameError::Lowercase));
        assert_eq!(validate_ticker(b"AB C"), Err(NameError::BadCharacter));
        assert_eq!(validate_ticker(b"AB*C"), Err(NameError::BadCharacter));
        // Non-ASCII cannot appear at all -- the Unicode homoglyph class is
        // structurally impossible, not merely discouraged.
        assert_eq!(validate_ticker("DIVI\u{0430}".as_bytes()), Err(NameError::BadCharacter));
    }

    #[test]
    fn must_start_with_a_letter() {
        assert_eq!(validate_ticker(b"1ABC"), Err(NameError::MustStartWithLetter));
        assert_eq!(validate_ticker(b"-ABC"), Err(NameError::MustStartWithLetter));
        assert_eq!(validate_ticker(b"!ABC"), Err(NameError::MustStartWithLetter));
    }

    #[test]
    fn reserved_names_are_blocked_outright() {
        for r in RESERVED {
            assert_eq!(validate_ticker(r.as_bytes()), Err(NameError::Reserved), "{r}");
        }
    }

    /// Punctuation and digit variants must not slip past.
    #[test]
    fn reserved_blocks_impersonation_variants() {
        let attacks: &[&[u8]] = &[
            b"D1VI", b"D!VI", b"DIVI.", b"D-IVI", b"D.I.V.I", b"DIV_I", b"D!V!", b"DMT-",
            b"N.F.D", b"P0E", b"D1V1X",
        ];
        for a in attacks {
            assert!(is_reserved(a), "should be reserved: {}", String::from_utf8_lossy(a));
        }
        // 0IVI is genuinely a different word (OIVI).
        assert!(!is_reserved(b"0IVI"));
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
        assert!(!is_reserved(b"GOLD1"));
        assert!(!is_reserved(b"DIVE"));
        assert!(!is_reserved(b"DIV"));
        assert!(validate_ticker(b"D1VE").is_ok());
    }

    #[test]
    fn charset_check_is_independent_of_reservation() {
        assert!(validate_charset_max(b"DIVI", TICKER_MAX_LEN).is_ok());
        assert_eq!(validate_ticker(b"DIVI"), Err(NameError::Reserved));
    }

    #[test]
    fn canonicalise_only_changes_case() {
        assert_eq!(canonicalise("  geoff "), "GEOFF");
        assert_eq!(canonicalise("Geoff"), "GEOFF");
        // A bad character survives so validation can report it honestly.
        assert_eq!(canonicalise("ge off"), "GE OFF");
    }
}
