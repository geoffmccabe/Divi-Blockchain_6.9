//! **Divi Names** — the shared name registry for the Divi chain.
//!
//! One namespace serves two things that used to be separate:
//!
//! * **Human readable addresses (HRAs).** `GEOFF` instead of a base58 hash, plus
//!   an ENS-style record set (EVM address, ENS name, Telegram, avatar, and so
//!   on) hanging off the same name.
//! * **DMT token tickers.** A ticker is simply a short name, capped at
//!   [`charset::TICKER_MAX_LEN`] instead of [`charset::NAME_MAX_LEN`].
//!
//! Keeping them in ONE namespace is deliberate. Two namespaces would let `GEOFF`
//! the person and `GEOFF` the token be different objects owned by different
//! people, and that ambiguity is a phishing surface we would be creating on
//! purpose. See `docs/DIVI-NAMES-PLAN.md` §1.
//!
//! ## Layout
//!
//! * [`charset`] — length, character set, and the normalised reserved-name
//!   defence. Moved here from `dmt-indexer`, which now re-exports it.
//! * [`fees`] — length-tiered registration and renewal pricing, term and grace
//!   periods, and the declining-price release auction.
//! * [`commit`] — commit-reveal, the anti-front-running rule.
//! * [`record`] — the DVXP type `0x05` codec.
//!
//! ## What this crate deliberately does NOT do
//!
//! It holds no ledger state and makes no ownership decisions. Those belong to an
//! indexer, which applies these rules to blocks in order. This crate is the part
//! that MUST be byte-identical everywhere, so it is kept small enough to audit
//! in one sitting and free of I/O, clocks, and configuration.
//!
//! ## Trust model
//!
//! An overlay. The chain carries and orders records; software interprets them.
//! Accurate: *"permanently recorded and ordered by the Divi chain."* Never:
//! *"the network enforces this."*

pub mod charset;
pub mod commit;
pub mod fees;
pub mod record;

pub use charset::{NameError, NAME_MAX_LEN, TICKER_MAX_LEN};
pub use record::{NameRecord, TYPE_NAME};

/// Everything a wallet needs to show a user before they commit money to a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameQuote {
    /// The canonical (uppercase) form that will actually be registered.
    pub canonical: String,
    pub registration_divi: u64,
    pub renewal_divi: u64,
    /// True when the name is short enough to also serve as a DMT token ticker.
    pub can_be_ticker: bool,
}

/// Validate a user-typed name and price it, or say precisely why not.
///
/// This is the single entry point a wallet should use, so that the canonical
/// form shown to the user is the same string that gets committed. Splitting
/// "validate" from "canonicalise" at the call site is how a user ends up
/// registering something subtly different from what they typed.
pub fn quote(input: &str) -> Result<NameQuote, NameError> {
    let canonical = charset::canonicalise(input);
    charset::validate_name(canonical.as_bytes())?;
    let len = canonical.len();
    Ok(NameQuote {
        registration_divi: fees::registration_divi(len).ok_or(NameError::TooLong)?,
        renewal_divi: fees::renewal_divi(len).ok_or(NameError::TooLong)?,
        can_be_ticker: len <= charset::TICKER_MAX_LEN,
        canonical,
    })
}

/// A plain-English reason a name was refused. Wallets should show this verbatim
/// rather than inventing their own wording, so every Divi app says the same
/// thing about the same name.
pub fn explain(err: NameError) -> &'static str {
    match err {
        NameError::TooShort => "Names must be at least 3 characters. One and two character names are not registrable at all.",
        NameError::TooLong => "Names can be at most 32 characters.",
        NameError::BadCharacter => "Names can use A-Z, 0-9 and ! # ^ - _ + . only. Spaces and accented or non-English letters are not allowed, which is what makes lookalike names impossible.",
        NameError::Lowercase => "Names are stored in capitals, so this should have been converted already. This is a bug in the app, not something you did.",
        NameError::MustStartWithLetter => "A name has to start with a letter.",
        NameError::Reserved => "That name is reserved to protect Divi's own identity, including lookalikes of it.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_a_typed_name_in_its_canonical_form() {
        let q = quote(" geoff ").unwrap();
        assert_eq!(q.canonical, "GEOFF");
        assert_eq!(q.registration_divi, 10_000); // 5 characters
        assert_eq!(q.renewal_divi, 10_000);
        assert!(q.can_be_ticker);
    }

    #[test]
    fn long_names_are_cheap_and_cannot_be_tickers() {
        let q = quote("geoffreymccabe").unwrap();
        assert_eq!(q.canonical, "GEOFFREYMCCABE");
        assert_eq!(q.registration_divi, 2_000);
        assert!(!q.can_be_ticker);
    }

    #[test]
    fn refusals_are_specific_and_explained() {
        assert_eq!(quote("ab"), Err(NameError::TooShort));
        assert_eq!(quote("divi"), Err(NameError::Reserved));
        assert_eq!(quote("d!vi"), Err(NameError::Reserved));
        assert_eq!(quote("ge off"), Err(NameError::BadCharacter));
        assert_eq!(quote("1geoff"), Err(NameError::MustStartWithLetter));
        for e in [
            NameError::TooShort,
            NameError::TooLong,
            NameError::BadCharacter,
            NameError::Lowercase,
            NameError::MustStartWithLetter,
            NameError::Reserved,
        ] {
            assert!(!explain(e).is_empty());
        }
    }

    /// Case is not identity: whatever the user types, one name results.
    #[test]
    fn case_variants_all_quote_to_the_same_name() {
        for typed in ["geoff", "GEOFF", "Geoff", "gEoFf"] {
            assert_eq!(quote(typed).unwrap().canonical, "GEOFF");
        }
    }
}
