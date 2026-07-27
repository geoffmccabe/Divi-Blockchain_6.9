//! Names nobody may register: Divi's own identity, and distinctive brand marks.
//!
//! ## Why this is a protocol rule and not a wallet setting
//!
//! If one implementation blocked a name and another allowed it, the name simply
//! gets registered by the permissive one and every indexer then has to honour
//! it. A blocklist only means anything if every implementation applies exactly
//! the same one, which is why it lives here beside the charset rules.
//!
//! ## The test used to pick these, and its limits
//!
//! Included only where **the word is distinctive rather than descriptive**: a
//! coined or arbitrary mark whose ordinary-language meaning is not what somebody
//! would plausibly be naming themselves after.
//!
//! **Ordinary words are deliberately NOT here**, even when a famous company uses
//! one. `APPLE` is a fruit, `ORACLE` is a prophet, `AMAZON` is a river, `META`
//! means "about itself", `VISA` is a travel document, `TELEGRAM` is a message,
//! `SIGNAL`, `DISCORD`, `STRIPE`, `LEDGER`, `KRAKEN`, `GEMINI`, `PHANTOM`,
//! `POLYGON`, `AVALANCHE`, `RIPPLE`, `OPTIMISM`, `CELSIUS` and `ADOBE` are all
//! ordinary words. Blocking those would stop legitimate people registering
//! everyday language, which is a much bigger harm than the impersonation risk.
//!
//! Generic and community terms are also absent: `BITCOIN`, `BLOCKCHAIN`,
//! `CRYPTO`, `DEFI`, `NFT`, `WALLET`, `TOKEN`. Bitcoin in particular has no
//! trademark owner; it is a protocol name, not a brand.
//!
//! ⚠ **This is a product judgement, not a legal determination.** It is a
//! best-effort list of marks that are distinctive enough that registering them
//! reads as impersonation. It is not exhaustive, it will age, and it does not
//! substitute for advice from somebody qualified before launch. Two consequences
//! follow and both are accepted knowingly:
//!
//! 1. Somebody legitimately called e.g. Tesla cannot register that name here.
//! 2. Plenty of marks are missing, so absence from this list is not permission.
//!
//! ## Changing it
//!
//! The list is compiled in. Adding to it is a spec version bump with a published
//! activation height, exactly like the fee table: announced in advance and
//! identical for everyone. **Removing an entry frees a name for anyone**, so
//! removals need more care than additions.
//!
//! Matching is done on the [`crate::charset::normalise`]d form, so `B1NANCE`,
//! `B!NANCE` and `B-I-N-A-N-C-E` all collide with `BINANCE`.

/// Divi's own identity. Protecting these protects the chain itself.
pub const RESERVED_CHAIN: &[&str] = &["DIVI", "DIVIX", "DMT", "NFD", "POE"];

/// Distinctive crypto marks. Coined words, not ordinary language.
pub const RESERVED_CRYPTO: &[&str] = &[
    "ETHEREUM",
    "COINBASE",
    "BINANCE",
    "TETHER",
    "SOLANA",
    "CARDANO",
    "CHAINLINK",
    "UNISWAP",
    "METAMASK",
    "OPENSEA",
    "TREZOR",
    "BITFINEX",
    "BITSTAMP",
    "KUCOIN",
    "BYBIT",
    "OKX",
    "GATEIO",
    "CONSENSYS",
    "INFURA",
    "ETHERSCAN",
    "CHAINALYSIS",
    "BLOCKFI",
    "BITPAY",
    "BITMEX",
    "POLONIEX",
    "MICROSTRATEGY",
    "GRAYSCALE",
    "PAXOS",
    "BAKKT",
    "ARBITRUM",
    "MONERO",
    "ALGORAND",
    "TEZOS",
    "COSMOS",
    "COINGECKO",
    "COINMARKETCAP",
];

/// Distinctive technology marks.
pub const RESERVED_TECH: &[&str] = &[
    "MICROSOFT",
    "GOOGLE",
    "FACEBOOK",
    "INSTAGRAM",
    "WHATSAPP",
    "YOUTUBE",
    "TIKTOK",
    "NETFLIX",
    "SPOTIFY",
    "PAYPAL",
    "MASTERCARD",
    "NVIDIA",
    "SAMSUNG",
    "TESLA",
    "LINKEDIN",
    "REDDIT",
    "DROPBOX",
    "SALESFORCE",
    "QUALCOMM",
    "VODAFONE",
    "SHOPIFY",
    "CLOUDFLARE",
    "ANTHROPIC",
    "OPENAI",
    "CHATGPT",
    "DEEPMIND",
    "HUAWEI",
    "XIAOMI",
    "PANASONIC",
    "SIEMENS",
    "IKEA",
    "NESTLE",
    "PEPSICO",
    "STARBUCKS",
    "MCDONALDS",
    "DISNEY",
    "NINTENDO",
    "PLAYSTATION",
];

/// Everything unregistrable, in one place.
pub fn all() -> impl Iterator<Item = &'static str> {
    RESERVED_CHAIN
        .iter()
        .chain(RESERVED_CRYPTO.iter())
        .chain(RESERVED_TECH.iter())
        .copied()
        .chain(crate::people::all())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charset::{is_reserved, normalise, validate_name, NAME_MAX_LEN};

    /// Every reserved entry must itself be a name the charset would otherwise
    /// accept. An entry that could never be typed protects nothing and hides a
    /// typo in the list.
    #[test]
    fn every_entry_is_a_registrable_shape() {
        for r in all() {
            assert!(r.len() >= 3, "{r} is too short to be a name");
            assert!(r.len() <= NAME_MAX_LEN, "{r} is longer than a name can be");
            assert!(
                r.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
                "{r} must be plain uppercase ASCII"
            );
        }
    }

    #[test]
    fn no_duplicates() {
        let mut seen: Vec<&str> = all().collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "the reserved list has duplicates");
    }

    /// The point of the list: these and their lookalikes are held by the
    /// reserve, so registering one fails because it is already owned.
    #[test]
    fn reserved_names_and_their_lookalikes_are_held() {
        for r in all() {
            assert!(is_reserved(r.as_bytes()), "{r}");
            assert!(validate_name(r.as_bytes()).is_ok(), "{r} must be a valid name shape");
        }
        for attack in ["B1NANCE", "C0INBASE", "M!CROSOFT", "G-O-O-G-L-E", "ETHEREUM."] {
            assert!(is_reserved(attack.as_bytes()), "{attack} should collide with a reserved name");
        }
    }

    /// ⚠ The counterweight. Ordinary words stay registrable even when a famous
    /// company uses one, because blocking everyday language would do more harm
    /// than the impersonation it prevents. If this test ever fails, somebody has
    /// added a common word and taken it away from every legitimate user.
    #[test]
    fn ordinary_words_are_not_reserved() {
        for word in [
            "APPLE", "ORACLE", "AMAZON", "META", "VISA", "TELEGRAM", "SIGNAL", "DISCORD",
            "STRIPE", "LEDGER", "KRAKEN", "GEMINI", "PHANTOM", "POLYGON", "AVALANCHE", "RIPPLE",
            "OPTIMISM", "CELSIUS", "ADOBE", "CIRCLE", "EXODUS", "ALCHEMY", "TWITTER",
        ] {
            assert!(!is_reserved(word.as_bytes()), "{word} must stay registrable");
        }
    }

    /// Generic and community terms are nobody's brand. Bitcoin especially: it is
    /// a protocol name with no trademark owner.
    #[test]
    fn generic_and_community_terms_are_not_reserved() {
        for word in ["BITCOIN", "BLOCKCHAIN", "CRYPTO", "DEFI", "WALLET", "TOKEN", "DOGECOIN"] {
            assert!(!is_reserved(word.as_bytes()), "{word} must stay registrable");
        }
    }

    /// Normalisation must not accidentally make an ordinary name collide with a
    /// reserved one. Over-blocking is a real cost, not a safe default.
    #[test]
    fn normalisation_does_not_over_reach() {
        for word in ["METAL", "GOOGOL", "TESLAS", "COIN", "CHAIN", "OPEN"] {
            assert!(!is_reserved(word.as_bytes()), "{word} must stay registrable");
        }
        assert_ne!(normalise(b"METAL"), normalise(b"METAMASK"));
    }
}
