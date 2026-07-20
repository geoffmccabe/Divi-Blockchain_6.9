//! ISSUE (subtype 0x01) -- create a token (spec §5.1, §6).

use super::{ensure_drained, malformed};
use crate::envelope::Ignored;
use crate::ticker;
use crate::varint::Cursor;

pub const FLAG_OPEN_MINT: u8 = 0x01;
pub const FLAG_SUPPLY_LOCKED: u8 = 0x02;
pub const FLAG_METADATA: u8 = 0x04;
pub const FLAG_NON_TRANSFERABLE: u8 = 0x08;
pub const FLAG_ISSUER_MINTABLE: u8 = 0x10;
pub const FLAG_PROCEEDS_BURNED: u8 = 0x20;
pub const FLAG_RISING_PRICE: u8 = 0x40;
/// Bits with no meaning in version 0x01. Any of these set -> ignore the record.
pub const FLAGS_RESERVED: u8 = 0x80;

pub const SALT_LEN: usize = 20;
pub const METADATA_PTR_LEN: usize = 32;
pub const MAX_DECIMALS: u8 = 8;

/// Open-mint terms, present only when `FLAG_OPEN_MINT` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTerms {
    /// 0 = unlimited.
    pub cap: u64,
    /// Units per claim; must be > 0.
    pub per_mint: u64,
    /// 0 = immediately.
    pub height_start: u64,
    /// 0 = no end.
    pub height_end: u64,
    /// Duffs per claim; 0 = free.
    pub mint_price: u64,
    /// Added to `mint_price` per claim already made (spec §6.3).
    pub price_step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub flags: u8,
    pub decimals: u8,
    pub ticker: Vec<u8>,
    pub salt: [u8; SALT_LEN],
    pub premine: u64,
    pub terms: Option<MintTerms>,
    pub metadata_ptr: Option<[u8; METADATA_PTR_LEN]>,
}

impl Issue {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
    pub fn is_open_mint(&self) -> bool {
        self.has(FLAG_OPEN_MINT)
    }
    /// Price of the next claim given how many have already been made (§6.3).
    /// Saturating: an absurd `price_step` cannot wrap the price to zero.
    pub fn price_at(&self, claims_made: u64) -> u64 {
        match &self.terms {
            None => 0,
            Some(t) => t
                .mint_price
                .saturating_add(t.price_step.saturating_mul(claims_made)),
        }
    }
}

pub fn parse(body: &[u8]) -> Result<Issue, Ignored> {
    let mut c = Cursor::new(body);

    let flags = c.read_u8().map_err(malformed)?;
    if flags & FLAGS_RESERVED != 0 {
        return Err(Ignored::Malformed("reserved flag bit set"));
    }
    // Contradictory supply policy -- ignore rather than guess an intent.
    if flags & FLAG_SUPPLY_LOCKED != 0 && flags & FLAG_ISSUER_MINTABLE != 0 {
        return Err(Ignored::RuleViolation("supply cannot be both locked and mintable"));
    }
    // Mint-only modifiers are meaningless without an open mint (spec §5.1).
    let open_mint = flags & FLAG_OPEN_MINT != 0;
    if !open_mint && (flags & (FLAG_PROCEEDS_BURNED | FLAG_RISING_PRICE)) != 0 {
        return Err(Ignored::RuleViolation("mint modifier without open mint"));
    }

    let decimals = c.read_u8().map_err(malformed)?;
    if decimals > MAX_DECIMALS {
        return Err(Ignored::RuleViolation("decimals out of range"));
    }

    let ticker_len = c.read_u8().map_err(malformed)? as usize;
    let ticker = c.read_bytes(ticker_len).map_err(malformed)?.to_vec();
    ticker::validate(&ticker).map_err(|e| match e {
        ticker::TickerError::Reserved => Ignored::RuleViolation("reserved ticker"),
        _ => Ignored::RuleViolation("invalid ticker"),
    })?;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(c.read_bytes(SALT_LEN).map_err(malformed)?);

    let premine = c.read_varint().map_err(malformed)?;

    let terms = if open_mint {
        let cap = c.read_varint().map_err(malformed)?;
        let per_mint = c.read_varint().map_err(malformed)?;
        if per_mint == 0 {
            return Err(Ignored::RuleViolation("per_mint must be positive"));
        }
        let height_start = c.read_varint().map_err(malformed)?;
        let height_end = c.read_varint().map_err(malformed)?;
        if height_end != 0 && height_end < height_start {
            return Err(Ignored::RuleViolation("mint window ends before it starts"));
        }
        let mint_price = c.read_varint().map_err(malformed)?;
        let price_step = if flags & FLAG_RISING_PRICE != 0 {
            let step = c.read_varint().map_err(malformed)?;
            if mint_price == 0 {
                return Err(Ignored::RuleViolation("rising price needs a base price"));
            }
            step
        } else {
            0
        };
        Some(MintTerms { cap, per_mint, height_start, height_end, mint_price, price_step })
    } else {
        None
    };

    // Total supply must be representable, or later arithmetic is undefined.
    if let Some(t) = &terms {
        if premine.checked_add(t.cap).is_none() {
            return Err(Ignored::RuleViolation("premine plus cap overflows"));
        }
    }

    let metadata_ptr = if flags & FLAG_METADATA != 0 {
        let mut p = [0u8; METADATA_PTR_LEN];
        p.copy_from_slice(c.read_bytes(METADATA_PTR_LEN).map_err(malformed)?);
        Some(p)
    } else {
        None
    };

    ensure_drained(&c)?;
    Ok(Issue { flags, decimals, ticker, salt, premine, terms, metadata_ptr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_varint;

    struct Build {
        flags: u8,
        decimals: u8,
        ticker: Vec<u8>,
        premine: u64,
        terms: Option<(u64, u64, u64, u64, u64, u64)>,
        metadata: bool,
    }

    impl Default for Build {
        fn default() -> Self {
            Self {
                flags: 0,
                decimals: 8,
                ticker: b"GOLD".to_vec(),
                premine: 1000,
                terms: None,
                metadata: false,
            }
        }
    }

    impl Build {
        fn bytes(&self) -> Vec<u8> {
            let mut v = vec![self.flags, self.decimals, self.ticker.len() as u8];
            v.extend_from_slice(&self.ticker);
            v.extend_from_slice(&[0x11u8; SALT_LEN]);
            encode_varint(self.premine, &mut v);
            if let Some((cap, per, hs, he, price, step)) = self.terms {
                for n in [cap, per, hs, he, price] {
                    encode_varint(n, &mut v);
                }
                if self.flags & FLAG_RISING_PRICE != 0 {
                    encode_varint(step, &mut v);
                }
            }
            if self.metadata {
                v.extend_from_slice(&[0x22u8; METADATA_PTR_LEN]);
            }
            v
        }
    }

    #[test]
    fn parses_a_minimal_fixed_supply_token() {
        let b = Build { flags: FLAG_SUPPLY_LOCKED, ..Default::default() };
        let issued = parse(&b.bytes()).unwrap();
        assert_eq!(issued.ticker, b"GOLD");
        assert_eq!(issued.premine, 1000);
        assert_eq!(issued.decimals, 8);
        assert!(issued.terms.is_none());
        assert!(!issued.is_open_mint());
    }

    #[test]
    fn parses_an_open_mint_with_rising_price() {
        let b = Build {
            flags: FLAG_OPEN_MINT | FLAG_RISING_PRICE,
            terms: Some((10_000, 10, 0, 0, 500, 25)),
            ..Default::default()
        };
        let issued = parse(&b.bytes()).unwrap();
        let t = issued.terms.as_ref().unwrap();
        assert_eq!((t.cap, t.per_mint, t.mint_price, t.price_step), (10_000, 10, 500, 25));
        // price(n) = mint_price + step*n
        assert_eq!(issued.price_at(0), 500);
        assert_eq!(issued.price_at(4), 600);
    }

    #[test]
    fn indivisible_tokens_are_ordinary() {
        let b = Build { decimals: 0, ticker: b"TICKET".to_vec(), ..Default::default() };
        assert_eq!(parse(&b.bytes()).unwrap().decimals, 0);
    }

    #[test]
    fn rejects_reserved_bits_and_contradictions() {
        let bad_bit = Build { flags: FLAGS_RESERVED, ..Default::default() };
        assert_eq!(parse(&bad_bit.bytes()), Err(Ignored::Malformed("reserved flag bit set")));

        let contradiction =
            Build { flags: FLAG_SUPPLY_LOCKED | FLAG_ISSUER_MINTABLE, ..Default::default() };
        assert!(matches!(parse(&contradiction.bytes()), Err(Ignored::RuleViolation(_))));

        let orphan_modifier = Build { flags: FLAG_PROCEEDS_BURNED, ..Default::default() };
        assert!(matches!(parse(&orphan_modifier.bytes()), Err(Ignored::RuleViolation(_))));
    }

    #[test]
    fn rejects_bad_decimals_ticker_and_terms() {
        let d = Build { decimals: 9, ..Default::default() };
        assert!(matches!(parse(&d.bytes()), Err(Ignored::RuleViolation(_))));

        let reserved = Build { ticker: b"DIVI".to_vec(), ..Default::default() };
        assert_eq!(parse(&reserved.bytes()), Err(Ignored::RuleViolation("reserved ticker")));

        let lower = Build { ticker: b"gold".to_vec(), ..Default::default() };
        assert_eq!(parse(&lower.bytes()), Err(Ignored::RuleViolation("invalid ticker")));

        let zero_per_mint =
            Build { flags: FLAG_OPEN_MINT, terms: Some((100, 0, 0, 0, 0, 0)), ..Default::default() };
        assert!(matches!(parse(&zero_per_mint.bytes()), Err(Ignored::RuleViolation(_))));

        let backwards_window = Build {
            flags: FLAG_OPEN_MINT,
            terms: Some((100, 1, 500, 400, 0, 0)),
            ..Default::default()
        };
        assert!(matches!(parse(&backwards_window.bytes()), Err(Ignored::RuleViolation(_))));
    }

    #[test]
    fn rejects_supply_overflow() {
        let b = Build {
            flags: FLAG_OPEN_MINT,
            premine: u64::MAX,
            terms: Some((5, 1, 0, 0, 0, 0)),
            ..Default::default()
        };
        assert!(matches!(parse(&b.bytes()), Err(Ignored::RuleViolation(_))));
    }

    #[test]
    fn rejects_trailing_bytes_and_truncation() {
        let b = Build::default();
        let mut extra = b.bytes();
        extra.push(0xff);
        assert_eq!(parse(&extra), Err(Ignored::TrailingBytes));

        let short = b.bytes();
        assert!(parse(&short[..short.len() - 1]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn metadata_pointer_is_optional_and_sized() {
        let with = Build { flags: FLAG_METADATA, metadata: true, ..Default::default() };
        assert!(parse(&with.bytes()).unwrap().metadata_ptr.is_some());
        // Flag set but pointer absent -> truncated, not silently accepted.
        let missing = Build { flags: FLAG_METADATA, metadata: false, ..Default::default() };
        assert!(parse(&missing.bytes()).is_err());
    }

    #[test]
    fn rising_price_cannot_saturate_to_zero() {
        let b = Build {
            flags: FLAG_OPEN_MINT | FLAG_RISING_PRICE,
            terms: Some((0, 1, 0, 0, 1, u64::MAX)),
            ..Default::default()
        };
        let issued = parse(&b.bytes()).unwrap();
        assert_eq!(issued.price_at(u64::MAX), u64::MAX);
    }
}
