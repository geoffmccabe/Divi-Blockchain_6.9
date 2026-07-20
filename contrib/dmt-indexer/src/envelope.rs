//! The shared DVXP envelope (spec §3), and the outcome model of §8.
//!
//! DMT is type 0x04. PoE (0x01), NFD (0x02) and PoE-batch (0x03) share this
//! envelope and are simply not ours.

/// `"DVXP"`.
pub const MAGIC: [u8; 4] = *b"DVXP";
/// The only envelope version this build understands.
pub const SUPPORTED_VERSION: u8 = 0x01;
/// Divi Meta Tokens.
pub const TYPE_DMT: u8 = 0x04;
/// magic(4) + version(1) + type(1) + subtype(1)
pub const HEADER_LEN: usize = 7;

/// Why a record produced no state change. Every variant means "skip it";
/// none of them ever destroys value (spec §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ignored {
    /// Not a DVXP record at all, or too short to be one.
    NotDvxp,
    /// A DVXP record belonging to PoE or NFD, not DMT.
    OtherType(u8),
    /// Subtype not defined in this version.
    UnknownSubtype(u8),
    /// Body did not parse: bad lengths, bad varints, truncation.
    Malformed(&'static str),
    /// Parsed cleanly but left unconsumed bytes.
    TrailingBytes,
    /// Well-formed but rejected by a rule (reserved name, bad charset, ...).
    RuleViolation(&'static str),
}

/// Conditions that must stop the indexer rather than be skipped (spec §8).
///
/// Halting is deliberate: an indexer that stops and asks to be upgraded is
/// merely unavailable, which is recoverable. Two indexers that silently
/// disagree is divergence, which is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// A future envelope version. This build cannot know what it means.
    UnsupportedVersion { found: u8, supported: u8 },
}

/// A parsed DMT envelope; `body` is the subtype-specific remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub subtype: u8,
    pub body: &'a [u8],
}

/// Classify a raw OP_META payload.
///
/// `Ok(Some(env))`  -- a DMT record to parse
/// `Ok(None)`       -- not ours; skip (reason in `ignored`)
/// `Err(halt)`      -- stop the indexer
pub fn classify(payload: &[u8]) -> Result<Result<Envelope<'_>, Ignored>, Halt> {
    if payload.len() < HEADER_LEN || payload[0..4] != MAGIC {
        return Ok(Err(Ignored::NotDvxp));
    }

    let version = payload[4];
    // Version is checked BEFORE type: a future version may redefine types, so
    // we must not assume a record is "not ours" based on a byte we cannot
    // interpret. Halting is the only safe answer.
    if version != SUPPORTED_VERSION {
        return Err(Halt::UnsupportedVersion {
            found: version,
            supported: SUPPORTED_VERSION,
        });
    }

    let record_type = payload[5];
    if record_type != TYPE_DMT {
        return Ok(Err(Ignored::OtherType(record_type)));
    }

    Ok(Ok(Envelope {
        subtype: payload[6],
        body: &payload[HEADER_LEN..],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(version: u8, ty: u8, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend_from_slice(&[version, ty, subtype]);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn accepts_a_dmt_record() {
        let raw = env(0x01, TYPE_DMT, 0x02, &[9, 9, 9]);
        let got = classify(&raw).unwrap().unwrap();
        assert_eq!(got.subtype, 0x02);
        assert_eq!(got.body, &[9, 9, 9]);
    }

    #[test]
    fn skips_non_dvxp_and_other_types() {
        assert_eq!(classify(b"hello").unwrap(), Err(Ignored::NotDvxp));
        assert_eq!(classify(&[]).unwrap(), Err(Ignored::NotDvxp));
        // PoE and NFD share the envelope and must be passed over, not halted on.
        for ty in [0x01u8, 0x02, 0x03] {
            let raw = env(0x01, ty, 0x01, &[]);
            assert_eq!(classify(&raw).unwrap(), Err(Ignored::OtherType(ty)));
        }
    }

    #[test]
    fn future_version_halts_rather_than_skipping() {
        let raw = env(0x02, TYPE_DMT, 0x01, &[]);
        assert_eq!(
            classify(&raw),
            Err(Halt::UnsupportedVersion { found: 0x02, supported: 0x01 })
        );
    }

    #[test]
    fn future_version_halts_even_for_a_foreign_type() {
        // A later version may reassign type bytes, so "not our type" cannot be
        // concluded from an unreadable version. Must halt, not skip.
        let raw = env(0x07, 0x01, 0x01, &[]);
        assert!(matches!(classify(&raw), Err(Halt::UnsupportedVersion { .. })));
    }

    #[test]
    fn header_boundary_is_exact() {
        let raw = env(0x01, TYPE_DMT, 0x01, &[]);
        assert_eq!(raw.len(), HEADER_LEN);
        assert_eq!(classify(&raw).unwrap().unwrap().body, &[] as &[u8]);
        // One byte short of a full header is not a DVXP record.
        assert_eq!(classify(&raw[..HEADER_LEN - 1]).unwrap(), Err(Ignored::NotDvxp));
    }
}
