//! Shared core for Divi's DVXP overlay protocols.
//!
//! Every overlay record — Proof-of-Existence (type 0x01), NFD / Divi
//! Collectibles (0x02), PoE batch (0x03), Divi Meta Tokens (0x04), and whatever
//! we add next — rides in the SAME `OP_META` envelope. This crate owns the parts
//! that MUST be identical across all of them, because the one failure these
//! systems cannot survive is two indexers silently disagreeing:
//!
//!   * `classify` — the envelope parser + the skip-vs-halt decision (here).
//!   * [`varint`]  — canonical LEB128 + a bounds-checked cursor for bodies.
//!   * [`codec`]   — the shared payload encodings (addresses, object ids).
//!   * [`registry`] — the [`RecordHandler`] trait + dispatch, and the per-block
//!                    chained state fingerprint.
//!
//! A new class of on-chain object is added by writing one `RecordHandler` and
//! registering it — never by touching the scanner, the envelope, or any other
//! protocol's code.

pub mod codec;
pub mod registry;
pub mod varint;

/// `"DVXP"` — the magic that marks a Divi overlay record inside an OP_META output.
pub const MAGIC: [u8; 4] = *b"DVXP";
/// The only envelope version this build understands. A record with any other
/// version halts the indexer (see [`classify`]).
pub const SUPPORTED_VERSION: u8 = 0x01;
/// magic(4) + version(1) + type(1) + subtype(1)
pub const HEADER_LEN: usize = 7;

// Well-known record types (each has its own handler; this crate stays agnostic).
pub const TYPE_POE: u8 = 0x01;
pub const TYPE_NFD: u8 = 0x02;
pub const TYPE_POE_BATCH: u8 = 0x03;
pub const TYPE_DMT: u8 = 0x04;

/// Why a record produced no state change. **Every variant means "skip it"; none
/// ever destroys value.** This is the deliberate rejection of Runes' "cenotaph"
/// design, where a malformed record burns tokens — a booby-trap for our own
/// future upgrades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ignored {
    /// Not a DVXP record at all, or too short to be one.
    NotDvxp,
    /// A valid DVXP record whose type has no registered handler.
    UnknownType(u8),
    /// Subtype not defined by the handler for this type/version.
    UnknownSubtype(u8),
    /// Body did not parse: bad lengths, bad varints, truncation.
    Malformed(&'static str),
    /// Parsed cleanly but left unconsumed bytes.
    TrailingBytes,
    /// Well-formed but rejected by a protocol rule.
    RuleViolation(&'static str),
}

/// A condition that must STOP the indexer rather than be skipped.
///
/// Halting is deliberate: an indexer that stops and asks to be upgraded is
/// merely unavailable (recoverable). Two indexers that silently disagree is
/// divergence (not recoverable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// A future envelope version — this build cannot know what it means, and a
    /// later version may even reassign type bytes, so we must not guess.
    UnsupportedVersion { found: u8, supported: u8 },
}

/// A parsed DVXP record, independent of type. `body` is the subtype-specific
/// remainder that a [`RecordHandler`] interprets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    pub record_type: u8,
    pub subtype: u8,
    pub body: &'a [u8],
}

/// Classify a raw OP_META payload.
///
/// * `Ok(Ok(record))` — a valid DVXP record of a supported version (ANY type;
///   the registry decides whether a handler exists).
/// * `Ok(Err(Ignored))` — skip it (reason attached), no state change.
/// * `Err(Halt)` — stop the indexer.
///
/// Version is checked BEFORE type on purpose: a future version may redefine the
/// type byte, so "not our type" cannot be concluded from a byte we can't
/// interpret. The only safe answer to an unknown version is to halt.
pub fn classify(payload: &[u8]) -> Result<Result<Record<'_>, Ignored>, Halt> {
    if payload.len() < HEADER_LEN || payload[0..4] != MAGIC {
        return Ok(Err(Ignored::NotDvxp));
    }
    let version = payload[4];
    if version != SUPPORTED_VERSION {
        return Err(Halt::UnsupportedVersion { found: version, supported: SUPPORTED_VERSION });
    }
    Ok(Ok(Record {
        record_type: payload[5],
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
    fn accepts_any_supported_type() {
        for ty in [TYPE_POE, TYPE_NFD, TYPE_POE_BATCH, TYPE_DMT, 0x40] {
            let raw = env(0x01, ty, 0x02, &[9, 9]);
            let got = classify(&raw).unwrap().unwrap();
            assert_eq!(got.record_type, ty);
            assert_eq!(got.subtype, 0x02);
            assert_eq!(got.body, &[9, 9]);
        }
    }

    #[test]
    fn skips_non_dvxp() {
        assert_eq!(classify(b"hello").unwrap(), Err(Ignored::NotDvxp));
        assert_eq!(classify(&[]).unwrap(), Err(Ignored::NotDvxp));
        let raw = env(0x01, TYPE_NFD, 0x01, &[]);
        assert_eq!(classify(&raw[..HEADER_LEN - 1]).unwrap(), Err(Ignored::NotDvxp));
    }

    #[test]
    fn unknown_version_halts_even_for_foreign_type() {
        let raw = env(0x02, TYPE_DMT, 0x01, &[]);
        assert!(matches!(classify(&raw), Err(Halt::UnsupportedVersion { found: 0x02, .. })));
        // a later version may reassign type bytes -> still halt, never skip
        let raw2 = env(0x07, 0x01, 0x01, &[]);
        assert!(matches!(classify(&raw2), Err(Halt::UnsupportedVersion { .. })));
    }
}
