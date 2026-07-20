//! # DMT — Divi Meta Tokens, reference indexer
//!
//! Normative implementation of `docs/DMT-TOKENS-SPEC.md`. Where this code and
//! the specification disagree, **this code is authoritative** and the document
//! is amended to match (spec §9.5) — one normative implementation is how two
//! indexers are kept from quietly believing different things.
//!
//! ## What this is
//!
//! DMT is an **overlay**. The Divi chain carries and orders these records
//! permanently; this software interprets them into balances. The network does
//! not validate token rules and no opcode could make it (spec §2, §12.2). The
//! accurate claim is "permanently recorded and ordered by the Divi chain",
//! never "the network enforces it".
//!
//! ## Two rules that shape everything here
//!
//! **Ignore, never destroy.** Any malformed, unparsable or unrecognised record
//! is skipped with no state change at all. The only record that ever destroys
//! units is an explicit BURN. This is a deliberate rejection of Runes'
//! "cenotaph" design, where a malformed record burns every token in the
//! transaction and an unrecognised field destroys the holdings of anyone
//! running older software (spec §8).
//!
//! **Halt rather than diverge.** An envelope version this build cannot read
//! stops the indexer instead of guessing. An indexer that stops and asks to be
//! upgraded is *unavailable*, which is recoverable. Two indexers that silently
//! disagree is *divergence*, which is not.
//!
//! ## Layout
//!
//! The envelope, varints, addresses and object ids live in `dvxp-core`, shared
//! with PoE and NFD. This crate owns only what is specific to tokens:
//!
//! | module | role |
//! |---|---|
//! | [`ticker`] | charset, length, normalised reserved matching |
//! | [`fees`] | compiled-in fee constants, scaled by ticker length |
//! | [`record`] | the eight record types and subtype dispatch |
//!
//! Adding a new record type is a local change — see [`record`].

pub mod config;
pub mod fees;
pub mod ledger;
pub mod record;
pub mod ticker;

pub use record::{Record, TokenId};

use dvxp_core::{Halt, Ignored, TYPE_DMT};

/// Outcome of reading one OP_META payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A well-formed DMT record, ready to apply to state.
    Record(Record),
    /// No state change; the reason is retained for logging and audit.
    Skip(Ignored),
}

/// Parse one OP_META payload end to end, using the shared classifier.
///
/// `Err(Halt)` must stop the indexer; it must never be treated as a skip.
pub fn parse_payload(payload: &[u8]) -> Result<Outcome, Halt> {
    match dvxp_core::classify(payload)? {
        Err(ignored) => Ok(Outcome::Skip(ignored)),
        Ok(rec) => {
            if rec.record_type != TYPE_DMT {
                return Ok(Outcome::Skip(Ignored::UnknownType(rec.record_type)));
            }
            Ok(match Record::parse(rec.subtype, rec.body) {
                Ok(r) => Outcome::Record(r),
                Err(ignored) => Outcome::Skip(ignored),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::varint::write_varint;
    use dvxp_core::{MAGIC, SUPPORTED_VERSION};

    fn envelope_of(record_type: u8, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend_from_slice(&[SUPPORTED_VERSION, record_type, subtype]);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parses_a_burn_end_to_end() {
        let mut body = Vec::new();
        write_varint(&mut body, 7); // height
        write_varint(&mut body, 2); // tx index
        write_varint(&mut body, 250); // amount
        let raw = envelope_of(TYPE_DMT, record::SUB_BURN, &body);

        match parse_payload(&raw).unwrap() {
            Outcome::Record(Record::Burn(b)) => {
                assert_eq!(b.token, TokenId { height: 7, tx_index: 2 });
                assert_eq!(b.amount, 250);
            }
            other => panic!("expected a burn, got {other:?}"),
        }
    }

    #[test]
    fn junk_and_foreign_records_skip_without_state_change() {
        for payload in [&b""[..], b"not a record", b"DVXPxx"] {
            assert!(matches!(parse_payload(payload).unwrap(), Outcome::Skip(_)));
        }
        // PoE and NFD share the envelope and are simply not ours.
        for ty in [dvxp_core::TYPE_POE, dvxp_core::TYPE_NFD, dvxp_core::TYPE_POE_BATCH] {
            let raw = envelope_of(ty, 0x01, &[]);
            assert_eq!(
                parse_payload(&raw).unwrap(),
                Outcome::Skip(Ignored::UnknownType(ty))
            );
        }
    }

    #[test]
    fn a_future_version_halts_the_indexer() {
        let mut future = MAGIC.to_vec();
        future.extend_from_slice(&[0x99, TYPE_DMT, record::SUB_BURN]);
        assert!(matches!(parse_payload(&future), Err(Halt::UnsupportedVersion { .. })));
    }

    /// The safety property the whole design rests on: nothing that arrives
    /// malformed is ever allowed to mean "destroy value".
    #[test]
    fn no_malformed_input_ever_yields_a_burn() {
        for subtype in 0x00u8..=0x0a {
            for len in 0usize..24 {
                for filler in [0xffu8, 0x00, 0x80] {
                    let raw = envelope_of(TYPE_DMT, subtype, &vec![filler; len]);
                    if let Ok(Outcome::Record(Record::Burn(_))) = parse_payload(&raw) {
                        assert_eq!(subtype, record::SUB_BURN, "burn from subtype {subtype:#x}");
                    }
                }
            }
        }
    }
}
