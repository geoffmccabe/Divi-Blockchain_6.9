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
//! is skipped with no state change at all ([`envelope::Ignored`]). The only
//! record that ever destroys units is an explicit BURN. This is a deliberate
//! rejection of Runes' "cenotaph" design, where a malformed record burns every
//! token in the transaction and an unrecognised field destroys the holdings of
//! anyone running older software (spec §8).
//!
//! **Halt rather than diverge.** An envelope version this build cannot read
//! stops the indexer ([`envelope::Halt`]) instead of guessing. An indexer that
//! stops and asks to be upgraded is *unavailable*, which is recoverable. Two
//! indexers that silently disagree is *divergence*, which is not.
//!
//! ## Layout
//!
//! | module | role |
//! |---|---|
//! | [`varint`] | LEB128 + a bounds-checked cursor; canonical encodings only |
//! | [`envelope`] | shared DVXP header; the ignore/halt outcome model |
//! | [`address`] | 21-byte packed addresses carried in payloads |
//! | [`ticker`] | charset, length, normalised reserved matching |
//! | [`fees`] | compiled-in fee constants, scaled by ticker length |
//! | [`record`] | the eight record types and subtype dispatch |
//!
//! Adding a new record type is a local change — see [`record`].

pub mod address;
pub mod envelope;
pub mod fees;
pub mod record;
pub mod ticker;
pub mod varint;

pub use address::Address;
pub use envelope::{classify, Envelope, Halt, Ignored};
pub use record::{Record, TokenId};

/// Outcome of reading one OP_META payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A well-formed DMT record, ready to apply to state.
    Record(Record),
    /// No state change; the reason is retained for logging and audit.
    Skip(Ignored),
}

/// Parse one OP_META payload end to end.
///
/// `Err(Halt)` must stop the indexer; it must never be treated as a skip.
pub fn parse_payload(payload: &[u8]) -> Result<Outcome, Halt> {
    match classify(payload)? {
        Err(ignored) => Ok(Outcome::Skip(ignored)),
        Ok(env) => Ok(match Record::parse(&env) {
            Ok(r) => Outcome::Record(r),
            Err(ignored) => Outcome::Skip(ignored),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_varint;

    fn envelope_of(subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = envelope::MAGIC.to_vec();
        v.extend_from_slice(&[envelope::SUPPORTED_VERSION, envelope::TYPE_DMT, subtype]);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parses_a_burn_end_to_end() {
        let mut body = Vec::new();
        encode_varint(7, &mut body); // block
        encode_varint(2, &mut body); // tx index
        encode_varint(250, &mut body); // amount
        let raw = envelope_of(record::SUB_BURN, &body);

        match parse_payload(&raw).unwrap() {
            Outcome::Record(Record::Burn(b)) => {
                assert_eq!(b.token, TokenId { block: 7, tx_index: 2 });
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
        // A PoE record shares the envelope and is simply not ours.
        let mut poe = envelope::MAGIC.to_vec();
        poe.extend_from_slice(&[0x01, 0x01, 0x01]);
        assert_eq!(
            parse_payload(&poe).unwrap(),
            Outcome::Skip(Ignored::OtherType(0x01))
        );
    }

    #[test]
    fn a_future_version_halts_the_indexer() {
        let mut future = envelope::MAGIC.to_vec();
        future.extend_from_slice(&[0x99, envelope::TYPE_DMT, record::SUB_BURN]);
        assert!(matches!(parse_payload(&future), Err(Halt::UnsupportedVersion { .. })));
    }

    /// The safety property the whole design rests on: nothing that arrives
    /// malformed is ever allowed to mean "destroy value".
    #[test]
    fn no_malformed_input_ever_yields_a_burn() {
        let mut cases: Vec<Vec<u8>> = Vec::new();
        for subtype in 0x00u8..=0x0a {
            for len in 0usize..24 {
                cases.push(envelope_of(subtype, &vec![0xffu8; len]));
                cases.push(envelope_of(subtype, &vec![0x00u8; len]));
                cases.push(envelope_of(subtype, &vec![0x80u8; len]));
            }
        }
        for raw in cases {
            if let Ok(Outcome::Record(Record::Burn(_))) = parse_payload(&raw) {
                // A burn may only come from a well-formed BURN record.
                assert_eq!(raw[6], record::SUB_BURN, "burn from subtype {:#x}", raw[6]);
            }
        }
    }
}
