//! Handler registry + the per-block chained state fingerprint.
//!
//! Adding a new class of on-chain object (a new record type) means implementing
//! [`RecordHandler`] and registering it — the scanner, envelope, fingerprint,
//! and every other protocol are untouched. That is the whole point: PoE, NFD,
//! DMT and future types coexist without any of them knowing about the others.

use crate::codec::Address;
use crate::{classify, Halt, Ignored, Record};
use sha2::{Digest, Sha256};

/// Where a record appeared and who authorised it. `sender` is the address that
/// funds `vin[0]` (the spec's deterministic, no-SegWit sender rule) — `None`
/// when it doesn't resolve to a plain address, in which case a handler that
/// needs a sender returns `Ignored`.
#[derive(Debug, Clone)]
pub struct RecordContext {
    pub height: u64,
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub block_time: i64,
    pub sender: Option<Address>,
}

/// A protocol that owns one DVXP record type. The core guarantees the record is
/// a valid DVXP envelope of a supported version before `apply` is called.
pub trait RecordHandler {
    /// The single record type byte this handler owns (e.g. `TYPE_NFD`).
    fn record_type(&self) -> u8;

    /// Apply one record to this handler's state.
    ///
    /// * `Ok(delta)` — applied; `delta` is the canonical bytes describing the
    ///   state change, folded into the per-block fingerprint in chain order.
    ///   Return an empty `Vec` for a record that is valid but changes nothing.
    /// * `Err(Ignored)` — skip it, no state change. **Never destroys value.**
    fn apply(&mut self, rec: &Record, ctx: &RecordContext) -> Result<Vec<u8>, Ignored>;
}

/// The outcome of classifying + dispatching one payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A handler applied the record; `delta` feeds the fingerprint.
    Applied { record_type: u8, delta: Vec<u8> },
    /// Skipped — reason attached, no state change.
    Ignored(Ignored),
}

/// Dispatches classified records to the right handler, one per type.
#[derive(Default)]
pub struct Registry {
    handlers: Vec<Box<dyn RecordHandler>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { handlers: Vec::new() }
    }

    /// Register a handler. Rejects a second handler for the same type — two
    /// handlers for one type is a build error, not a runtime ambiguity.
    pub fn register(&mut self, handler: Box<dyn RecordHandler>) -> Result<(), &'static str> {
        if self.handles(handler.record_type()) {
            return Err("a handler is already registered for this record type");
        }
        self.handlers.push(handler);
        Ok(())
    }

    pub fn handles(&self, record_type: u8) -> bool {
        self.handlers.iter().any(|h| h.record_type() == record_type)
    }

    /// Classify one OP_META payload and dispatch it. `Err(Halt)` must stop the
    /// indexer (unknown envelope version); everything else is a normal `Outcome`.
    pub fn process(&mut self, payload: &[u8], ctx: &RecordContext) -> Result<Outcome, Halt> {
        let rec = match classify(payload)? {
            Ok(rec) => rec,
            Err(ig) => return Ok(Outcome::Ignored(ig)),
        };
        match self.handlers.iter_mut().find(|h| h.record_type() == rec.record_type) {
            None => Ok(Outcome::Ignored(Ignored::UnknownType(rec.record_type))),
            Some(h) => Ok(match h.apply(&rec, ctx) {
                Ok(delta) => Outcome::Applied { record_type: rec.record_type, delta },
                Err(ig) => Outcome::Ignored(ig),
            }),
        }
    }
}

/// The per-block chained state fingerprint (spec §9.2):
/// `F(n) = SHA256( F(n-1) ‖ height ‖ block's canonical state changes )`.
/// Because it's a chain, any divergence propagates forward permanently, so two
/// implementations discover they disagree immediately rather than years later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn genesis() -> Self {
        Self([0u8; 32])
    }

    /// Fold one block's ordered state changes into the chain.
    pub fn advance(&self, height: u64, block_deltas: &[u8]) -> Fingerprint {
        let mut h = Sha256::new();
        h.update(self.0);
        h.update(height.to_le_bytes());
        h.update(block_deltas);
        Fingerprint(h.finalize().into())
    }

    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAGIC, TYPE_DMT, TYPE_NFD};

    // A trivial handler that records "I saw one" as its delta.
    struct Counter {
        ty: u8,
        seen: u32,
    }
    impl RecordHandler for Counter {
        fn record_type(&self) -> u8 {
            self.ty
        }
        fn apply(&mut self, rec: &Record, _ctx: &RecordContext) -> Result<Vec<u8>, Ignored> {
            if rec.subtype == 0xff {
                return Err(Ignored::UnknownSubtype(0xff));
            }
            self.seen += 1;
            Ok(vec![rec.record_type, rec.subtype])
        }
    }

    fn ctx() -> RecordContext {
        RecordContext { height: 10, tx_index: 0, txid: [0; 32], block_time: 0, sender: None }
    }

    fn rec(ty: u8, subtype: u8) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend_from_slice(&[0x01, ty, subtype]);
        v
    }

    #[test]
    fn dispatches_to_the_right_handler_and_flags_unknown_types() {
        let mut reg = Registry::new();
        reg.register(Box::new(Counter { ty: TYPE_NFD, seen: 0 })).unwrap();
        reg.register(Box::new(Counter { ty: TYPE_DMT, seen: 0 })).unwrap();

        assert_eq!(
            reg.process(&rec(TYPE_NFD, 1), &ctx()).unwrap(),
            Outcome::Applied { record_type: TYPE_NFD, delta: vec![TYPE_NFD, 1] }
        );
        // a type with no handler is ignored, never an error
        assert_eq!(
            reg.process(&rec(0x09, 1), &ctx()).unwrap(),
            Outcome::Ignored(Ignored::UnknownType(0x09))
        );
        // handler-level skip is surfaced, not destroyed
        assert_eq!(
            reg.process(&rec(TYPE_DMT, 0xff), &ctx()).unwrap(),
            Outcome::Ignored(Ignored::UnknownSubtype(0xff))
        );
    }

    #[test]
    fn rejects_duplicate_type_registration() {
        let mut reg = Registry::new();
        reg.register(Box::new(Counter { ty: TYPE_NFD, seen: 0 })).unwrap();
        assert!(reg.register(Box::new(Counter { ty: TYPE_NFD, seen: 0 })).is_err());
    }

    #[test]
    fn unknown_version_halts_dispatch() {
        let mut reg = Registry::new();
        reg.register(Box::new(Counter { ty: TYPE_NFD, seen: 0 })).unwrap();
        let mut bad = MAGIC.to_vec();
        bad.extend_from_slice(&[0x02, TYPE_NFD, 0x01]); // version 2
        assert!(matches!(reg.process(&bad, &ctx()), Err(Halt::UnsupportedVersion { .. })));
    }

    #[test]
    fn fingerprint_chains_and_detects_divergence() {
        let g = Fingerprint::genesis();
        let a = g.advance(1, b"same").advance(2, b"changes");
        let b = g.advance(1, b"same").advance(2, b"changes");
        let c = g.advance(1, b"same").advance(2, b"DIFFERENT");
        assert_eq!(a, b, "same history -> same fingerprint");
        assert_ne!(a, c, "any divergence propagates forward");
        assert_eq!(a.hex().len(), 64);
    }
}
