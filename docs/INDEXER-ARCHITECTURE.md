# Shared indexer architecture — `dvxp-core`

**Audience:** the DMT, NFD, and PoE workstreams (and whoever adds the next record
class). This is the coordination contract so we build **one** indexer core, not
three that can silently disagree.

## No conflicts today

All overlay records share the `OP_META` "DVXP" envelope and are separated only by
the **type byte**. There are no collisions:

| type | protocol                       | owner workstream |
|------|--------------------------------|------------------|
| 0x01 | Proof of Existence             | chain / PoE      |
| 0x02 | NFD / Divi Collectibles        | NFD              |
| 0x03 | PoE Merkle batch               | chain / PoE      |
| 0x04 | DMT / Divi Meta Tokens         | DMT              |
| …    | reserved for future classes    | —                |

## The problem this solves

Every one of these needs the *same* behaviour, and it must be byte-for-byte
identical or two indexers diverge (the one failure these systems can't survive):

- envelope parsing + the **skip-vs-halt** decision (halt on unknown version;
  ignore-never-destroy everything else),
- canonical LEB128 varints and a bounds-checked body cursor,
- the shared payload encodings (21-byte addresses, `(height, tx_index)` object ids),
- the **per-block chained state fingerprint** `F(n)=SHA256(F(n-1)‖height‖Δ)`,
- deterministic ordering, prevout-based sender identity, 200-block reorg undo.

Duplicating these across `dmt-indexer`, an `nfd-indexer`, and `poe_index` is how
they drift apart. So the shared parts live in one crate.

## The shared crate: `contrib/dvxp-core/`

MIT, Rust, `sha2`-only. Already built and tested (12 tests). Modules:

- `lib.rs` — `classify(payload) -> Result<Result<Record, Ignored>, Halt>`: the
  type-agnostic envelope parser and the `Ignored` (skip) / `Halt` (stop) model.
- `varint.rs` — canonical `write_varint` + `Cursor` (bounds-checked, rejects
  overlong/truncated).
- `codec.rs` — `Address` (21 bytes) and `ObjectId` (`(height, tx_index)`).
- `registry.rs` — the `RecordHandler` trait, `Registry` dispatch, `RecordContext`
  (height, tx_index, txid, block_time, **sender = vin[0] prevout address**), and
  the `Fingerprint` chain.

## Adding a class = one handler (the flexibility contract)

A record class plugs in by implementing one trait — nothing else in the system
changes:

```
trait RecordHandler {
    fn record_type(&self) -> u8;                 // 0x02 for NFD, 0x04 for DMT, …
    fn apply(&mut self, rec: &Record, ctx: &RecordContext)
        -> Result<Vec<u8> /* fingerprint delta */, Ignored>;
}
```

`Registry::process()` classifies the payload, halts on an unknown version, skips
non-DVXP / unhandled-type / handler-rejected records (never destroying value),
and otherwise calls the owning handler. Want a new class of collectible or token
next year? Write a handler, register it. Done — no scanner or envelope edits.

## What each workstream owns vs shares

**Shared (in `dvxp-core`):** everything above.
**Per-protocol (its own handler + state):** the subtype bodies and rules, and the
state model — DMT: token balances + tickers; NFD: address→NFD ownership + the
Arweave/hash pointers; PoE: the anchor set.

## Migration — DMT indexer (mechanical, same semantics)

`contrib/dmt-indexer/` currently carries its own `envelope.rs` and `varint.rs`.
These are semantically identical to `dvxp-core`'s (same magic, same version-halt,
same canonical varints), by design — so the switch is drop-in:

1. Add `dvxp-core = { path = "../dvxp-core" }` to `dmt-indexer/Cargo.toml`.
2. Delete `dmt-indexer/src/{envelope,varint}.rs`; `use dvxp_core::{classify,
   varint::*, codec::*, registry::*}`.
3. Make the DMT logic a `RecordHandler` for `record_type() == 0x04`, returning its
   canonical state delta for the fingerprint.

The NFD workstream builds its `RecordHandler` for `0x02` the same way. Result: one
scanner, one fingerprint, one halt/skip rule — three (soon four) protocols.

## Still to build (shared, next)

`dvxp-core` owns the pure/deterministic core. The remaining shared pieces should
also land here, once, rather than per-protocol:

- **Block scanner** — walk blocks → txs → OP_META outputs → payloads via the
  node RPC (the Rust successor to `contrib/poe/poe_index.py`), resolving each
  tx's `vin[0]` prevout to fill `RecordContext.sender`.
- **Reorg/undo** — retain undo data for 200 blocks (Divi hard-caps reorgs at
  100); halt on anything deeper. Applies to every handler's state uniformly.
- **State store** — a SQLite home with a per-protocol schema, plus the published
  fingerprint per block.

Coordinate here before implementing these so we don't build two.
