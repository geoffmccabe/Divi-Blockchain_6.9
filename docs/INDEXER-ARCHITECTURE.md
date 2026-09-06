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

## Migration — DMT indexer: DONE

`dmt-indexer` no longer carries its own `envelope.rs` / `varint.rs`; it depends on
`dvxp-core` and uses `classify()` directly. `nfd-indexer` is a `RecordHandler`
for `0x02` and goes through `Registry`. Note the asymmetry, because it surprises
everyone who drives both: **DMT is not a `RecordHandler`.** Its ledger needs a
`TxContext` carrying every payment the transaction makes, because a priced mint
must be paid for in the *same* transaction. A driver has to build the richer
context and call `dmt_indexer::parse_payload` itself.

## Where the shared pieces actually stand (2026-Sep-06)

This section was stale for a while and said "still to build" about code that
exists. Corrected, and kept honest from here.

**Built, per-protocol, not yet shared:**

- **Rules engines.** `dmt-indexer` (8 record types, ledger, 72 tests) and
  `nfd-indexer` (ownership ledger, 10 tests).
- **Reorg/undo — DMT only.** `dmt-indexer/src/ledger/reorg.rs` retains 200 blocks
  of undo against Divi's hard 100-block reorg cap and halts rather than guessing
  beyond it. **`nfd-indexer` has none**, so a reorg would leave collectible
  ownership quietly wrong. Fixing that is a prerequisite for any live scanner.

**Built, but in the wrong place and not a service:**

- **Block scanner.** `Divilovescan/indexer/src/main.rs` walks blocks, pulls
  `OP_META` outputs, and drives both indexers. It works, and it is a **one-shot
  batch scan**: it runs `start..tip` once and exits. No resume, no tip following,
  no reorg handling, no RPC throttle, and its output is a single JSON snapshot
  rather than anything queryable. It also advances the fingerprint from **NFD
  deltas only**, so the published fingerprint does not currently cover DMT at
  all — the one value whose job is catching divergence is blind to tokens.

**Now built, here: `contrib/dvxp-scan`.**

A library with a daemon on top. `driver::Overlay` is pure and drives every
protocol over one pass, with **one combined fingerprint** (tagged per record
type, so tokens are no longer invisible to it) and **one reorg window**. The
`rpc` feature carries the throttled node client; the wallet depends on the crate
with `default-features = false` and drives it in-process from its own node
connection, which is what keeps a self-custody wallet independent of any server
we run. `nfd-indexer` gained the undo log it was missing so that window covers
both protocols.

**Still genuinely missing:**

- **State store.** A per-protocol schema shaped around the queries in DD69's
  `docs/DMT-WALLET-INTERFACE.md` §2, plus the published fingerprint per block.
  `dvxp-scan` publishes progress and sync state today; it does not yet answer
  "what does this address hold".
- **Genesis height.** Still `0` in `dmt-indexer/src/config.rs`. Until it is set,
  every scan replays 4.1M irrelevant blocks.

**Decision (2026-Sep-06), now implemented:** the scanner lives here, in
`contrib/dvxp-scan`, as a library with a thin binary on top. Divilovescan and
DD69 both vendor it the same way they already vendor `dvxp-core` and the rules
crates. Any other arrangement means the wallet and the explorer can run different
scanning rules, which is exactly the divergence this crate exists to prevent.
`Divilovescan/indexer` is superseded and should be switched over to it.
