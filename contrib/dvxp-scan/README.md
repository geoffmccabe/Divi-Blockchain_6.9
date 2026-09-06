# `dvxp-scan` — one scanner for every overlay protocol

`docs/INDEXER-ARCHITECTURE.md` asked for the block scanner to be built once,
shared, rather than per protocol. This is it.

## What it is

A library, with a daemon on top. The library half is the important half.

- **`driver::Overlay`** — pure. Hand it blocks, it applies them to every
  protocol, keeps one combined fingerprint and one reorg window. No I/O, no
  dependencies beyond the rules crates, fully unit tested.
- **`rpc`** (feature, on by default) — a throttled Divi JSON-RPC client and the
  block-to-records reduction.
- **`store`** (feature) — publishing progress atomically for readers.
- **`bin/divi-overlay-indexer`** — catch up, then follow the tip forever.

The wallet embeds the library and drives it from its own node connection:

```toml
dvxp-scan = { path = "...", default-features = false }
```

That is not a nicety. A self-custody wallet that got its balances from a server
we run would let our downtime hide a user's own tokens from them, which is
exactly what the spec's invitation to competing implementations exists to
prevent. So the scanner has to be callable in-process, under the wallet's
control, so it never competes with staking for RPC threads.

## What it fixed

Three things, all of which only bite in production:

1. **The fingerprint was blind to tokens.** The previous scanner advanced it from
   NFD deltas only. A fingerprint covering half the state is worse than none: it
   reads as an assurance and is not one. The combined fingerprint here chains
   every protocol's deltas, each tagged with its record type.
2. **Nothing handled a reorg.** Divi caps reorgs at 100 blocks; they happen. The
   old scanner would have left the wrong owner in place with no indication. This
   needed a matching change in `nfd-indexer`, which had no undo log at all.
3. **It ran once and exited.** No tip following, no throttle. An earlier scanner
   at ~1,170 blocks/sec with 12 workers saturated the node's RPC threads and took
   the public explorer offline, so throttling is on by default and the daemon
   yields between calls.

## Invariants

**A block applies completely or not at all.** Every payload is classified before
any is applied, so an unreadable envelope version halts with the ledger exactly
as the previous block left it.

**Halting is permanent until a human intervenes.** A halted driver refuses every
later block, and the daemon exits with code 2 so a supervisor can tell "upgrade
me" from "the node went away" and not restart-loop on the former.

**Skips are reported, never dropped.** A record the rules reject is a fact about
the chain. The old scanner discarded them.

## Running it

```
DIVI_RPC_USER=... DIVI_RPC_PASS=... START_HEIGHT=<overlay genesis> \
  divi-overlay-indexer
```

`START_HEIGHT` matters more than anything else here. Records below the overlay
genesis height are ignored by the rules, so with it set the scanner never touches
the 4.1M blocks that predate tokens: minutes of work at launch, growing by about
1,440 blocks a day. The full historical scan the explorer once needed took 2.9
hours. It is still `0` in `dmt-indexer/src/config.rs` and the daemon warns loudly
when it is left there.

## Measured, not guessed

Run against a regtest node on 2026-Sep-06, scanning from height 1:

- **~17 blocks/sec**, about **4 RPC calls per block**.
- It correctly found and skipped 8 real **Divi Names** (type `0x05`) records
  already on that chain: envelope parsed, type recognised as not ours, no state
  touched. Ignore-never-destroy, on real data rather than a fixture.
- Two independent runs produced the **same fingerprint** at height 1000, which is
  the property the whole fingerprint design exists for.

The rate is dominated by one `getrawtransaction` round trip per transaction.
There is no way around that on this node: Divi's `getblock` takes a bool, not a
verbosity int, so it returns txids and nothing else. Connection pooling (one
agent, one connection) took it from ~11 to ~17 blocks/sec and, more importantly,
stops the scanner opening a fresh connection per call.

At that rate a backfill of the whole 4.1M-block chain would take days, which is
the strongest practical argument for setting the genesis height before launch
rather than after.

## Restarts

The daemon replays from `START_HEIGHT` on start. With a real genesis height that
is minutes, which is why no binary checkpoint of ledger state exists yet: it
would be a real amount of encoding to maintain, for a cost the genesis height
already removes. Worth revisiting only if a restart ever stops being cheap.

## Adding a protocol

Add its crate, route its record type in `Overlay::apply_block`, and append its
deltas with a tag byte. The fingerprint, the reorg window and the halt rules are
already shared, which is the entire point of this crate existing.
