# Divi overlay roadmap — DMT, NFD, and the DIVA registry

**Owner lane:** the overlay-scanner lane (Claude session `geoffreymccabe-55`).
**Status page:** https://claude.ai/code/artifact/208aa28f-f655-4ee3-b7cd-9d098059dedf
**Coordination:** `~/DIVI-OVERLAY-COORDINATION.md` — read that before touching
anything listed here, and add your lane to it.

Tokens (`0x04`), collectibles (`0x02`) and the DIVA bridge all ride the same
DVXP envelope, and they were all blocked on the same missing piece. One plan,
eight phases, dependency ordered.

---

## Phase 0 — clear the small blockers · DONE 2026-Sep-06

- Token panel no longer hangs on "Loading your tokens". `wallet_addresses`
  reaches the node over RPC with no deadline; a stopped or wedged node meant the
  list waited forever. Now gives up after 5s and renders without addresses.
  `Divi-Desktop-6.9/ui/src/wallet/dmt/TokenList.tsx`, commit `d287ba4`.
- `docs/INDEXER-ARCHITECTURE.md` corrected. It listed as "still to build" work
  that existed and passed tests.
- Scanner home settled: the chain repo, vendored outward.

## Phase 1 — the shared scanner · DONE 2026-Sep-06

New crate `contrib/dvxp-scan`, commit `326ef0417` on `feat/nfd-collectibles`.

| piece | what |
|---|---|
| `driver::Overlay` | Pure, no I/O. Drives every protocol over one pass. One combined tagged fingerprint, one 200-block undo window. A block applies completely or not at all. A halt is permanent. |
| `rpc` feature | Throttled node client. **One pooled connection**, because Divi allocates a node thread per application connection. |
| `store` feature | Atomic progress and sync state for readers. |
| `bin` | Catch up, follow the tip, detect reorgs by hash comparison, walk back to the fork point. |

Two defects fixed on the way:

1. `nfd-indexer` had **no undo log**, so a reorg left collectible ownership
   quietly wrong. It now records the inverse of every mutation and unwinds a
   block newest change first. 10 tests became 17.
2. The fingerprint covered **collectibles only**. Token state was invisible to
   the one value whose job is catching two indexers disagreeing. Now combined,
   each protocol's deltas tagged by record type. `dmt-indexer` gained
   `Chain::end_block_deltas` to expose its half.

**Verified against a live regtest node**, read-only: ~17 blocks/sec, ~4 RPC calls
per block, correctly found and skipped 8 real Divi Names (`0x05`) records without
touching state, and produced the same fingerprint on two independent runs.

**Measured constraint:** Divi's `getblock` takes a bool, not a verbosity int, so
it returns txids only and one `getrawtransaction` per transaction is unavoidable.
A full 4.1M-block backfill would take days. **Setting `GENESIS_HEIGHT` before
launch is therefore a schedule question, not tidiness.**

Not integration-tested: reorg *detection* against a live chain. Proving it means
invalidating blocks on a running node, which is Geoff's call.

## Phase 2 — the queryable store and one read API · DONE 2026-Sep-06

- **`events`** — the event log neither ledger keeps. They hold what is true now;
  history had nothing to read. Events are stored neutrally with a `from` and a
  `to`, never as "in" or "out", because which one it is depends on whose history
  is being asked for. Direction is derived per query.
- **`query`** — pure, so the wallet answers these from its own embedded indexer
  with no HTTP anywhere: balances, token metadata in batch, history, ticker
  status, mint terms, collectible ownership, collection members.
- **`api`** — a small read-only HTTP layer, hand-rolled with no framework
  because DD69 vendors this crate and has to build it standalone. Loopback by
  default. **Every response carries sync state, including the errors**, so a
  client cannot read an answer without the caveat attached.

Proven end to end in tests: issue a token, transfer part of it, burn some,
then read back balances, supply, and history from both sides. The same transfer
reads as an out for the sender and an in for the recipient. A rollback discards
the history with the block.

**Also fixed:** the daemon now refuses to start while the treasury address is the
all-zero placeholder. The token creation fee is checked against that address, so
in the placeholder state a payment to an address nobody controls satisfies it,
and an index against a real chain would record issuances that never paid.
`treasury_is_configured()` had existed all along and nothing called it.
`ALLOW_PLACEHOLDER_TREASURY=1` for regtest.

**Verified live** against the HRA lane's regtest node: caught up 3,320 blocks,
reported `trustworthy: false` while behind and `true` once current, then followed
new blocks as the miner produced them. All routes exercised, bad addresses and
non-GET refused.

**The wallet should not use the HTTP API at all.** DD69's CSP deliberately blocks
the webview from reaching any network address, including loopback, so all I/O
goes through Rust. The builds lane's first instinct was a Rust command proxying
to the indexer's HTTP port, but there is a better answer and it is why this crate
was built library-first: DD69 depends on `dvxp-scan` with
`default-features = false`, drives the driver in-process from the supervisor's
existing node connection, and calls `query::` directly. No second process to
install and supervise, no port, no proxy, and no CSP question. The HTTP API is
for the explorer and anything outside the wallet.

## Phase 3 — collectibles visible on scan.divi.love · NOT STARTED

- Thumbnails inline in block and transaction pages. The mint record already
  carries a 32-byte `thumb_ptr`, so no format change is needed.
- A thumbnail and collection cache, strictly a cache with the chain as authority,
  so an outage makes pages slower and never makes ownership wrong.
- Collectible detail, collection and creator pages; keyword search.
- Fill the four page shells already in `Divilovescan/src/collectibles/`.

## Phase 4 — the collectibles grid in DD69 · NOT STARTED

- **Reuse `ui/src/wallet/ImageGrid.tsx`** on `integration/all-features`, not the
  Community Apps grid. The builds lane has already built a data-agnostic grid
  there: user-selectable column count, double-click lightbox,
  `GridItem { thumb, full, title, subtitle, badge }`. Corrected on 2026-Sep-06
  after they flagged it; two grids would have been the wrong outcome.
- Replace the "coming soon" `CollectiblesPanel.tsx`.
- Views: what I own, a collection, keyword search, offered for sale.
- **Blocked sub-item:** "for sale" has no record type and no design. Open
  decision, see below.

## Phase 5 — token write path · NOT STARTED

- Payload encoders in `dmt-indexer` for issue, transfer, mint, name commit, burn,
  lock supply, issuer transfer. The crate owns encoding so the wallet cannot
  drift from the indexer.
- A validate-before-send check, answered locally before any DIVI is spent.
- A token module in the DD69 supervisor beside `names.rs` and `poe.rs`, reusing
  `dvxp.rs` for coin selection, signing and broadcast.
- Swap the stub data layer, enable Send and Create.

## Phase 6 — the registry root on DIVA · NOT STARTED

- Each epoch, publish one Merkle **root** over the collectibles registry to DIVA.
  Not the registry itself.
- Prove individual collectibles on demand against the root.
- **Never mirror availability.** It is the field that goes stale fastest, and a
  stale "available" is someone trading on a lie.
- Until the DIVA validator set exists this is one signer with the same trust as
  the coordinator. Build the format now, swap the signer later.

## Phase 7 — finish the bridge · NOT STARTED

Owned by the NFD/bridge lane, not this one. Three efforts have already converged
on it; read the three authoritative specs before writing any of it.

---

## Decisions still with Geoff

| decision | blocks | state |
|---|---|---|
| Treasury address | DMT ticker registration only | **Deliberately blank.** `treasury_is_configured()` refuses startup, so nothing leaks. |
| `GENESIS_HEIGHT` | any real scan | Still `0`. Needed before launch, see the Phase 1 measurement. |
| What "for sale" means | Phase 4's fourth view | On-chain listing record, or an owner-signed off-chain listing. |

## Working with the other lanes

`~/DIVI-OVERLAY-COORDINATION.md` is the live version of this. Two rules learned
the hard way on 2026-Sep-06:

- **DD69 `main` is a stale side branch.** `integration/all-features` is roughly
  97 commits ahead of it. Do not build from `main` and do not install over a
  running app: someone did exactly that today and wiped Divi Names out of Geoff's
  installed build. Commit, tell the builds lane, and let them fold it into the
  union build.
- **Only the builder bumps the version**, in `tauri.conf` and the hardcoded
  string in `Sidebar.tsx`, when a build actually ships.
