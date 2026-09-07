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

**Worth adopting from Divi Names (suggested, not done):** that protocol has no
placeholder at all. Its treasury is an `Option<Address>`: either a real chosen
address, or `None`, and on `None` the indexer refuses to scan and the wallet
refuses to register. There is no state in which a payment to an uncontrolled
address satisfies a fee, because the unconfigured case cannot be represented as
an address. DMT's all-zero placeholder is a valid-looking `Address` that happens
to be nobody's, which is why a runtime guard was needed at all. Changing the type
would make the guard unnecessary rather than merely present. Confirmed with the
HRA lane 2026-Sep-06.

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

## Phase 3 — collectibles visible on scan.divi.love · BUILT 2026-Sep-06

`Divilovescan` commit `426310f`. The repo was unowned; this lane has taken it.

- **Thumbnails in block and transaction pages**, linking to the collectible and
  to the transaction that minted it. Renders nothing when a block contains
  nothing, which is almost every block. Needed two new index routes so a block
  page is one request rather than one per transaction in it.
- **Real pages**: a collectible (owner, provenance, collection, content
  fingerprint), a collection with its members and its enforced cap, and a list
  with search. Search is narrow on purpose: an id, an owner, or a collection.
  The chain carries no name, and matching off-chain metadata we have not fetched
  would return results the index cannot stand behind.
- **Every preview passes through `functions/api/nfd-image`**, never an `<img>`
  pointed at a gateway. This is the image cache asked for, and it is also the
  moderation choke point the plan requires: a blocklist is only enforceable if
  every image goes through one place. Four reasons, in the file.
- **Previews are labelled as the creator's claim** wherever they appear at a
  readable size. Nothing on-chain binds a preview to the encrypted content, so a
  page implying the picture IS the asset is where someone gets defrauded. That
  sentence lives in one component so it cannot soften.
- **The explorer's own scanner is gone**, replaced by a two-line shim around
  `dvxp-scan`. The daemon moved into the library so both hosts run the same loop.

**Not yet verified against real data.** No collectible has ever been minted, so
every page has been exercised against an empty index and by tests, not against a
real preview. The first mint is the real test.

**Ops still required before this is live:** the indexer must run beside the node
and be reachable through the tunnel, and `OVERLAY_ORIGIN` must be set in
Cloudflare alongside the existing `SCAN_ORIGIN`. Until then the explorer degrades
exactly as designed: block and transaction pages are unaffected, and the
collectibles pages say the index is unavailable.

**Found while re-vendoring:** `name-registry` was missing from the explorer's
`sync-crates.sh`, so its vendored crate set had quietly stopped building.
`dmt-indexer` gained that dependency when tokens and Divi Names started sharing
ticker rules, and nothing re-ran the script afterwards.

## Phase 4 — the collectibles grid in DD69 · DEFERRED by agreement

Not started, deliberately. Geoff has not asked for the collectibles gallery, so
building it now would be speculative. Agreed split with the builds lane for when
he does: **this lane owns the in-process data layer** (`dvxp-scan` with
`default-features = false`, driven from the supervisor's existing node
connection, exposed as commands over `query::`), **the builds lane owns the UI**
(`ImageGrid.tsx` and the wallet-side wiring). Neither reimplements the other's
half.

- **Reuse `ui/src/wallet/ImageGrid.tsx`** on `integration/all-features`, not the
  Community Apps grid. The builds lane has already built a data-agnostic grid
  there: user-selectable column count, double-click lightbox,
  `GridItem { thumb, full, title, subtitle, badge }`. Corrected on 2026-Sep-06
  after they flagged it; two grids would have been the wrong outcome.
- Replace the "coming soon" `CollectiblesPanel.tsx`.
- Views: what I own, a collection, keyword search, offered for sale.
- **Blocked sub-item:** "for sale" has no record type and no design. Open
  decision, see below.

## Phase 5 — token write path · HALF DONE 2026-Sep-06

Commit `71b430285`.

**Done, in the chain repo:**

- **Payload encoders** for every record type. Each is tested by parsing its own
  output back with the real parser, so the two halves provably agree.
- **`validate::dry_run`**, which applies a record to a *clone* of the ledger and
  reports what happened. Not a list of pre-flight checks: that would be a second
  copy of the rules, and a wallet promising acceptance while the ledger disagrees
  is worse than no check. `Verdict::explain()` returns a sentence for a person.
- **The whole stack proven on a real chain.** A throwaway regtest node, real
  records: issue 1000, transfer 300, burn 100, lock supply. Read back as supply
  900, locked true, issuer 600, recipient 300, with the same transfer showing as
  an out for one and an in for the other.

**Two defects that only a real chain could have found:**

1. **The scanner could not read any testnet or regtest address.** Mainnet version
   bytes only, so every sender failed to resolve, every record was skipped for
   having no sender, and the overlay was untestable off mainnet. Fixed.
2. **⚠ The coin-selection trap.** A record's sender is the address funding
   `vin[0]`. Ordinary coin selection picks a change address holding no tokens, so
   a well-formed record is mined, costs a fee, and is **ignored** with nothing
   said. The first run lost three of four records this way. **Coin selection for
   a token record must be constrained to the address that holds the tokens, and
   change must return to it.** Written down in `encode.rs` where whoever writes
   the send will read it.

   **There is already a fix in the tree.** `dvxp::select_coins(from)` in DD69's
   supervisor pins a coin at the author's address as the first input, returns
   change there, and errors rather than funding from elsewhere. The HRA lane
   wrote it after hitting this same trap in live Divi Names testing, so Names and
   PoE are both clear. The token module must call it rather than doing its own
   coin selection.

**The wallet half is now done too**, DD69 commit `a1e897d` on branch
`feat/dmt-tokens` off `integration/all-features`, agreed with the builds lane
before starting and Rust-only by their preference: the tokens panel still says
"preview only" and nothing user-visible changes until they wire it.

- `crates/supervisor/src/dmt.rs` beside `names.rs` and `poe.rs`. Six operations:
  create, send, airdrop, burn, lock supply, reserve a ticker. It contains **no
  record layouts and no coin selection**: bytes come from `dmt_indexer::encode`,
  and funding goes through `dvxp::broadcast_record` with `from` pinned, which is
  the Names lane's shared implementation rather than a token-only copy.
- `treasury_address()` returns an address or a refusal, never a placeholder,
  matching `names.rs`. That is what stops the wallet paying a fee to an address
  nobody controls while the compiled-in treasury is still zeroes.
- Six Tauri commands, appended to the handler list rather than inserted so the
  builds lane's edits stay a trivial merge. Amounts cross as strings.
- `dmt-indexer`, `nfd-indexer` and `dvxp-scan` vendored into `crates/`, with
  `sync-divi-crates.sh` extended to keep drift loud. `dvxp-scan` taken with
  `default-features = false`: no HTTP client, no listener.

**The read side is now built too**, DD69 `b079a6d`. `crates/supervisor/src/dmt_index.rs`
runs the wallet's own index over the chain it already has, in-process, no HTTP.

- It contains **no interpretation of any record**. The rules, ledger, reorg
  window and scanning loop are the vendored crates, shared byte-identical with
  the explorer. It supplies only block-fetching through the wallet's existing
  pooled connection. Keeping that the only difference is why `follow` was
  extracted in the chain repo (`a862c4dd2`): one scanning loop, two hosts.
- **Staking comes first.** 25-block slices, a pause between them, a longer pause
  once caught up, and the writer lock held for one slice only so a balance query
  waits milliseconds. The node it would starve is the one the user stakes with.
- `genesis_height()` **refuses on mainnet** rather than starting a scan it cannot
  finish, and says so in words. Test chains start at 0.
- `IndexStatus::trustworthy()` is what any UI must gate on: running, not halted,
  within two blocks of the tip.

**Verified on a live chain**, the one thing unit tests cannot cover: caught up to
the tip and read back all three test tokens through the same query layer the
explorer uses, with correct supplies, locked flags and histories.
`examples/dmt_index_smoke.rs` is that check, rerunnable.

**So the only thing still missing is the number.** With `GENESIS_HEIGHT` set, the
wallet can show balances as well as send. Without it, it refuses honestly.

## Phase 6 — the registry root · FORMAT BUILT 2026-Sep-06

Commit `d03f6c172`. Frozen format in `docs/NFD-REGISTRY-ROOT.md`, agreed with the
DIVA lane before anything was written.

**It closes a real gap rather than duplicating their bridge.** Their proofs
attest an *event*: a transaction is included under a block's Merkle root. That is
not enough to know a bridge lock was valid, because a malformed record, or one
sent by somebody who did not own the collectible, is still provably included.
Only the overlay rules decide whether ownership moved. This attests the
*interpreted result*, so DIVA does not have to run its own overlay indexer.

The two compose: transaction inclusion gives an immediate **provisional** answer,
the next root gives the **authoritative** one. That is the DIVA lane's framing and
it is why the epoch can be unhurried without the bridge feeling slow.

- **RFC 6962**, so Certificate Transparency verifiers are the prior art. ⚠ **Not**
  OpenZeppelin's `MerkleProof`, which uses keccak, sorted-pair hashing and no
  domain tags, and would silently be the wrong verifier. Not asserted: mine
  builds bottom-up, the RFC is defined top-down, and a test checks the two agree
  for every leaf count from 1 to 64.
- Domain-separated leaves and nodes; an unpaired node is **promoted, never
  duplicated** (CVE-2012-2459).
- What is signed is a **header**, not a bare root: tag, epoch, height, leaf count,
  root. A bare root cannot be bound to a moment, and an old root presented as
  current verifies perfectly against its own proofs.
- Epoch by **block-height modulus**, never wall clock. Hourly, configurable. A
  verifier binds to the published **height**, never an assumed schedule, which is
  what makes configurability safe.
- Collectibles only. Fungible tokens move by a different mechanism and would
  churn the tree for no benefit.

**Still theirs, and not started:** publishing a root, who signs it, the validator
set. Until POAS exists a signed root has the same trust as a coordinator
signature, so this is "the format is ready", never "it is decentralized".
**Nothing publishes roots yet, so this is a format and a library, not a running
system.**

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
