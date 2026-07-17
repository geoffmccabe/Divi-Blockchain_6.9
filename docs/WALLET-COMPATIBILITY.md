# Divi Blockchain 6.9 ⇄ Divi Desktop 6.9 — Compatibility Contract

This node (`divid`) is supervised by the **Divi Desktop 6.9** wallet
(`geoffmccabe/Divi-Desktop-6.9`). This document is the shared contract so changes
on either side don't silently break the other. It lives in both repos.

## Status (2026-07-17)

The OpenSSL removal + toolchain modernization changed **only** internal crypto and
build dependencies. **Consensus, RPC, on-disk format, and daemon lifecycle are
unchanged by design.** A wallet-side compatibility review confirmed **10 of 11
integration points work with the modernized node unchanged**; the one item is a
wallet-side binary-selection fix (below), not a protocol break.

**The win:** the node now builds as a **native arm64 (Apple Silicon) binary** — the
wallet's Phase-9 gate is satisfied by this fork. The wallet should ship *this* `divid`.

## The node guarantees (invariants the wallet relies on)

- **C1.** RPC `getblockcount`, `getconnectioncount`, `getbestblockhash`, `getblock`,
  `getstakingstatus`, `stop` remain available over local JSON‑RPC 1.0, Basic‑auth,
  at `rpcport` (default 51473).
- **C2.** `getstakingstatus` returns booleans named exactly: `validtime`,
  `haveconnections`, `walletunlocked`, `enoughcoins`, `mintablecoins`, `mnsync`.
- **C3.** `getstakingstatus`'s `"staking status"` stays a JSON **boolean**.
- **C4.** Any RPC key the wallet consumes keeps its JSON **type** stable, not just its name.
- **C5.** The daemon writes `divid.pid` (default name) into the datadir on start and
  removes it on clean exit.
- **C6.** `debug.log` contains the literal line `Last shutdown was prepared: true|false`
  on every startup (the wallet's dirty-start detector).
- **C7.** `stop` triggers flush‑then‑exit; the daemon is safe to `stop`‑and‑wait and
  must **never** require SIGKILL. Flush window ≈ 9–13 s.
- **C8.** `-reindex-chainstate` and `-reindex` remain valid repair flags; fatal
  block‑db errors keep printing recognizable "corruption / Error loading block
  database" wording.
- **C9.** Datadir layout + default location (`DIVI` / `.divi`) and `divi.conf`
  (`rpcuser` / `rpcpassword` / `rpcport`) format are unchanged.
- **C10.** Consensus/network wire format is unchanged (numeric version stays 3.0.0.0).

## The wallet relies-on / must-do

- Never SIGKILL mid‑flush; always `stop` + wait (honor **C7**).
- **Prefer the bundled, verified fork binary** over any stray stock daemon — see the
  binary-resolution fix below. This is the one change needed to actually get the
  arm64 speedup.
- Treat the numeric version as consensus‑identical; gate "fast build" messaging on
  the **suffix** only.

## Version & release scheme

- Numeric/consensus version stays **3.0.0.0** (wire‑compatible with stock nodes).
- This fork sets `CLIENT_VERSION_SUFFIX = "-dd69.1"` (see `src/clientversion.cpp`), so
  `divid --version` / `getnetworkinfo.subversion` shows **`v3.0.0.0-dd69.1`** — the
  fork is identifiable without any protocol implication.
- Releases: tag `v3.0.0.0-dd69.N` and publish a GitHub Release with per‑platform
  `divid` binaries + a `SHA256SUMS` file. The wallet pins the expected suffix + hash.

## Wallet-side action list (tracked in Divi-Desktop-6.9)

1. Reorder `find_divid` (crates/supervisor `process.rs`) to prefer the bundled
   modernized binary; demote/remove the old Divi Desktop 2.0 path. *(Without this, an
   Apple-Silicon Mac with the old wallet installed keeps running the slow x86_64
   daemon under Rosetta — the arm64 win silently evaporates.)*
2. Bundle `divid` per target (Tauri sidecar/resource): `aarch64-apple-darwin` +
   `x86_64-apple-darwin` + Windows + Linux, sourced from this repo's release.
3. On startup read `getnetworkinfo.subversion`: accept `v3.0.0.0*`; **warn**
   (non-blocking) if the `-dd69.*` suffix is absent ("running a stock/unknown divid").
4. Verify each shipped `divid` SHA‑256 before exec.
5. Smoke-test the recovery ladder against a genuinely corrupt chainstate with the
   modernized binary (confirm C6/C8 wording matches).
