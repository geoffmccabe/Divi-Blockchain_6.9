# Workstream A1 — OpenSSL & Toolchain Modernization

**Status:** starting · **Priority:** #1 (also unblocks the native arm64 build for
Divi Desktop 6.9) · **Fork impact:** none — validation behavior stays byte‑for‑byte
identical.

## Goal

Get the node building cleanly on a current toolchain (including Apple Silicon / arm64)
by removing the end‑of‑life OpenSSL and other frozen 2016‑era dependencies — **without
changing what the node considers a valid block or transaction.**

## Key findings that shape the plan

- **Consensus is already safe from this work.** Signature *verification* runs on the
  bundled `libsecp256k1`, not OpenSSL. So updating/removing OpenSSL cannot change which
  blocks are valid — this is a build/library refactor, not a consensus change.
- **In‑tree replacements already exist.** The `crypto/` directory already contains
  SHA‑256, SHA‑512, RIPEMD‑160, HMAC, and AES implementations. Almost everything OpenSSL
  is used for here has an in‑house equivalent already present.
- **The realistic end state is: no OpenSSL at all** — the same path Bitcoin Core took.
- **Qt can be dropped.** The daemon (`divid`) and CLI (`divi-cli`) build independently of
  the Qt GUI. Because Divi Desktop 6.9 replaces the desktop GUI, we build daemon + CLI
  only and remove the entire Qt dependency.

## Where OpenSSL is used today (and its replacement)

| Site | Use | Replacement |
| --- | --- | --- |
| `ecwrapper.*`, key signing | legacy OpenSSL EC signing | `libsecp256k1` (verification already uses it) |
| `crypto/scrypt.cpp` | SHA‑256 primitive | in‑tree `crypto/sha256` |
| `bip38.cpp`, `crypter.cpp`, `bip39.cpp` | wallet key encryption (AES/KDF) | in‑tree `crypto/aes` + HMAC KDF |
| `random.cpp`, `init.cpp` | RNG seeding | OS CSPRNG / in‑house RNG |
| `allocators.h` | secure memory wipe (`OPENSSL_cleanse`) | in‑house `memory_cleanse` |
| `db.cpp`, `util*`, `rpcdump.cpp` | misc glue | in‑tree / standard library |

None of these sit in the consensus signature path (already `libsecp256k1`); hashing that
*is* consensus‑relevant uses standardized algorithms whose output is identical across any
correct implementation.

## Phases

### Phase 1 — Build baseline & regression harness (do this first, change nothing)
- Reproduce a current build via the `depends` system; capture exactly where it fails on a
  modern toolchain / arm64.
- Stand up a **regression baseline**: a node that syncs and validates the live chain.
  Every later change must reach the **same chain tip** and accept the **same blocks** as
  this baseline. This is how we prove "no fork."

### Phase 2 — Confirm the OpenSSL inventory
- Verify the table above against the code; flag any consensus‑adjacent use before touching it.

### Phase 3 — Remove OpenSSL, behavior‑identical
- Migrate EC signing to `libsecp256k1`; retire `ecwrapper`.
- Repoint hashing/AES/HMAC/RNG/secure‑wipe to the in‑tree `crypto/` equivalents.
- Remove OpenSSL from the build once no references remain.
- After each step: rebuild and re‑validate against the Phase 1 baseline.

### Phase 4 — Modernize the rest of the toolchain
- Replace the release‑candidate libevent with a current stable release.
- Add **arm64 / Apple‑Silicon host support** to the `depends` system.
- **Drop Qt** (build daemon + CLI only).
- Bump remaining `depends` packages to current, compiler‑clean versions.

### Phase 5 — Prove behavior unchanged
- Full reindex‑and‑revalidate of the chain with the modernized node.
- Confirm identical acceptance vs the Phase 1 baseline; cross‑check on testnet.

## Success criteria

1. `divid` + `divi-cli` build from source on a current toolchain, native arm64 included.
2. OpenSSL is gone from the dependency set.
3. The modernized node reaches the same chain tip and accepts the same blocks as an
   unmodified node — verified, not assumed.
