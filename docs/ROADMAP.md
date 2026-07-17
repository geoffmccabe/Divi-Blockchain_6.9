# Divi Blockchain 6.9 — Roadmap

Three workstreams: modernize the codebase, add a few backward‑compatible protocol
features, and ship two applications beside the chain. Nothing here requires a hard fork.

---

## A. A better codebase (modernization — no consensus change)

The consensus core is sound and its signature verification already runs on the modern
`libsecp256k1` library. The work in this section keeps validation behavior byte‑for‑byte
identical — it is a build/library/hygiene refactor, **not** a fork.

1. **Modernize dependencies and toolchain.** Move off end‑of‑life cryptographic and
   networking libraries (OpenSSL, libevent) and get the node building cleanly on a
   current toolchain, including **Apple Silicon / arm64** native builds. *This is the
   #1 item — it also unblocks the native build for the Divi Desktop 6.9 wallet.*
2. **Remove dead code.** Delete legacy files that are no longer compiled but still sit
   in the tree containing stale copies of consensus logic.
3. **Retire the legacy alert subsystem** (removed from Bitcoin Core in 2016).
4. **Strengthen governance‑key handling.** Move network‑control keys toward
   multi‑signature / time‑locked custody rather than single hard‑coded keys.
5. **Strengthen finality.** Add recent checkpoints and revisit deep‑reorg / network‑
   partition recovery behavior.
6. **Harden proof‑of‑stake timing** against timestamp grinding.
7. **Expand test coverage** for governance and chain‑reorganization paths.
8. **Refresh network bootstrap** (seed nodes / snapshot infrastructure) to be
   independent of legacy hosting.

## B. New protocol features (backward‑compatible soft forks)

Added via Divi's existing time‑based ("flag‑day") activation mechanism, which was used
successfully for the August 2023 upgrade. Each is optional and sequenced deliberately —
every opcode is a permanent addition.

1. **Native data-record opcodes — `OP_POE` and `OP_NFD`.** Promote the already-working
   forkless records (the "DVXP" format) into consensus-recognized, natively-indexed
   first-class types. `OP_POE` anchors Proof-of-Existence; `OP_NFD` marks
   Non-Fungible-DIVI ("NFDs", branded **Divi Collectibles** — the encrypted-Arweave
   format, see C2). Ships with native RPCs (`createpoe`/`verifypoe`/`getpoe`/`listpoe`)
   and built-in indexing, which is the real convenience for app builders — no external
   indexer, no `txindex`. *(The opcodes provide recognition, structural validity, and
   indexing; the privacy/permanence come from the application design, not the opcode.)*
   Full spec: `docs/SOFTFORK-OPCODES.md` (`OP_POE` specified; `OP_NFD` reserved for the
   NFD workstream).
2. **Covenant support (OP_CTV‑style).** Enables clawback vaults and constrained‑spend
   patterns — a capability Bitcoin itself has not yet activated.
3. **Relative timelocks (CheckSequenceVerify).** Complements the absolute timelocks
   already present since 2023; a building block for payment channels.

## C. New applications (built beside the chain, in Rust — no fork)

### C1. Proof of Existence (PoE)

Timestamp any document by anchoring its SHA‑256 hash in a data output.

- Uses the chain's existing data‑carrier capability — no protocol change.
- Merkle‑batches many documents into a single on‑chain anchor (OpenTimestamps pattern),
  so cost stays flat regardless of volume.
- ~60‑second blocks confirm timestamps roughly an order of magnitude faster than Bitcoin.
- Can live directly inside the Divi Desktop 6.9 wallet as a "timestamp a file" feature.
- Optional: pay for anchoring in DIVI.

### C2. Permanent, private NFTs on Arweave

Solves two problems ordinary NFTs have: media that rots (dead links) and media anyone
can copy from a public gallery.

- **Permanent:** media is stored on Arweave (pay‑once, stored indefinitely) instead of
  a link that can break.
- **Private:** media is encrypted to the owner's key (ECIES / envelope encryption — a
  random content key encrypts the file, and that key is wrapped to the owner's public
  key). Only the key‑holder can decrypt.
- **On‑chain record:** a compact data output binds the Arweave pointer, an integrity
  hash of the stored content, and ownership.
- **Transfers:** because Arweave is immutable, a transfer publishes a fresh copy
  encrypted to the new owner and updates the on‑chain pointer.
- **Shared primitive:** the on‑chain content hash doubles as a proof‑of‑existence
  record — so PoE (C1) and NFTs are one system, not two.

**Honest security note.** Encryption stops casual scraping and makes media owner‑only,
and Arweave storage is genuinely permanent. It does **not** make media *uncopyable*: a
legitimate owner who decrypts and views the media can still capture it, and a past owner
retains whatever they decrypted while they held it. The accurate, defensible claim is
**"permanent and private,"** not "uncopyable."

### Build path

Each application is built **overlay‑first** — proven as an off‑chain format read by an
indexer and the wallet — and only later promoted into native protocol support (B1) once
the format is settled by real‑world use.

---

## Recommended sequence

1. **Codebase modernization** (dependencies/toolchain first).
2. **PoE application** — the fastest visible, fork‑free win.
3. **Encrypted‑NFT + Arweave application** (overlay implementation).
4. **Soft‑fork the native features** (NFT type, covenants, relative timelocks) once the
   application formats are proven.

---

*Design decision: the consensus node remains C++ for bug‑for‑bug network compatibility;
all new applications, tooling, and indexers are written in Rust.*
