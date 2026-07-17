# Divi Blockchain 6.9

A modernization fork of [Divi Core](https://github.com/DiviProject/Divi) that brings the
node codebase up to date and adds a small set of new, high‑value capabilities —
without breaking compatibility with the live Divi network.

## What this is

Divi is a UTXO proof‑of‑stake chain (a Bitcoin → Dash → PIVX descendant). The current
core works and its consensus logic is sound, but the codebase is frozen on 2016‑era
dependencies and toolchain. Divi Blockchain 6.9 has three goals:

1. **A better codebase** — modernize dependencies and toolchain, remove dead/legacy
   code, strengthen tests and governance, so the node builds and runs cleanly on
   current systems (including Apple Silicon).
2. **A few new protocol features** — added the careful way, as backward‑compatible
   soft forks, using Divi's existing flag‑day activation mechanism.
3. **Two new applications built beside the chain** — permanent, private NFTs backed by
   Arweave, and a proof‑of‑existence (document timestamping) service.

## Design principles

- **The consensus core stays C++.** A live chain must validate bug‑for‑bug identically
  to every other node; a language rewrite of consensus would risk splitting the
  network. New tooling, apps, and indexers are built in **Rust**.
- **No unnecessary forks.** The modernization work keeps validation behavior
  byte‑for‑byte identical — it is a build/library refactor, not a consensus change.
  Features that genuinely need a fork are backward‑compatible soft forks, sequenced
  deliberately.
- **Overlay first, then protocol.** New application formats (NFTs, PoE) are proven as
  off‑chain conventions first, then promoted into native protocol support once the
  format is right.
- **Honest claims.** Where we describe security properties (e.g. private NFTs), we
  state what is actually true — *permanent and owner‑only*, not *uncopyable*.

## The two applications, in brief

- **Proof of Existence (PoE).** Anchor a SHA‑256 hash of any file on‑chain to prove it
  existed at a point in time. Divi's ~60‑second blocks confirm timestamps far faster
  than Bitcoin, and Merkle‑batching lets a single transaction timestamp many documents.
- **Permanent, private NFTs.** Media is encrypted to the owner's key and stored
  permanently on [Arweave](https://www.arweave.org/); the chain holds a compact record
  binding the storage pointer, an integrity hash, and ownership. Permanent (never rots)
  and private (only the owner can decrypt) — a genuinely different NFT.

## Status

Early / planning. The full plan is in **[docs/ROADMAP.md](docs/ROADMAP.md)**.

## Relationship to upstream

Based on [DiviProject/Divi](https://github.com/DiviProject/Divi) (MIT License). This fork
aims to remain a compatible node on the live Divi network throughout the modernization
work; new protocol features activate via Divi's existing time‑based fork mechanism.

## License

MIT (inherited from Divi Core).
