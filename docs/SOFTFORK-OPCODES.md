# Soft-fork opcodes: OP_POE and OP_NFD

Expands section B of `ROADMAP.md`. Two backward-compatible opcodes that promote
the already-working forkless records (the "DVXP" format,
`docs/POE-NFT-RECORD-FORMAT.md`) into consensus-recognized, natively-indexed
first-class citizens:

- **`OP_POE`** — Proof of Existence anchors. **Fully specified here** (this is the
  chain/PoE workstream).
- **`OP_NFD`** — Non-Fungible-DIVI ("NFDs", branded **Divi Collectibles**).
  **Reserved and named here; the NFD workstream owns its body and semantics.**
  See `docs/DIVI-COLLECTIBLES-NFT-BRIEF.md`.

## What an opcode here does — and does not

An opcode is a rule the network runs while validating transactions; it must be
deterministic and offline (every node computes the same result without touching
the internet). So these opcodes **mark and structurally validate a data record**;
they do **not** "read" or "fetch" anything, and cannot verify a document's
meaning. Concretely:

- **Create** is real: the anchor output *is* the opcode + the record.
- **Read / enumerate** is not an opcode — it's a node/wallet query. We deliver it
  as native RPC + built-in indexing (below), which is the actual developer win.
- **Verify** (does hash X sit in block at time T) is done by anyone off-chain;
  the opcode just guarantees the record is well-formed and easy to find.
- **`OP_NFD` cannot reach Arweave.** It can only carry/standardize an Arweave
  pointer in a recognized shape. All fetch/decrypt stays in the wallet.

The value delivered: native recognition, enforced structural validity, built-in
indexing (no external indexer, no `txindex`), smaller records (the opcode
replaces the 4-byte "DVXP" magic), and a credible branded protocol feature.

## Output shape (both opcodes)

A **provably-unspendable** output (like `OP_RETURN`), beginning with the new
opcode byte, followed by a single push of a compact body:

```
scriptPubKey = OP_POE  <push: version(1) | subtype(1) | 32-byte digest>
scriptPubKey = OP_NFD  <push: version(1) | subtype(1) | body...>        (NFD workstream)
```

Value 0, dust-exempt, one such output per transaction. Because the output is
unspendable, no node ever executes the opcode during a spend — which is exactly
what makes the soft fork safe (see activation).

### OP_POE body (this workstream)
| field   | size | meaning                                             |
|---------|------|-----------------------------------------------------|
| version | 1    | `0x01`                                              |
| subtype | 1    | `0x01` = single anchor · `0x03` = Merkle batch root |
| digest  | 32   | SHA-256 doc hash (single) or RFC 6962 root (batch)  |

34 bytes of body — smaller than the 39-byte forkless DVXP record, since the
opcode itself replaces the magic. `subtype` carries forward the exact meanings of
DVXP types 0x01/0x03, so the single/batch logic and the RFC 6962 Merkle
construction (`contrib/poe/poe_batch.py`) are unchanged — only the wrapper is.

## Native RPCs (the real "skip a step" for app builders)

Shipped with the opcode; these are where front-ends save work. Because the node
recognizes `OP_POE` outputs, it maintains its **own index** of them — so none of
this needs the external `poe_index.py` or `txindex=1`.

- `createpoe <hash> [batch=false]` — fund + build + sign + broadcast an OP_POE
  anchor in one call; returns the txid. (Replaces the four-step
  listunspent/createraw/sign/send dance.)
- `verifypoe <txid> <hash>` — returns `{matched, confirmations, blocktime}`.
- `getpoe <hash>` / `listpoe [fromHeight]` — native lookup / enumeration from the
  built-in index.

(The NFD workstream defines its own `createnfd` / `getnfd` / … — named, not
specified here.)

## How the soft fork activates (and why it's safe)

- **Opcode slots.** Divi already redefined `OP_NOP9/OP_NOP10` into
  `OP_LIMIT_TRANSFER` / `OP_REQUIRE_COINSTAKE` (`divi/src/script/opcodes.h`), so
  the NOP-redefinition path is proven here. Free slots for `OP_POE` and `OP_NFD`:
  `OP_NOP1` (0xb0) and `OP_NOP3`–`OP_NOP8` (0xb2–0xb7). Pick two; record the
  choice in `opcodes.h`.
- **Activation.** Use Divi's existing time-based ("flag-day") activation — the
  same mechanism used for the August 2023 upgrade (see `ROADMAP.md` B).
- **Why no chain split.** The outputs are unspendable, so **old nodes never
  execute the new opcode** — they accept blocks containing these outputs exactly
  as they do any unspendable data output. New nodes *add* meaning after
  activation: they enforce the record is well-formed and index it. Old nodes lose
  nothing and stay in consensus; this is a true soft fork (a tightening, not a
  break).
- **Standardness first.** Before activation, relay `OP_POE`/`OP_NFD` outputs as
  standard so they propagate; enforce structural-validity as a consensus rule at
  the activation height.

## Migration from the forkless records

The forkless DVXP-in-OP_META records (types 0x01/0x03) that exist today stay
**valid forever** — nothing is invalidated. After activation, apps can emit the
smaller `OP_POE` form. **Verifiers must accept both**: the reference tools
(`contrib/poe/poe_anchor.py`, `poe_batch.py`, `poe_index.py`) and the wallet's
`poe.rs` should recognize the OP_META form *and* the OP_POE form. Recommend a
shared parser that returns `{form, subtype, digest}` for either.

## Honest caveats (say these plainly in marketing too)

1. The opcode formalizes and eases PoE; it does not change the trust model — the
   proof is still "this hash was in a block at time T," nothing more.
2. `OP_NFD` standardizes an NFD/Arweave record; it cannot make content
   uncopyable and cannot touch Arweave. The privacy/permanence come from the
   application design (encryption + Arweave), not the opcode.
3. Every opcode is permanent consensus surface — keep the consensus rules minimal
   (structural validity only) and put all convenience in the RPC/index layer.

## Build order (chain/PoE workstream)

1. Allocate `OP_POE` (+ reserve `OP_NFD`) in `opcodes.h`; define the unspendable
   output template + structural-validity rule (behind the activation flag).
2. Built-in index of `OP_POE` outputs; the `createpoe`/`verifypoe`/`getpoe`/
   `listpoe` RPCs.
3. Dual-form support in the reference tools + `poe.rs`.
4. Wire activation into the flag-day mechanism; regtest end-to-end
   (anchor via `createpoe` → mine → `verifypoe`/`getpoe`), mirroring the forkless
   proof already done.
5. Tests for structural validity, activation boundary, and old-node acceptance.

`OP_NFD` internals (body layout, mint/transfer, ownership) are the NFD
workstream's — this doc only nails down the shared shape and the reserved slot.
