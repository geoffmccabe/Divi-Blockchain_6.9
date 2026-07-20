# NFD / Divi Collectibles — integration guide (for other projects)

**Who this is for:** agents/teams on *other* Divi projects — block explorers,
marketplaces, LW-SSO / access-gating, other wallets, analytics — that need to read,
display, verify, or gate on NFDs. It's self-contained; deeper specs are linked at
the end.

## What an NFD is

An **NFD** (Non-Fungible-DIVI), branded **Divi Collectibles**, is an NFT on the
Divi chain with three defining properties:

1. **Forkless.** Records ride in Divi's `OP_META` data output (OP_RETURN, opcode
   `0x6a`). No consensus change; nothing to activate. Old nodes relay/validate
   them as ordinary data outputs.
2. **Address-based ownership.** An NFD is owned by a Divi *address*, tracked by an
   overlay indexer replaying on-chain records — **never bound to a coin** (Divi is
   proof-of-stake; a coin-bound asset would be eaten by staking). Spending/staking
   your DIVI never affects your NFDs.
3. **Encrypted content + optional public preview.** The full-quality file is
   AES-encrypted and stored on **Arweave**; only the owner can decrypt it. The
   creator may also publish a small **unencrypted WebP thumbnail** (≤500px) anyone
   can display.

## On-chain wire format (what you parse)

Every overlay record shares the **DVXP envelope** inside the OP_META push:

```
scriptPubKey = OP_META(0x6a) PUSH(payload)
payload = "DVXP"(4 = 44 56 58 50) | version(1=0x01) | type(1) | body
```

Types: `0x01` PoE · `0x02` **NFD** · `0x03` PoE-batch · `0x04` DMT tokens.

> **Header is 6 bytes** (`magic|version|type`); the byte after is **type-specific**,
> NOT a universal subtype. NFD (0x02) and DMT (0x04) put a **subtype** there; PoE
> (0x01 / 0x03) puts **hashAlg** and distinguishes single vs batch by the *type*.
> A generic parser must not assume a subtype byte for every type. *(The shared
> `dvxp-core` currently hardcodes a 7-byte header with subtype — a known issue to
> reconcile with PoE; see `docs/DVXP-INTEGRATION-GUIDE.md`, which is the canonical
> shared-envelope guide.)*

Rules: unknown **version** → halt (don't guess); unknown type/subtype/malformed →
**ignore, never destroy** (no "burn"). Records are applied in block height, then
tx-index order.

### NFD (type `0x02`) bodies — lengths are EXACT (reject trailing bytes)

| subtype | body | fields |
|---------|------|--------|
| `0x01` MINT | 65, or 97 with a thumbnail | `arweave_ptr`(32) · `content_hash`(32) · `flags`(1) · `thumb_ptr`(32, only if flags bit1) |
| `0x02` TRANSFER | 85 | `mint_txid`(32) · `new_owner`(21 = shared packed addr) · `wrapkey_ptr`(32) |
| `0x03` KEY-ANNOUNCE | 32 | `enc_pubkey`(32 = X25519) |

- **flags**: bit0 `0x01` = encrypted · bit1 `0x02` = has public thumbnail.
- `arweave_ptr` / `thumb_ptr` / `wrapkey_ptr` are **32-byte Arweave tx ids**.
  Fetch a pointer: base64url-encode the 32 bytes → `https://arweave.net/<id>`.
- `content_hash` = `SHA-256(salt ‖ plaintext)` — NOT the bare plaintext hash (the
  salt is encrypted in the bundle for privacy), so you can't brute-match it to a
  known file.

## Determining ownership (for marketplaces / gating / SSO)

Replay NFD records in chain order:
- **MINT** → owner = the address that funded the mint tx's **`vin[0]`** (the
  record's "sender"). The NFD's id = the mint **txid**.
- **TRANSFER** of `mint_txid` → **only if** the tx's `vin[0]` address equals the
  current owner, set owner = `new_owner`; otherwise ignore (unauthorized).
- **KEY-ANNOUNCE** → records `enc_pubkey` for the sender address (needed to send
  someone a transfer).

The **normative implementation** is `contrib/nfd-indexer` (a `dvxp-core`
`RecordHandler`): `owner_of(mint_txid)`, `owned_by(address)`, `enc_pubkey_of(address)`.
Reuse it rather than re-deriving the rules. A per-block state fingerprint
(`F(n)=SHA256(F(n-1)‖height‖Δ)`) lets two indexers detect divergence.

> To gate access on ownership today: run the indexer and query `owned_by(addr)`.
> Once the `OP_NFD` soft-fork opcode ships, a native `listnfd`/`getnfd` RPC will
> make this a single node call (see `docs/SOFTFORK-OPCODES.md`).

## Displaying an NFD

- **Public preview:** if flags bit1 is set, `thumb_ptr` → an unencrypted WebP at
  `https://arweave.net/<id>` — display it directly. If no thumbnail, show a
  generic "locked" placeholder.
- **⚠ The preview is the creator's claim, not proof.** Nothing binds the thumbnail
  to the encrypted content; a creator could preview one thing and encrypt another.
  Authenticity is only enforced when the **owner** decrypts (hash check). Never
  present a preview as a guarantee of the underlying content.
- **The encrypted bundle** (`arweave_ptr`) is opaque without the owner's key —
  explorers/marketplaces cannot and should not try to show it.

## Fees / treasury (if you surface economics)

Fee-charging actions (NFD mint, etc.) add a normal output to a **public treasury
address** (configurable; disabled until set). Explorers see it as an ordinary
payment. The treasury is one HD wallet; its key never appears in any app. See
`docs/TREASURY-AND-FEES.md`.

## Decrypting (only relevant to a wallet acting AS the owner)

Third parties never decrypt. A wallet that owns an NFD derives its key by
**sign-to-derive**: `signmessage(addr, "DIVI-NFD-KEY-v1")` (deterministic on Divi)
→ SHA-256 → an X25519 keypair; the raw wallet key is never exposed. Content is
AES-256-GCM under a random key that's ECIES-wrapped to the owner. Full detail in
`docs/NFD-COLLECTIBLES-SPEC.md` §3.

## Roadmap (what to build against)

- **Done (forkless v1):** mint, view/decrypt, transfer (address→address),
  optional public thumbnail, treasury fees. Proven end-to-end on regtest.
- **Next:** a shared **chain scanner** (in `dvxp-core`) for automatic
  discovery/enumeration — turns transfers from a code-handoff into
  "enter address, send," and powers explorers without each running a full indexer.
- **Later:** `OP_NFD` **soft-fork opcode** — native recognition, built-in
  indexing, and native RPCs (`createnfd`/`getnfd`/`listnfd`/…). Records get
  smaller; verification no longer needs an external indexer. Backward-compatible;
  the forkless records stay valid forever, so **verifiers must accept both forms**.
- **Later:** marketplace (built on the ownership ledger + transfers).

## Where the code lives

- **Wallet (Rust/Tauri + React):** `geoffmccabe/Divi-Desktop-6.9`, branch
  `feat/nfd-collectibles`. Record codec `crates/supervisor/src/nfd_record.rs`;
  flow `collectibles.rs`; crypto `crypto_nfd.rs`; storage `nfd_storage.rs`.
- **Chain-side (indexer, shared core, specs):** `geoffmccabe/Divi-Blockchain_6.9`,
  branch `feat/nfd-collectibles`. `contrib/dvxp-core` (shared envelope/registry/
  fingerprint), `contrib/nfd-indexer` (NFD handler), `nfd-relay/` (Arweave uploader).

## Deeper specs
- `docs/NFD-COLLECTIBLES-SPEC.md` — full NFD spec (format, crypto, ownership, thumbnail).
- `docs/POE-NFT-RECORD-FORMAT.md` — the shared DVXP envelope.
- `docs/INDEXER-ARCHITECTURE.md` — `dvxp-core` + the handler model (shared with DMT).
- `docs/SOFTFORK-OPCODES.md` — the OP_POE / OP_NFD opcode plan.
- `docs/TREASURY-AND-FEES.md` — fee/treasury model.

**One coordination note:** NFDs (type 0x02) and DMT tokens (type 0x04) share the
`dvxp-core` envelope, indexer framework, and address-ledger model — build one
indexer with pluggable handlers, not two.
