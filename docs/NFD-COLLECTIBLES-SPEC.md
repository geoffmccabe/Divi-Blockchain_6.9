# NFD / Divi Collectibles — technical spec (record format · crypto · OP_NFD internals)

Authoritative spec for the **NFD** (Non-Fungible-DIVI) feature, branded **Divi
Collectibles**. Companion to the onboarding brief
(`docs/DIVI-COLLECTIBLES-NFT-BRIEF.md`) and the opcode shape
(`docs/SOFTFORK-OPCODES.md`, chain workstream). This doc owns the parts the
chain workstream left to the NFD workstream: the record body, the crypto, the
ownership model, and the `OP_NFD` internals.

**Sequencing (decided with Geoff):**
- **v1 is forkless, built now** — NFD records ride in `OP_META` as DVXP **type
  `0x02`**. Nothing waits on a soft fork.
- **`OP_NFD` is designed in parallel** and supersedes the forkless wrapper later
  (smaller records, native indexing, native RPCs). Verifiers accept **both**
  forms forever. §5.

**Decisions locked (Geoff):** never expose the private key → **sign-to-derive**
(§3, validated: Divi `signmessage` is deterministic). Arweave paid by a
**Divi-funded relay** (§4). Naming: **NFD / Non-Fungible-DIVI / Divi
Collectibles / OP_NFD** everywhere.

---

## 1. Honest scope (put this in marketing too)

Encrypting the content on Arweave stops **casual scraping by non-owners** and the
chain proves **authenticity + provenance**. It does **not** make content
uncopyable — the current owner holds the key and can always decrypt and re-share.
Claim "not publicly scrapeable + provably authentic," never "impossible to copy."

---

## 2. Forkless record — DVXP type `0x02` (three subtypes)

Envelope (shared): `magic "DVXP"(4) | version 0x01 (1) | type 0x02 (1) | subtype(1)
| body`. One `OP_META` output per tx, ≤603 bytes, value 0. On-chain stays tiny;
all heavy data lives on Arweave.

### subtype `0x01` — MINT
| field         | size | meaning                                              |
|---------------|------|------------------------------------------------------|
| arweave_ptr   | 32   | Arweave tx id of the content bundle                  |
| content_hash  | 32   | SHA-256 of the **plaintext** (doubles as a PoE)      |
| flags         | 1    | bit0 encrypted · bits1-3 media class · rest reserved |

70-byte body. The mint tx's owner = the address of the input that funded it
(first mint owner); recorded by the indexer, not spelled out in the body.

### subtype `0x02` — TRANSFER
| field         | size | meaning                                              |
|---------------|------|------------------------------------------------------|
| mint_txid     | 32   | which NFD this transfers (the mint tx id)            |
| new_owner     | 20   | recipient (Divi address hash160)                     |
| wrapkey_ptr   | 32   | Arweave tx id of the content-key re-wrapped to recipient |

84-byte body. **Authorization:** the transfer tx must be *signed by the current
owner* — enforced by requiring an input spending a coin the current owner
controls, or (v1) an attached `signmessage` proof over `mint_txid|new_owner`.
The indexer replays mint→transfer→transfer… to compute the current owner.

### subtype `0x03` — KEY-ANNOUNCE
| field         | size | meaning                                              |
|---------------|------|------------------------------------------------------|
| enc_pubkey    | 32   | the address's **derived** X25519 encryption pubkey (§3) |

Published once per address so senders can wrap content keys to it. A recipient
who never announced can't receive a transfer — the wallet prompts this at
onboarding.

---

## 3. Crypto design (the security-critical part)

### 3a. Sign-to-derive — an encryption key from the wallet, without exposing it
1. Wallet calls `signmessage(addr, "DIVI-NFD-KEY-v1")`. **Verified deterministic**
   on Divi (same phrase → identical signature every time), so this is stable.
2. `seed = SHA-256(signature_bytes)`. Never leaves the machine; the node's real
   ECDSA private key is never dumped.
3. From `seed`: derive an **X25519** keypair (`enc_priv`, `enc_pub`) for wrapping,
   and via HKDF a per-purpose symmetric key when needed. `enc_pub` is what the
   KEY-ANNOUNCE record publishes.

Domain string is versioned (`-v1`) so we can rotate the derivation later.

### 3b. Envelope encryption (content never re-encrypted on transfer)
- **Mint:** random 32-byte **content key** `CK`; `ciphertext = AES-256-GCM(CK,
  plaintext)`. Wrap `CK` to the owner: self-wrap uses the owner's own `enc_pub`
  (so only they can open it). Upload `{ciphertext, wrapped_CK, public_metadata}`
  to Arweave; write the MINT record.
- **View:** re-derive `enc_priv` (sign-to-derive) → unwrap `CK` → AES-GCM-decrypt
  → display in-app only. Plaintext is never persisted unencrypted or re-uploaded.
- **Transfer:** owner unwraps `CK`, re-wraps it to recipient's announced
  `enc_pub` (X25519 ECDH → HKDF → AES-GCM key-wrap), uploads the small
  `wrapped_CK` to Arweave, writes the TRANSFER record. The big ciphertext is
  untouched.

### 3c. Vetted primitives only
AES-256-GCM, X25519, HKDF-SHA256, SHA-256 — all from audited libraries
(RustCrypto `aes-gcm` / `x25519-dalek` / `hkdf` in the wallet; no hand-rolled
crypto, no unvetted deps). Get a security review before shipping (Geoff rule).

---

## 4. Arweave (relay-funded)

- **Stored on Arweave per NFD:** `ciphertext`, `wrapped_CK`, and a small public
  metadata JSON (name, description, media type, thumbnail-of-ciphertext note).
- **Who pays:** a **Divi-funded relay/bundler** so minting "just works"; users
  never touch an Arweave wallet. The relay is one swappable Rust module boundary
  (Arweave today, another backend later) — the panel never talks to Arweave
  directly.
- **Read:** fetch by Arweave tx id from any gateway; decrypt locally. Downloads
  are free and gateway-agnostic.
- **Relay guards (build in):** rate-limit + size cap per mint, and require a
  valid draft MINT/DIVI-side check before the relay spends, so the funded pool
  can't be drained by spam. (Design detail for the relay service.)

---

## 5. `OP_NFD` internals (the opcode — designed here, implemented by chain wkstm)

Follows the shared shape in `SOFTFORK-OPCODES.md`: a provably-unspendable output
`OP_NFD <push: version(1) | subtype(1) | body>`, value 0, one per tx. Consensus
rule = **structural validity only**; all convenience lives in RPC + the built-in
index. The opcode drops the 4-byte `DVXP` magic (smaller records) and gives
native recognition + indexing (no external indexer, no `txindex`).

**Subtypes** carry the exact meanings from §2 (mint `0x01`, transfer `0x02`,
key-announce `0x03`), so the crypto/ownership logic is unchanged — only the
wrapper shrinks.

**Native RPCs (the "skip a step" for app builders):**
- `createnfd <arweave_ptr> <content_hash> [flags]` — fund+build+sign+broadcast a
  mint in one call → txid.
- `announcenfdkey <enc_pubkey>` — publish the address's encryption pubkey.
- `transfernfd <mint_txid> <to_address> <wrapkey_ptr>` — authorized transfer in
  one call (node checks current-owner authorization).
- `getnfd <mint_txid>` / `listnfd [address]` — native lookup / "what do I own",
  from the built-in index.

**Roadmap subtypes Geoff asked to explore** (optics + offload the frontend; add
only where the *consensus* rule stays minimal and the logic genuinely belongs
on-chain):
- **Loan / rental** (`subtype 0x04`): time-boxed grant of viewing rights without
  transferring ownership — node tracks an expiry the index enforces.
- **Escrow / offer** (`subtype 0x05`): a signed sell offer + atomic
  owner-change-on-payment, so a marketplace needs no custodian.

Each such subtype must be justified: keep the consensus check to "is this record
well-formed," and put matching/eligibility/UX in the RPC+index layer — never put
Arweave access or fetch/decrypt in consensus (impossible and unsafe).

**Dual-form (permanent):** the wallet's parser and the reference tools return
`{form: op_meta|op_nfd, subtype, body}` for both the DVXP-in-OP_META records and
the OP_NFD records, so forkless-v1 NFDs stay fully valid after activation.

---

## 6. Build order (NFD workstream)

1. **Crypto core (offline, Rust, tested):** sign-to-derive keypair + AES-256-GCM
   envelope + wrap/unwrap, with known-answer + tamper tests (mirror
   `poe_batch.py selftest`). No chain, no Arweave.
2. **Record codec + regtest mint (storage stubbed):** encode/parse the three
   type-0x02 subtypes; anchor a MINT on regtest, read it back (on-chain half
   proven, exactly as the PoE tools did).
3. **Arweave relay** behind the storage module; decide relay funding/guards.
4. **Wallet panel "Divi Collectibles":** My Collectibles + Mint + View (reuse the
   PoE panel's file-picker/local-hash flow and the app's glass styling).
5. **Transfer + key-announce:** re-wrap + TRANSFER/KEY-ANNOUNCE records; indexer
   computes current owner.
6. **OP_NFD migration:** dual-form parser; adopt `createnfd`/`getnfd`/… when the
   chain workstream ships the opcode.

## 7. Open items (raise before the relevant phase)
- TRANSFER authorization: input-spend proof vs attached `signmessage` proof — pick
  in Phase 5 (input-spend is stronger and maps to OP_NFD; signmessage is simpler).
- Relay economics/anti-abuse (Phase 3).
- Which two NOP slots the chain workstream assigns `OP_POE`/`OP_NFD` (their call).
