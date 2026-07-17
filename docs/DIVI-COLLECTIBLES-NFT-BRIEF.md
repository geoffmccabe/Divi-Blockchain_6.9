# Divi Collectibles (NFDs) — encrypted-Arweave collectibles on Divi (build brief)

**Naming (use consistently everywhere — guides, code, marketing):** these are
**NFDs** = **Non-Fungible-DIVI**, presented to users as **Divi Collectibles**.
The consensus opcode is **`OP_NFD`** (reserved in `docs/SOFTFORK-OPCODES.md`; the
chain workstream named the slot, the internals are yours). Wherever this brief
says "NFT" or "type 0x02," read it as NFD / OP_NFD.

**Audience:** a fresh Claude Code agent picking this up cold. Read this end to
end before writing anything. It is self-contained but points at the existing
Proof-of-Existence work, which you should mirror in style and reuse where noted.

**One-line goal:** a new "Divi Collectibles" panel in the Divi Desktop 6.9
wallet that mints, views, and transfers NFTs whose actual content lives
**encrypted** on Arweave and whose ownership + integrity is anchored on the Divi
chain via an **OP_META** record. Version 1 is **forkless** (no consensus change).

---

## 0. Context you inherit (already built — reuse, don't reinvent)

- **DVXP on-chain record envelope** — the shared format for putting small records
  in an OP_META output (Divi's OP_RETURN, opcode `0x6a`, up to 603 bytes,
  standard `nulldata`, forkless). Spec: `docs/POE-NFT-RECORD-FORMAT.md`.
  Layout: `magic "DVXP"(4) | version(1) | type(1) | body`. Type **`0x02` is
  reserved for NFTs — that's you.** Types `0x01` (Proof-of-Existence) and `0x03`
  (Merkle batch) are done and on-chain-proven.
- **Reference tools** in `contrib/poe/`: `poe_anchor.py` (single anchor),
  `poe_batch.py` (Merkle batch), `poe_index.py` (light chain indexer with a
  SQLite catalog + `lookup`). All build/sign/broadcast OP_META via
  `createrawtransaction` (Divi rejects the `"data"` output convention on some
  builds — the tools fall back to a raw OP_META script output; copy that
  pattern). `poe_index.py` needs the node run with `txindex=1`.
- **Wallet architecture (repo `geoffmccabe/Divi-Desktop-6.9`)** — Tauri v2
  (Rust supervisor + OS webview, ~10 MB), React 18 + Vite 5 + Tailwind 3 UI.
  The **Proof-of-Existence feature is your template** — copy its shape:
  - Rust logic module: `crates/supervisor/src/poe.rs` (pure hex + RPC, no file
    I/O; the UI hashes locally and passes only bytes it needs).
  - Tauri commands: `crates/app/src/main.rs` (`poe_timestamp`, `poe_verify`,
    each `async` + `spawn_blocking`; DTO structs live in the app crate, the
    supervisor returns plain structs).
  - Node config: `crates/supervisor/src/config.rs` — `NodeConfig::load()`,
    honors `DIVI_DATADIR` (point at a regtest node for testing).
  - Frontend: `ui/src/wallet/TimestampPanel.tsx` (+ `api.ts` typed boundary,
    `nav.ts` menu item, `icons.ts` icon, `Shell.tsx` router, `index.css`
    styles). New non-admin features must use the app's glass/animated styling.
  - RPC client: `crates/supervisor/src/rpc.rs` (`call(method, params)`).
- **Divi node capabilities** (see `reference` memory / earlier audit): no
  SegWit (so no Ordinals-style inscriptions), no `fundrawtransaction`; fund via
  `listunspent` + `createrawtransaction` + `signrawtransaction` +
  `sendrawtransaction`. Wallet keys live in the **node**, not the app. This
  matters a lot for the encryption design (§3).

---

## 1. The "superior NFT" thesis — and its honest limit

Normal NFTs point at a **public** image; anyone can right-click/scrape/copy it,
so the token and the art are effectively decoupled. Divi Collectibles stores the
content **encrypted** on Arweave; a random person browsing Arweave sees only
ciphertext. Only the current owner can decrypt and view the real thing.

**State this limit honestly in the product and to the user — do NOT over-claim:**
no cryptographic scheme can stop the *current owner* from decrypting and
re-sharing the plaintext (they hold the key by definition). What this design
buys is: (a) the content is not casually scrapeable by non-owners, (b) the
on-chain record proves authenticity/provenance and integrity, and (c) viewing
rights move with the token. Sell "not publicly scrapeable + provably authentic,"
never "impossible to copy."

---

## 2. How the pieces connect

```
   ┌─────────────┐   encrypt    ┌──────────────┐   upload    ┌───────────┐
   │  original   │ ───────────► │  ciphertext  │ ──────────► │  Arweave  │  (permanent,
   │  content    │  (AES-256)   │  + metadata  │  (bundler)  │  tx: AR_ID │   pay once)
   └─────────────┘              └──────────────┘             └───────────┘
                                                                   │ AR_ID (32 bytes)
                                                                   ▼
                                        ┌───────────────────────────────────────┐
   Divi chain (source of truth):        │ OP_META  DVXP type 0x02  MINT record   │
   ownership + integrity anchor    ────►│  arweave_ptr | content_hash | owner    │
                                        └───────────────────────────────────────┘
```

- **Arweave** holds the heavy, permanent bytes (the encrypted content + public
  metadata JSON). One-time payment, stored forever. Referenced by its 32-byte
  Arweave tx id.
- **Divi OP_META (type 0x02)** holds only the *anchor*: a pointer to Arweave, an
  integrity hash of the content, and an owner reference. Cheap, tiny, and the
  chain's timestamp doubles as a proof-of-existence for the mint.
- **The owner's Divi key** gates decryption (§3).

---

## 3. Encryption & transfer (the crux — get this right)

**Envelope encryption.** Encrypt the content once with a random symmetric
**content key** (AES-256-GCM). Then wrap (encrypt) that content key *to the
owner*. Transfer = re-wrap the content key to the new owner. The big file never
re-uploads on transfer; only the small key envelope changes.

**Where do owner keys come from without exposing the node's private key?**
The node holds the wallet keys and exposes `signmessage`/`verifymessage` but
**not** ECDH/decrypt. Recommended forkless approach — **sign-to-derive**:

1. The wallet asks the node to `signmessage(addr, "DIVI-COLLECTIBLES-KEY-v1")`.
   The signature is deterministic for that address and never leaves the machine.
2. Hash the signature → a 32-byte seed → derive an X25519 (or secp256k1-ECIES)
   **encryption keypair** bound to that Divi address. The node's real private
   key is never dumped.
3. The owner **publishes their encryption public key once** (small OP_META
   record, or in their Arweave profile, or an on-chain "key announce"), so
   senders can wrap content keys to them.

**Mint:** generate content key → AES-encrypt content → wrap content key to your
own derived pubkey → upload {ciphertext, wrapped-key, public metadata} to
Arweave → write the type-0x02 MINT record on Divi.

**Transfer to Divi address B:** look up B's published encryption pubkey →
decrypt the content key with your derived privkey → re-wrap it to B's pubkey →
publish a type-0x02 TRANSFER record (references the mint, names new owner,
carries the new wrapped key or an Arweave pointer to it). The indexer (§5)
replays mint+transfers to compute current ownership.

**Decision to escalate to Geoff (do not silently pick):** the alternative to
sign-to-derive is exporting the key via `dumpprivkey` and doing secp256k1-ECIES
directly — simpler but security-sensitive (raw key in app memory). Recommend
sign-to-derive; flag the tradeoff.

**Caveat to encode in the record:** transfer requires the recipient's published
encryption pubkey to exist. Design the "announce my key" step into onboarding.

---

## 4. The type `0x02` record(s)

Keep on-chain minimal; put rich data on Arweave. Fits easily in 603 bytes.

**MINT (subtype 0x01):**
| field         | size | meaning                                            |
|---------------|------|----------------------------------------------------|
| magic..type   | 6    | `DVXP` \| ver `0x01` \| type `0x02`                |
| subtype       | 1    | `0x01` = mint                                       |
| arweave_ptr   | 32   | Arweave tx id of the content bundle                |
| content_hash  | 32   | SHA-256 of the plaintext (doubles as PoE)          |
| flags         | 1    | e.g. encrypted-yes/no, media type hint             |

**TRANSFER (subtype 0x02):** references the mint txid + a pointer to the new
wrapped-key (Arweave) + new owner reference. Exact layout is yours to finalize;
document it in `docs/POE-NFT-RECORD-FORMAT.md` under type 0x02 (currently a
reserved stub) the same way types 0x01/0x03 are specified.

Ownership binding — **two models**, pick v1 deliberately:
- **v1 (recommended, forkless): signed-record + indexer.** Mint and transfer are
  OP_META records signed by the current owner; the indexer replays them to
  determine who owns what. Ownership is a convention the indexer enforces.
- **Future (stronger): UTXO-bound or a soft-fork NFT opcode.** Bind the token to
  a specific UTXO (spend = transfer, consensus-enforced), or add a native opcode
  (Geoff wants a "superior NFTs" opcode narrative later). Note as roadmap; don't
  block v1 on it.

---

## 5. Arweave integration (real dependency + a cost decision)

- **Upload:** Arweave stores permanently for a one-time fee. Direct uploads need
  AR tokens + an Arweave JWK wallet; **bundler services** (e.g. Turbo/ardrive,
  Irys) allow small uploads and paying in other currencies, often free under
  ~100 KB. Downloads are free from any gateway (`https://arweave.net/<AR_ID>`).
- **Read path:** fetch ciphertext by Arweave tx id from a gateway → decrypt
  locally with the derived key → display in-app only (plaintext never persisted
  unencrypted, never re-uploaded).
- **DECISION FOR GEOFF (flag, don't assume):** who pays Arweave and how?
  Options: (a) user supplies their own Arweave JWK; (b) Divi runs a funded
  bundler/relay so minting "just works" and Divi eats the tiny cost; (c) charge
  a small DIVI fee that backs a relay. Recommend starting with a bundler relay
  for a friction-free demo, user-supplied key as fallback.
- Keep Arweave access behind one Rust module boundary so the storage backend can
  be swapped (Arweave today, something else later) without touching the panel.

---

## 6. The wallet panel: "Divi Collectibles"

Mirror the Proof-of-Existence feature exactly (see §0). New pieces:

- **Nav:** add `{ id: "collectibles", label: "Divi Collectibles", icon: "collectibles" }`
  to `ui/src/nav.ts`; add an icon to `ui/src/icons.ts`; route in `Shell.tsx`.
- **Rust:** `crates/supervisor/src/collectibles.rs` (mint/transfer/list/decrypt
  helpers over RPC + Arweave + crypto), exposed as `async` Tauri commands in
  `main.rs` with app-crate DTOs. Put crypto in a small `crates/supervisor/src/
  crypto_nft.rs` (AES-256-GCM + the sign-to-derive keypair + wrap/unwrap).
- **Frontend panel** `ui/src/wallet/CollectiblesPanel.tsx` with views:
  - **My Collectibles** — grid of owned items; decrypt thumbnails locally.
  - **Create / Mint** — pick file + name/description → encrypt → upload →
    anchor → appears in the grid. (Reuse `TimestampPanel`'s file-picker +
    local-hash flow; you already have SHA-256-in-browser code to copy.)
  - **View** — full-size decrypted display, provenance (mint block/time from the
    indexer), Arweave link (shows it's ciphertext to outsiders).
  - **Transfer** — enter a Divi address → re-wrap key → publish transfer record.
  Use the glass-panel / AnimatedBackdrop styling (project rule: new non-admin
  features use the app's design system, never black-on-black).
- **Provenance/ownership** comes from extending `poe_index.py` (or a Rust port)
  to understand type-0x02 mint/transfer and expose "items owned by address X."

---

## 7. Suggested build phases (ship each, don't boil the ocean)

1. **Format + crypto core (offline, testable):** finalize the type-0x02 mint
   record; implement AES-256-GCM + sign-to-derive keypair + wrap/unwrap with
   unit tests (mirror `poe_batch.py selftest`). No chain, no Arweave yet.
2. **Mint on regtest, storage stubbed:** encrypt locally, "upload" to a local
   file standing in for Arweave, anchor the type-0x02 record on regtest, read it
   back. Proves the on-chain half end-to-end (like the PoE tools did).
3. **Real Arweave:** swap the stub for a real bundler upload/download behind the
   storage module. Decide funding (§5) with Geoff.
4. **Panel — My Collectibles + View:** indexer finds your mints; decrypt+display.
5. **Transfer:** re-wrap + transfer record; indexer computes current owner.
6. **Polish:** collections, metadata, error states, the "announce my key" step.

---

## 8. Open decisions to raise with Geoff (don't guess these)

1. **Encryption:** sign-to-derive (recommended) vs `dumpprivkey`-ECIES.
2. **Arweave funding:** Divi-funded bundler relay (recommended) vs user JWK vs
   DIVI-fee-backed relay.
3. **Ownership model for v1:** signed-record + indexer (recommended) vs
   UTXO-bound now.
4. **Opcode roadmap:** confirm the native-NFT soft-fork opcode is a *later*
   phase, not v1.

---

## 9. Guardrails (Geoff's standing rules — the new agent must follow)

- Work only in Geoff's repos (`geoffmccabe/*`); **never** push to
  `DiviProject/Divi` (`upstream`). Both repos are public but **no public
  notification / tags / releases** until Geoff says go.
- Never install unverified packages; treat any Arweave/crypto dependency with
  suspicion and verify it before adding. Prefer no-install / vetted crates.
- Geoff is **not a coder**: explain in plain English, no code dumps in chat,
  calibrated confidence (say what you KNOW vs EXPECT), commit+push after changes,
  and do risky/irreversible steps one at a time with confirmation.
- Security-first: this handles keys, encryption, and real value — get review on
  the crypto before shipping.
