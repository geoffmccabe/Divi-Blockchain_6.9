# Treasury & fees — shared model for all Divi apps

**Audience:** the NFD, DMT, PoE/chain, and DD69/Lovenode wallet workstreams. Every
feature that charges a fee (PoE anchor, NFD mint, DMT ticker/issue, …) follows
this so fees land consistently and the design stays safe to open-source.

## The one principle

**Security lives in the key, not in hiding the code.** Every serious crypto
wallet is open-source and safe because the private key protects the funds, never
code secrecy (Kerckhoffs). So publishing these apps — including the admin panel —
is fine, *provided the treasury key never appears in the code, the repo, or the
shipped app.*

## Two sides, very different risk

### Receiving fees — 100% safe, and a transparency win
- Fees are paid **to treasury addresses**. Addresses are public by nature; a fee
  output specifying a destination needs **no secret**.
- So treasury **addresses and fee amounts belong in open config** — anyone can
  audit that fees go where we say. That's a trust asset, not a weakness.
- One HD wallet (one seed) derives a **separate address per fee type / per app**.
  The seed is the single crown jewel; addresses derived from it are public.

### Spending the treasury — the guarded side
- Spending requires the **treasury private key**, which lives **only on the
  founder's own wallet instance**, behind his passphrase. It is never bundled,
  committed, or shipped.
- A "superadmin password" gate in open-source code is **cosmetic only**: someone
  could delete the check, but the admin panel on their copy is empty because the
  key isn't there. Real "only I can send" = only the founder's machine holds the
  key. **Never treat the UI gate as the security boundary.**

## Hard rules (do / don't)

- **DO** keep treasury addresses + fee amounts in open config (per app).
- **DO** default a fee to **0 / disabled until an address is configured**, so a
  misconfigured build never sends fees to a wrong/empty address.
- **DON'T** hardcode or commit any key/seed — not in code, config, or a "secret"
  file.
- **DON'T** ship the encrypted treasury key to users (offline-brute-forceable).
  The founder imports it only on his own instance.
- **DON'T** rely on a client-side admin check as the lock.

## Treasury hardening (recommended)
- Prefer a **hardware wallet** for the treasury seed (key never touches the app).
- Longer term, a **multisig** treasury (e.g. 2-of-3) so one leaked key isn't fatal.
- **Sweep to cold storage** periodically; don't leave large balances hot.
- **Back up the seed/passphrase** — "only I can send" also means "only I can lose it."

## Fee-collection mechanics (how each feature charges)

A fee is just an **extra output to the treasury address** on the same
transaction that anchors the record. Concretely (NFD reference impl,
`crates/supervisor/src/collectibles.rs`):

- Config (public): `treasury_address` + a per-action fee (e.g. `nfd_mint_fee`),
  read from a persisted config, default **0/disabled**.
- When configured, the action's tx adds `{ treasury_address: fee }` alongside the
  OP_META record + change. No key needed — it's a normal payment output.
- Each workstream wires its own fees the same way (PoE anchor fee, DMT ticker fee,
  DMT issue fee), reading its amount + the shared treasury address from config.

## Server components (the exception)
Desktop wallets (DD69, Lovenode) are clean because the key is local. Anything on
a **server** — e.g. the Arweave uploader (`nfd-relay/`), which holds a *spending*
key to pay for storage — must enforce access **server-side** (not client-side)
and guard its key with the same discipline (off git, restricted perms, funded
pool watched). That key pays Turbo/Arweave; it is not the treasury key.

## Admin surfaces (DD69)
- **Payouts tab** — shows the configured fee rows (per action: amount + treasury
  address) so fees are trackable; superadmin can set them. Reads/writes the fee
  config; never touches keys.
- **Arweave tab** — shows the uploader's Turbo balance and offers top-up (card via
  Turbo's hosted checkout / API). Operational, not treasury.
- Both are gated superadmin UX; the real control remains key possession.
