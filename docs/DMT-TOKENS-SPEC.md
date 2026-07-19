# Divi Meta Tokens (DMT) — technical specification

**DMT** is Divi's general-purpose token layer: fungible tokens of any kind —
divisible currencies, indivisible units (tickets, passes, credits, vouchers,
licences, points), collectible fungibles, community/meme coins. It is
deliberately **not** specialised to any one category; divisibility, supply
policy, pricing and transferability are per-token settings chosen at issuance.

The name is literal: these tokens live in Divi's **OP_META** output (Divi's name
for `OP_RETURN`, opcode `0x6a`). Meta Tokens are metadata records the Divi chain
carries and orders permanently.

**Status:** design locked, unimplemented. **Requires no fork of any kind.**

Companion documents:
- `docs/POE-NFT-RECORD-FORMAT.md` — the shared DVXP envelope (types 0x01/0x03).
- `docs/NFD-COLLECTIBLES-SPEC.md` — NFDs / Divi Collectibles (type 0x02).
- `docs/SOFTFORK-OPCODES.md` — OP_POE / OP_NFD; the OP_DMT request is in §12.

---

## 1. The decision that shapes everything: address balances, not coin-bound

**DMT balances are held against a Divi address, like an account. Tokens are
never bound to a particular coin.**

Every token protocol on Bitcoin — colored coins, Ordinals, Runes — binds assets
to specific UTXOs. On Divi that design is **uniquely and severely unsafe**, and
this was verified against Divi's own source rather than inferred:

- Divi is proof-of-stake. `CWallet::SelectStakeCoins` (`divi/src/wallet.cpp`)
  continuously asks for spendable coins, and a **coinstake transaction consumes
  them**. The wallet does this automatically, forever, as its normal job.
- The only protection is `lockunspent`. It *does* work on the staking path —
  the lock filter in `divi/src/AvailableUtxoCalculator.cpp` is applied for
  `STAKABLE_COINS`, not merely for ordinary sends.
- **But the lock set is memory-only.** It is a plain in-memory member
  (`divi/src/wallet.h`), and nothing in `divi/src/walletdb.cpp` persists it.
  **Every restart, crash or upgrade clears it.**

So on other chains the hazard is a careless user; on Divi the *wallet itself*
would spend the asset overnight, and the one guard rail resets on every restart.
Worse, coin-protection flags are wallet-local, so restoring the same seed into
different software loses them silently.

With address balances the entire class of problem does not exist. Staking
consumes coins; tokens are not in coins. There is nothing to protect, nothing to
remember, and no seed-restore hole. This also deletes the coin-protection
workstream, which is the most error-prone part of every other implementation.

**Consequences (binding on all future work):**
- Never ship a "the token *is* this coin" mode on Divi.
- A future `OP_DMT` must also remain address-based.
- Authorising a transfer requires spending a coin from the sending address, so a
  token-holding address needs a small DIVI reserve. This is a "cannot send right
  now", **never** a loss; wallets must maintain the reserve automatically.

### 1.1 What this costs — stated honestly

Address balances do not compose with single-transaction coin swaps. That is a
real cost, and §10 addresses it. It is accepted deliberately: an unusable-but-
elegant trade primitive is worth less than not destroying users' assets.

---

## 2. Trust model — say this plainly, including in marketing

DMT is an **overlay**. The Divi chain **carries and orders** the records
permanently and immutably; **software interprets** them into balances. The
network does **not** validate token rules, and no opcode can change that (§12).

- Accurate: *"permanently recorded and ordered by the Divi chain."*
- **Not** accurate: *"the network enforces it."*

This is the same honesty standard set for NFDs ("permanent and private", not
"uncopyable"). Only a full consensus ledger (§12.3) would earn the stronger
claim, and that is explicitly out of scope for v1.

The practical limits that follow: two indexers that disagree produce two
realities and proof-of-work cannot arbitrate; and a lightweight wallet can never
verify its own balance, because proving nobody moved a token earlier means
proving an absence, which a data record cannot do. §9 mitigates; it cannot cure.

---

## 3. Envelope

DMT uses the existing **DVXP** envelope in an **OP_META** output — Divi's
`OP_RETURN`, opcode `0x6a` — with no consensus change.

```
scriptPubKey = OP_META(0x6a)  PUSHDATA(payload)
```

| field   | size | value                          |
|---------|------|--------------------------------|
| magic   | 4    | `"DVXP"`                       |
| version | 1    | `0x01`                         |
| type    | 1    | `0x04` (DMT)                   |
| subtype | 1    | see §5                         |
| body    | var  | subtype-specific               |

Coexists with PoE (0x01), NFD (0x02) and PoE-batch (0x03).

**Size.** `MAX_OP_META_RELAY` is 603 bytes measured over the **whole script**
(`divi/src/script/standard.cpp`), so usable payload is **~599 bytes** after the
opcode and push-length bytes — about 592 bytes of body. This is ~7.5x Bitcoin's
carrier, and **capacity is not a constraint**: a transfer entry costs ~24 bytes,
so ~24 recipients fit in one transaction, and an issuance costs ~33 bytes.

**One data output per transaction** is enforced at
`divi/src/MempoolConsensus.cpp` ("only one OP_META txout is permitted"). This is
relay policy, not consensus. DMT needs only one, so it is never a limitation.
**Exactly one DMT record per transaction; if a transaction somehow carries more,
only the first is processed and the transaction is otherwise ignored.**

---

## 4. Identity

### 4.1 Sender

The sender is the address that funds **input 0** (`vin[0]`) — i.e. the address
of the output that input 0 spends. Chosen because it is deterministic, cheap
(one prevout lookup, no scan of all inputs), and unambiguous.

Divi has **no SegWit**, so the txid-ambiguity failures that forced Counterparty
into two separate consensus fixes cannot occur here.

If input 0 does not resolve to a P2PKH or P2SH address, the record is **ignored**
(§8). Signing is implicit: only the key holder can spend that input.

### 4.2 Addresses in payloads

21 bytes: 1 type byte (`0x00` P2PKH, `0x01` P2SH) followed by the 20-byte hash.
Recipients are carried **in the payload**, not as transaction outputs — so a
transfer needs no dust output, no output ordering discipline, and nothing that
could ever be spent by staking.

### 4.3 Token IDs

A token's permanent ID is the pair **(block height, transaction index within
that block)** of its issuance, encoded as two varints. Deterministic, compact
(2–4 bytes), assigned by chain position, no registry needed, and impossible to
collide.

Tickers (§7) are a human-facing alias; the ID is canonical. **All references in
records use the ID, never the ticker.**

### 4.4 Integers

All variable-length integers are **LEB128 unsigned varints**. Amounts are always
integers in the token's smallest unit; divisibility is display-only (§6.1).
Maximum representable supply is 2^64−1 smallest units; issuance exceeding this
is invalid.

---

## 5. Subtypes

### 5.1 `0x01` — ISSUE

Creates a token. Must reveal a prior NAME COMMIT (§7).

| field         | size | notes                                              |
|---------------|------|----------------------------------------------------|
| flags         | 1    | see below                                          |
| decimals      | 1    | 0–8; **0 = indivisible** (tickets, passes, units)  |
| ticker_len    | 1    | 3–8 (§7.2.1)                                       |
| ticker        | var  | ASCII `A–Z`, `0–9`, `!#^-_+.`; first char `A–Z`     |
| salt          | 20   | reveals the commitment                             |
| premine       | var  | units credited to the issuer (may be 0)            |
| cap           | var  | *(open-mint only)* total mintable, 0 = unlimited   |
| per_mint      | var  | *(open-mint only)* units per claim, must be > 0    |
| height_start  | var  | *(open-mint only)* 0 = immediately                 |
| height_end    | var  | *(open-mint only)* 0 = no end                      |
| mint_price    | var  | *(open-mint only)* duffs of DIVI per claim; 0 = free |
| price_step    | var  | *(if flagged)* added to `mint_price` per claim made |
| metadata_ptr  | 32   | *(if flagged)* Arweave tx id                       |

**Flags**

| bit  | meaning                                                          |
|------|------------------------------------------------------------------|
| 0x01 | open mint — anyone may claim (§5.3)                              |
| 0x02 | supply locked at issue — issuer can never mint again             |
| 0x04 | metadata pointer present                                         |
| 0x08 | **non-transferable** — only the issuer may send; holders cannot  |
| 0x10 | issuer may mint later (mutable supply)                           |
| 0x20 | mint proceeds are **burned**; unset = paid to the issuer address  |
| 0x40 | **rising price** — `price_step` present (§6.3)                    |
| rest | reserved; **must be zero** in version 0x01                       |

`0x02` and `0x10` are mutually exclusive; both set is invalid. `0x08` exists for
tickets, credentials, memberships and non-tradable points. `0x20` and `0x40`
are meaningful only with `0x01` (open mint); set otherwise, the record is
ignored.

**Metadata** reuses the NFD storage layer exactly — a 32-byte Arweave pointer,
same relay, same fetch path (`docs/NFD-COLLECTIBLES-SPEC.md`). Content is a
JSON document (name, description, icon). It is **optional and advisory**; the
ledger never depends on it, and it is never required to compute state.

Typical size: ~33 bytes.

### 5.2 `0x02` — TRANSFER

Grouped by token to keep airdrops compact.

| field       | size | notes                          |
|-------------|------|--------------------------------|
| group_count | var  | ≥ 1                            |

Per group:

| field       | size | notes                                        |
|-------------|------|----------------------------------------------|
| id_block    | var  | delta from previous group's block, ascending |
| id_tx       | var  |                                              |
| recip_count | var  | ≥ 1                                          |

Per recipient:

| field   | size | notes                    |
|---------|------|--------------------------|
| amount  | var  | smallest units, > 0      |
| address | 21   | §4.2                     |

Groups must be **sorted ascending by token ID with no duplicates**; an unsorted
or duplicated group makes the record invalid (deterministic canonical form).

**All-or-nothing.** If the sender's balance is insufficient for *any* entry, the
**entire record is ignored** and no balance changes. There is no partial fill and
no clamping — those caused real divergence bugs in Counterparty and Omni.

Sending to your own address is valid and is a no-op. Sending a non-transferable
token (flag `0x08`) from a non-issuer is invalid.

### 5.3 `0x03` — MINT

Claims from an open-mint token. The amount is fixed by the issuance terms, so it
is not carried.

| field     | size | notes                                        |
|-----------|------|----------------------------------------------|
| id_block  | var  |                                              |
| id_tx     | var  |                                              |
| recipient | 21   | *(optional)* absent = sender                 |

**Payment.** If the token's current mint price (§6.3) is non-zero, the same
transaction must contain an output paying **at least** that amount to the
required destination — the issuer's address, or a provably-unspendable output if
the burn flag `0x20` is set. Underpayment, or payment to the wrong destination,
makes the claim invalid. Overpayment is accepted and not refunded; wallets must
pay the exact amount.

Invalid, and ignored, if: the token is not open-mint; the current height is
outside `[height_start, height_end]`; the cap is already fully allocated; or
payment is missing or short.

**Partial fill at the cap boundary only** (Geoff, 2026-Jul-19). If a valid,
fully-paid claim would exceed the remaining cap, it mints **whatever remains**
rather than being rejected. This is deterministic — ordering is deterministic
(§9.1) — so every indexer computes the same result. It exists to prevent a real
loss: without it, two buyers racing for the last units both pay, and the later
one's payment is gone with nothing returned. Partial fill converts a total loss
into a short fill. Wallets must warn when a claim will be partially filled.

This is the **only** place partial fill occurs. TRANSFER remains strictly
all-or-nothing (§5.2); clamping there caused real divergence bugs in Counterparty
and Omni. ~4 bytes plus the payment output.

### 5.4 `0x04` — NAME COMMIT

| field      | size | notes                              |
|------------|------|------------------------------------|
| commitment | 20   | `Hash160(salt ‖ ticker_ascii)`     |

See §7.

### 5.5 `0x05` — BURN

| field                     | size |
|---------------------------|------|
| id_block, id_tx, amount   | var  |

Permanently destroys the sender's own units and reduces circulating supply.
Explicit and deliberate — the **only** way DMT ever destroys value (§8).

### 5.6 `0x06` — LOCK SUPPLY

| field             | size |
|-------------------|------|
| id_block, id_tx   | var  |

Issuer-only, irreversible: disables all future issuer minting. Does not affect
an already-running open mint.

### 5.7 `0x07` — ISSUER TRANSFER

| field                          | size |
|--------------------------------|------|
| id_block, id_tx, new_issuer    | var + 21 |

Issuer-only. Hands issuer rights to another address. Sending to a provably
unspendable address is the canonical way to renounce control.

---

## 6. Token properties

### 6.1 Divisibility

`decimals` is **presentation only**. All arithmetic is integer, in smallest
units, everywhere — in records, in the ledger, and in every API. Wallets divide
by `10^decimals` for display and multiply on input.

- `decimals = 0` → **indivisible**: tickets, passes, licences, credits, seats,
  collectible units. One unit is atomic and cannot be split.
- `decimals = 8` → currency-like, matching DIVI's own precision.

This single field is what makes DMT general-purpose rather than category-bound.

### 6.2 Supply policies

| policy               | flags                          | use                                   |
|----------------------|--------------------------------|---------------------------------------|
| Fixed                | premine > 0, `0x02` set        | fixed-supply asset; trustless         |
| Issuer-mintable      | `0x10` set                     | credits, points, redeemable units     |
| Open mint (fair)     | `0x01` set, cap, per_mint      | fair-launch / community distribution  |
| Hybrid               | premine + `0x01`               | reserve plus public mint              |

An issuer may LOCK SUPPLY at any time to convert a mintable token to fixed.

### 6.3 Mint pricing — set, free, or rising

Open-mint tokens choose how claimants pay, if at all. All three are per-token
settings; none is privileged by the protocol.

| model   | fields                          | use                                  |
|---------|---------------------------------|--------------------------------------|
| Free    | `mint_price = 0`                | fair launch, airdrop, first-come      |
| Set     | `mint_price > 0`                | fixed-price sale: tickets, passes, credits |
| Rising  | `mint_price > 0`, flag `0x40`   | early-buyer discount; price climbs    |

Rising price is deliberately the simplest possible curve:

```
price(n) = mint_price + (price_step × n)
```

where `n` is the number of claims already made. Linear, integer-only, and
computable by anyone from chain data alone with no floating point — so every
indexer and every wallet agrees on the exact price of the next claim. Richer
curves (geometric, time-decaying, Dutch auction) are deliberately **excluded from
v1**; they can be added later as a new subtype under the versioning rule in §8.

**Where the money goes is the issuer's choice** (flag `0x20`): mint proceeds
either pay the issuer's address or are burned. Note this is a *different* fee
from ticker registration (§7.3), which is not issuer-configurable and never can
be — see §7.4.

---

## 7. Ticker registration — commit-reveal, and pricing

### 7.1 Why commit-reveal

Tickers are first-come-first-served, so a plain registration is trivially
front-run: an observer sees a valuable ticker in the mempool and pays a higher
fee to grab it first. Namecoin solved this in 2011 and Runes reimplemented the
same idea in 2024 (using a Taproot witness, which Divi does not have and does
not need — the mechanism is a maturity rule, not a script rule).

### 7.2 The scheme

1. Broadcast a **NAME COMMIT** (§5.4) carrying `Hash160(salt ‖ ticker)`, with a
   **20-byte random salt**.
2. Wait **12 confirmations** (`MIN_COMMIT_DEPTH = 12`).
3. Broadcast **ISSUE** revealing the ticker and salt, **from the same address**.

The indexer recomputes the hash and rejects a mismatch, a commit shallower than
12 blocks, a commit from a different address, or a commit already consumed.

An attacker who learns the ticker at reveal time cannot use it: claiming it needs
*their own* commit already 12 blocks deep, and they learned it seconds ago. **The
delay converts a mempool race — winnable by fee-bumping — into a 12-block reorg,
which is not winnable.** Divi's 100-block max-reorg cap makes this absolute.

The 20-byte salt is deliberate. Namecoin's original 8-byte salt was
brute-forceable against the published hash, letting an attacker learn the name
*during* the waiting window; they treated lengthening it as a security fix.

**On Divi this costs 12 minutes, not 2 hours.** 60-second blocks make
anti-front-running registration genuinely practical here in a way it never was
on Bitcoin — a real, defensible advantage.

### 7.3 Pricing — do not use a flat fee

A Princeton study of Namecoin found that of ~120,000 registered names, **28 were
genuinely in use**. The cryptography worked perfectly; the economics failed. A
flat fee hands squatters the entire gap between a trivial cost and a name's real
value.

### 7.3.1 The two protocol fees (Geoff, 2026-Jul-19)

Creating a token and registering a ticker are **separate, separately-priced
operations**. A token always has a canonical numeric ID (§4.3) and works without
a ticker; a ticker is an optional human-readable alias.

| operation                | cost           | destination           |
|--------------------------|----------------|-----------------------|
| Create a token (ISSUE)   | 10,000 DIVI    | Divi Love treasury    |
| Register a ticker        | 5,000 DIVI     | Divi Love treasury    |

Paid as an output to the treasury address in the same transaction. The address is
a **compiled-in constant**; the indexer rejects an ISSUE or ticker registration
that underpays or pays elsewhere.

Treasury rather than burn is a valid choice for the anti-squatting purpose: what
matters is that the money **leaves the payer's control permanently** (§7.4), not
where it lands. Two consequences to accept knowingly: the treasury key becomes a
long-lived asset that must be protected, and the destination is a trusted
constant that can only be changed by a spec version bump (§8) — never at runtime,
never fetched over a network (§9.3).

### 7.3.2 Ticker pricing scales by LENGTH — no oracle required

**Scaling here means scaling by ticker length, not by DIVI's market price.** The
length of the ticker string is present in the record itself, so the fee is a pure
lookup table computed identically by every implementation from chain data alone.
**No oracle, no price feed, no external input, no trusted party.**

Flat pricing is what produced Namecoin's 28-out-of-120,000 outcome. A squatter
does not buy the average name; they buy the ~200 valuable short tickers, and a
3-letter ticker is worth vastly more than a 10-letter one. Under a flat fee they
take the entire premium namespace at commodity cost and resell — which is *more*
attractive now that tickers are transferable (§7.5).

| ticker length | cost        |
|---------------|-------------|
| 3             | 50,000 DIVI |
| 4             | 20,000 DIVI |
| 5             | 10,000 DIVI |
| 6–8           | 5,000 DIVI  |

(Geoff, 2026-Jul-19.) Ordinary names stay at 5,000; only the scarce, contested
end is expensive.

### 7.2.1 Ticker length and character set

**Length is 3–8 characters.** The 2-and-under range is excluded entirely rather
than priced: there are only 26 single letters and ~1,300 two-character
combinations, so allowing them creates a pure land-grab over a tiny namespace
with no legitimate advantage over a 3-character name. Excluding them avoids the
fight. 8 is a generous upper bound — a token's full name belongs in its metadata
(§5.1), not its ticker.

**Character set: `A–Z`, `0–9`, and `!#^-_+.`** (Geoff, 2026-Jul-19). No
lowercase — case-folding is a classic source of duplicate-identity bugs, and
forbidding it outright means `DIVI` and `divi` can never be different tokens.
First character must be a letter.

Because the set is ASCII-only, the entire **Unicode homoglyph attack class is
structurally impossible** — no Cyrillic `о` rendering as `o`, no zero-width
joiners, no right-to-left overrides. That is a significant, free security win
and it must not be given up later by "just adding Unicode for international
tokens".

⚠ **The punctuation does carry two costs, recorded honestly:**

1. **`!` is a letter-lookalike.** `D!VI` reads as `DIVI` at a glance, exactly as
   `D1VI` does. `.` `-` `_` are mutually confusable at small sizes. This is
   mitigated — but not eliminated — by normalised reserved matching (§7.6) and
   wallet warnings.
2. **`! # ^ +` are metacharacters** in URLs and shells. A ticker appearing in an
   explorer URL, a QR payload, a filename or a shell command needs correct
   escaping; `#` truncates a URL at the fragment and `+` decodes as a space if
   anyone forgets. This is an implementation-correctness burden, not a protocol
   flaw: **every implementation must percent-encode tickers in URLs and never
   interpolate a ticker into a shell command.** Flagged so it is designed for
   rather than discovered.

A conservative alternative, if these prove troublesome in practice, is to keep
`-` `_` `.` only. Changing the set later is a version bump (§8), and *narrowing*
it would strand already-registered tickers — so if it is to be narrowed, that
must happen before launch, not after.

### 7.3.3 The real problem: DIVI's price drifts. Do NOT use a spork.

Any fee denominated in DIVI becomes wrong over time — 10,000 DIVI may be trivial
in one market and prohibitive in another. Options considered:

| approach | oracle? | verdict |
|----------|---------|---------|
| Fixed forever | no | simple, but wrong eventually |
| **Live spork / remote-settable** | no | **rejected — see below** |
| **Governance constant, version-bumped** | no | **recommended for v1** |
| Demand-adjusted from chain data | no | best long-term; deferred to v2 |

**A spork is rejected, and this is a firm recommendation rather than a
preference.** Three reasons:

1. Divi's existing spork mechanism is already a documented weak point — a
   *single hardcoded key*, no multisig, no timelock, able to change live
   consensus-relevant values. Hanging more on it deepens an existing risk.
2. It is precisely the antipattern this specification bans in §9.3, where
   Counterparty fetches consensus parameters at runtime and its own source
   comments acknowledge the hijack surface. A fee that can change under a user
   mid-transaction is a consensus parameter in everything but name.
3. It destroys the credibility of §11.1. "Anyone may build on this" is a much
   weaker promise if one key can reprice the layer without warning. Live
   repricing is exactly the grievance that motivates someone to fork the indexer.

**Governance constant (recommended).** The fee table is compiled into the
software. Changing it is a spec version bump with a published activation height
(§8) — announced in advance, identical for everyone, effective at a known block.
**This gives Geoff the same control**; the only difference is that the change is
scheduled and visible rather than instant and silent. That difference is
strictly in his favour: predictable fees are what make the layer safe to build
on, and an announced change cannot be mistaken for an attack.

**Demand adjustment (v2, no oracle).** The most durable answer, deferred only
for complexity. Target a registration rate (say N per 1,000 blocks); if actual
registrations exceed target the base fee rises, if below it falls, bounded by a
floor and ceiling, computed by integer arithmetic from chain data alone. This
targets the actual goal — deterring spam and squatting — instead of proxying it
through fiat price, and it tracks purchasing power indirectly: if DIVI
appreciates sharply, registrations slow and the DIVI-denominated fee falls.
A mass-squatter drives the price up against themselves as they register.
Specify carefully before building; determinism and integer-only math are
mandatory.

Tokens do **not** expire. Unlike domain names, a token with holders must not
evaporate; expiry would strand real balances. Squatting is priced against, not
timed out.

### 7.4 The two fees are different, and only one is issuer-configurable

These are easily confused and must never be conflated:

| | **Ticker registration** (§7.3) | **Mint price** (§6.3) |
|---|---|---|
| Who pays | the token creator, once | each claimant, per mint |
| Purpose | make squatting expensive | sell or distribute the token |
| Destination | burn (or treasury) — **network-wide constant** | issuer's choice: issuer address or burn |
| Issuer-configurable | **No, and cannot be** | **Yes** |

The registration fee **cannot** be issuer-configurable, for a reason that is
structural rather than a policy preference: it is a cost *paid by the creator*,
and its entire purpose is to be a real, unrecoverable expense that prices out
squatters. If a creator could direct their own registration fee to their own
address, it would cost them nothing but transaction fees, and the anti-squatting
mechanism would evaporate. A squatter would register thousands of tickers for
free. **The fee must leave the creator's control permanently, or it is not a
fee.** Burning achieves this with no trusted recipient and no key to manage, and
anyone can verify it independently.

Mint proceeds are the opposite case — that money comes *from buyers*, and where
it goes is legitimately the issuer's business. Hence flag `0x20`.

### 7.5 Tickers are owned and transferable — with one hard rule

A registered ticker is an **owned, transferable asset** held by an address, like
a domain name. It may be registered on its own, held, and sold. Represented in
the UI as an NFD (`docs/NFD-COLLECTIBLES-SPEC.md`) so it appears in Divi
Collectibles alongside other owned assets; the DMT ledger remains authoritative.

**The hard rule: a ticker is freely transferable until it names a live token,
and permanently frozen to that token afterwards.**

| state                        | transferable? |
|------------------------------|---------------|
| Registered, unused           | **Yes** — freely bought and sold |
| Attached to a token by ISSUE | **No** — bound to that token forever |

The reason is a scam vector, not tidiness. If a ticker could be detached and
reassigned after people hold the token, then whoever controls the ticker can
**rename a token under its holders' feet** — point the well-known name at a
worthless new token, or strip the name off a real one. Every wallet and explorer
would follow, because they resolve names through this ledger. That is a rug-pull
with the protocol's assistance, and it must be structurally impossible rather
than merely discouraged.

Selling a *live* token's identity is still possible — via ISSUER TRANSFER
(§5.7), which hands over the whole token, ticker included. What cannot happen is
the name moving while the holders stay behind.

Unused tickers being tradeable is the intended market: name speculation is
harmless when nobody holds a balance under that name, and it gives the 5,000 DIVI
registration a genuine secondary value.

**New subtype `0x08` — TICKER TRANSFER**

| field       | size | notes                          |
|-------------|------|--------------------------------|
| ticker_len  | 1    |                                |
| ticker      | var  | ASCII                          |
| new_owner   | 21   | §4.2                           |

Sender must be the current ticker owner, and the ticker must be unused. Ignored
otherwise (§8).

### 7.6 Issuance is open to anyone — and what that obliges us to build

**Decision (Geoff, 2026-Jul-19): anyone may create a token. No gating, no
allow-list, no approval.** The registry fees (§7.3.1) are the only filter.

This is the right call for an open chain, and it is also the state that cannot be
walked back later without breaking users. It has a predictable consequence:
**scam and impersonation tokens will be created.** Not a risk — a certainty, on
every chain that permits open issuance. Since we are not gating creation, the
defences must live in naming rules and presentation instead.

**1. Reserved tickers, matched on a NORMALISED form (protocol-enforced).** A
small hardcoded list is unregisterable by anyone, protecting the chain's own
identity: `DIVI`, `DIVIX`, `DMT`, `NFD`, `POE`.

Exact string matching would be **nearly useless**, because the character set
(§7.2.1) lets an impersonator write `D1VI`, `D!VI`, `D-I-V-I`, `DIVI.` or
`DIV_I`. Reservation is therefore checked against a normalised form:

1. Remove every punctuation character (`!#^-_+.`).
2. Fold digit and punctuation lookalikes to letters:
   `0→O`, `1→I`, `!→I`, `2→Z`, `5→S`, `8→B`.
3. Compare the result against the identically-normalised reserved list.

Any collision is refused (§8). So `DIVI`, `D1VI`, `D!VI`, `D-IVI`, `D.I.V.I` and
`0IVI` all resolve to the same reserved name and none of them can be registered.
This is a **protocol rule**, deliberately: it is a small, fixed, exactly
specifiable table, and it must produce the same answer in every implementation.

**2. Confusable-name warnings (wallet/explorer, NOT protocol).** Beyond the
reserved list, wallets **must** compute visual similarity against tokens the user
already holds and warn prominently before a first interaction — `DIVl`, `D1VI0`
and similar near-misses on *ordinary* tokens. This stays out of the protocol on
purpose: it is heuristic, it will change as attacks evolve, and heuristics must
never be baked into ledger state where they can never be corrected.

**3. There is no verification, and no badge — deliberately** (Geoff,
2026-Jul-19). Marking a token "verified" is an implied endorsement, and an
endorsement carries **legal exposure** for whoever issues it. It also invites
exactly the wrong mental model: users would treat an unbadged token as
"suspicious" and a badged one as "safe", outsourcing judgement to a party who
cannot actually guarantee anything about a token's business.

The protocol therefore takes no position on any token's legitimacy, and no
implementation should introduce one. Wallets may show **facts** — issuance
height, issuer address, supply, whether supply is locked, how many holders exist,
whether the name is confusable with something the user holds. Facts are
verifiable from the chain and endorse nothing. Anything reading as approval is
out of scope.

This is consistent with §2: the chain records and orders; it does not vouch.

**4. Never present a ticker as identity.** The canonical identifier is the
numeric token ID (§4.3). Wallets should show the ticker with its ID available,
and must resolve by ID — never by ticker — in any security-relevant path.

---

## 8. Error handling — ignore, never destroy

**Any invalid, malformed, unparsable or unrecognised record is skipped entirely,
producing no state change whatsoever.**

This is the single most important safety rule in the specification, and it is a
deliberate rejection of Runes' "cenotaph" design, where a malformed record
**burns every token in the transaction** — and where one trigger is an
*unrecognised field*, meaning a future protocol upgrade destroys the holdings of
anyone running older software. That is a booby trap aimed at our own users.

BURN (§5.5) is the only mechanism that ever destroys units, and it is explicit.

**Forward compatibility:**

| situation                        | behaviour                                        |
|----------------------------------|--------------------------------------------------|
| unknown envelope **version**     | indexer **halts** and refuses to advance         |
| unknown **subtype**              | record ignored, no state change                  |
| reserved flag bit set            | record ignored, no state change                  |
| malformed body / bad lengths     | record ignored, no state change                  |
| trailing bytes after a record    | record ignored, no state change                  |

Halting on an unknown version is intentional. Two indexers that silently
disagree is the failure that must never happen; an indexer that stops and says
"upgrade me" is merely unavailable, and unavailability is recoverable while
divergence is not. **Any new subtype or flag requires a version bump and a
published activation height**, never a silent change.

---

## 9. Indexer requirements — normative

Written in Rust, per `docs/ROADMAP.md`. Reuses the scanning skeleton in
`contrib/poe/poe_index.py`.

1. **Deterministic ordering.** Apply records strictly by block height, then by
   transaction index within the block. Never by timestamp, arrival order, or
   anything node-local.
2. **Per-block chained state fingerprint, from day one.**
   `F(n) = SHA256(F(n−1) ‖ height ‖ canonical serialisation of the block's state
   changes)`. Publish it. Because it is a chain, any divergence propagates
   forward permanently and cannot be silently repaired — two implementations
   discover they disagree immediately rather than years later.
   Ordinals still has no such fingerprint after three years of requests; Omni's
   checkpoints have been unmaintained since 2019. Do not repeat this.
3. **Ship activation heights and all consensus parameters compiled into the
   binary.** Counterparty fetches its rules from a web URL at runtime and its own
   source comments acknowledge the DNS/TLS hijacking risk. Never do this.
4. **Reorg handling.** Retain undo data for **200 blocks**. Divi hard-caps reorgs
   at 100 blocks, so this window is *provably* sufficient — a stronger guarantee
   than any Bitcoin indexer can offer. On a deeper reorg, halt; never serve
   possibly-wrong state.
5. **One normative implementation.** It is the specification of record in any
   dispute, and this document is amended to match it, not the reverse.
6. **Genesis height.** Records before the published DMT genesis height are
   ignored, so the ledger has one unambiguous origin.

---

## 10. Trading

Address balances do not compose with single-transaction coin swaps. Three paths,
in order of confidence:

1. **Token-for-token — solid.** Fully deterministic, because the protocol
   controls both sides. This is the part of Counterparty and Omni that genuinely
   worked. Settlement should use **per-block uniform-price clearing**: every
   trade in a block settles at one price, so position within a block is worth
   nothing and there is nothing to gain by jumping the queue. A block already
   *is* a batch. This is the mitigation the market-design literature endorses,
   and **no token protocol has ever implemented it**; 60-second blocks make it
   natural here.
2. **Peer-to-peer swaps — available today.** Divi already has hashed-timelock
   contracts as a standard transaction template (`TX_HTLC`,
   `divi/src/script/standard.cpp`) with CLTV active since August 2023. Trustless,
   no fork. Costs four transactions and interactivity. **Use the Decred-style
   script-branch refund, never a pre-signed refund chain** — transaction
   malleability is unfixed without SegWit, which breaks pre-signed chains but
   leaves script-branch refunds unaffected.
3. **Buying with DIVI — the PRIMARY sale is already solved; the SECONDARY sale
   is not.** These are different problems and were previously conflated here.

   **Primary (issuer sells new units to the public): safe, atomic, no trust.**
   This is exactly the priced open mint of §5.3 + §6.3, and it is immune to the
   dispenser attack by construction. The buyer builds **one transaction** that
   both pays and mints; the terms — price, cap, window — were fixed immutably at
   issuance; and **the issuer is not a participant at mint time**. There is no
   seller to front-run the buyer, nothing to empty, no rate to change, and
   LOCK SUPPLY explicitly cannot stop a running open mint (§5.6). Either the
   whole transaction is valid and the buyer gets their units, or it is invalid
   and nothing happens. This covers ticket sales, credit sales, presales and
   token launches — most real demand.

   *Residual edge case:* two buyers racing for the last units of a cap. Both pay;
   the later one's claim is invalid, and their payment has already gone to the
   issuer. Bounded and rare, but a real loss. Fix under consideration: allow a
   **partial fill at the cap boundary only** — deterministic because ordering is
   deterministic, and it converts a total loss into a short fill. Pending (§13).

   **Secondary (a holder resells to another person for DIVI): genuinely
   unsolved.** An overlay cannot escrow the chain's native coin, so the ledger
   can freeze the seller's tokens but cannot compel the buyer to pay. This is
   what broke Counterparty and Omni: a buyer matches, freezes the seller's tokens
   for a settlement window, then walks away at zero cost — a free option and a
   griefing tool. The reverse role is worse: Counterparty's dispenser lets the
   **seller take the buyer's coin outright** — the buyer's payment lands at the
   seller's address, and if the seller has emptied or closed the dispenser first,
   no tokens are returned and the protocol has no refund path. Their own lead
   maintainer calls it "a blockchain-hosted *centralized* service" where "it's
   trivial for the seller to front-run the buyer and get free BTC". **That is
   theft of the payment, not a cancelled sale**, and it is why the dispenser
   pattern must not be copied as-is.

   **Do not ship a native-coin order book.** The most promising direction is a
   narrow, optional *attach-to-coin* mode used only for the duration of one
   atomic swap — tokens live in accounts, briefly bind to a coin, then unbind.
   That is the hybrid Counterparty reached after ten years. It must be designed
   deliberately, and any attached coin must be excluded from staking for the
   window it is attached (§1) — which is precisely why it stays narrow and
   temporary.

---

## 11. Wallet requirements (Divi Desktop 6.9)

1. Balances per address and per token; respect `decimals` for display only.
2. **Maintain a small DIVI reserve at token-holding addresses** so a transfer can
   always be authorised (§1).
3. **No coin-protection UI, no lock lists, no "protected coin" markers.** They are
   unnecessary under this model — that is the entire point of §1, and shipping
   them would imply a hazard that does not exist.
4. Show indivisible tokens (`decimals = 0`) as whole units, never with a decimal
   point.
5. Surface the ticker-registration flow as commit → 12-minute wait → issue, and
   explain the wait as front-running protection rather than an apology.
6. Never claim the network enforces balances (§2).

### 11.1 Third-party implementations are expected and encouraged

Nothing in DMT is proprietary. The record format is public, the chain is public,
and the reference indexer is open source. **Anyone may build, with no fee and no
permission:** their own indexer, wallet, block explorer, mobile app, minting
front end, vending machine, marketplace, or exchange — commercial or free,
competing directly with ours.

The **only** protocol fees are the two registry costs in §7.3.1, paid once when
creating a token or registering a ticker. Building software costs nothing, and
running a service on top of DMT costs nothing. Charging for the scarce, canonical
registry rather than for the software is deliberate: it keeps the ecosystem open
while funding the layer everyone depends on.

**One honest limit, stated plainly.** The registry fees are enforced by the
indexer, not by consensus (§2). Someone could publish a modified indexer that
recognises tokens which never paid — and in doing so they would create a
*separate, incompatible ledger*. Their tokens would not appear in any wallet,
explorer or exchange following this specification. Nothing prevents this
technically; what prevents it in practice is that a token is only worth
something if the software everyone actually uses recognises it. This is the same
network-effect defence Ordinals and Runes rely on, and it is the honest answer
rather than a guarantee. It is also the strongest argument for keeping the fees
at a level the community considers fair — an unfair fee is what motivates a fork.

---

## 12. OP_DMT

### 12.1 Reservation requested

**This document requests one soft-fork opcode slot, named `OP_DMT`, alongside
`OP_POE` and `OP_NFD`.** Free slots are `OP_NOP1` (0xb0) and `OP_NOP3`–`OP_NOP8`
(0xb2–0xb7); Divi has already proven NOP redefinition with `OP_LIMIT_TRANSFER`
and `OP_REQUIRE_COINSTAKE` (`divi/src/script/opcodes.h`).

At the time of writing `opcodes.h` records **no** reservations yet. The chain
workstream owns that file, so this is a request, not an edit — please reserve all
three together to avoid collisions.

### 12.2 What it would and would not buy

Ship **later**, once the record format is proven by real use, per the roadmap's
overlay-first principle (`docs/ROADMAP.md`).

Would buy: recognition as a native protocol feature; structural validity checking;
built-in indexing so applications need no external indexer or `txindex`; native
RPCs; ~4 bytes saved per record.

**Would not buy — and this must not be overstated:** any enforcement of balances.
For a node to verify "does this address hold 500 units", it must maintain the
entire token ledger inside consensus. That is not an opcode; that is §12.3.
`OP_DMT` marks and structurally validates a record. It cannot compute state.

### 12.3 The consensus route, for the record

Namecoin demonstrated that consensus-enforced asset semantics need **no new
opcodes at all** — it reused existing small-integer opcodes as markers, dropped
them from the stack, and ran an ordinary P2PKH underneath, leaving script
execution untouched. Full nodes then *reject* invalid operations rather than
confirming and ignoring them, and light clients can verify against a committed
state root.

Cost: permanent consensus surface, permanent per-node state, and a change that
can never be taken back. **Out of scope for v1**, recorded here because it is the
only path to "the network enforces it", and because Divi — unlike everyone who
built these protocols on Bitcoin — actually can change its own consensus. Every
protocol surveyed was a workaround by people who could not.

A lighter middle path worth future study: keep the overlay encoding, but commit a
token-state fingerprint (§9.2) into the chain periodically. That closes the
light-client gap without putting token rules into consensus.

---

## 13. Decisions

### Settled

- **DMT = Divi Meta Tokens** (Geoff, 2026-Jul-19). Matches the carrier: these are
  metadata records in Divi's `OP_META` output.
- **All token types supported**, not one category — free, set-price and rising
  price mints (§6.3); divisible and indivisible (§6.1); fixed, mintable and
  open-mint supply (§6.2); transferable and non-transferable (§5.1).
- **Mint proceeds are issuer-configurable** (issuer address or burn, flag `0x20`).
  **Ticker registration is not, and cannot be** — see §7.4 for why.
- **Genesis height** is not a design decision: it is the block height at which the
  first indexer is deployed, fixed as a compiled-in constant at that moment so
  every implementation starts counting from the same block. It will be recorded
  here at deployment. No action needed in advance.

- **Protocol fees** (§7.3.1): 10,000 DIVI to create a token, 5,000 DIVI to
  register a ticker, both to the **Divi Love treasury** (Geoff, 2026-Jul-19).
- **Tickers are owned and transferable** (§7.5), shown as NFDs, tradeable while
  unused and frozen once they name a live token.
- **Third-party front ends, vending machines and marketplaces are free and
  encouraged** (§11.1). Only the registry costs anything.
- **Primary sale with DIVI is solved** by the priced open mint (§10.3) — atomic,
  no trust, immune to the dispenser attack.

- **Ticker pricing scales by length** (§7.3.2), by lookup table. No oracle.
- **No spork / no live repricing** (§7.3.3). Fees are compiled-in constants,
  changed only by version bump with a published activation height.
- **Anyone may create a token** (§7.6) — open issuance, with normalised reserved
  names and wallet-side confusable warnings.
- **No verification and no badge** (§7.6) — an endorsement carries legal exposure
  and teaches users the wrong mental model. Wallets show verifiable facts only.
- **Tickers are 3–8 chars**, `A–Z 0–9 !#^-_+.`, no lowercase (§7.2.1).
- **Partial fill at the cap boundary** (§5.3), so a losing racer is short-filled
  rather than losing their payment entirely.

### Still open

1. **Secondary sales for DIVI** (§10.3) — holder-to-holder resale is the one
   genuinely unsolved problem. Primary sales are unaffected and safe.
2. **Demand-adjusted fees** (§7.3.3) — deferred to v2; specify before building.
3. Whether attach-to-coin (§10.3) is pursued at all.
4. Final reserved-ticker list (§7.6).

## 14. Build order

1. This specification. ✅
2. Rust indexer: envelope parsing, ledger, chained fingerprint, reorg undo.
3. Regtest end-to-end: commit → issue → transfer → mint → burn, with fingerprint
   agreement between two independent runs.
4. DD69 wallet: balances, send, registration flow.
5. Token-for-token trading with per-block uniform clearing.
6. HTLC peer-to-peer swaps.
7. *Later:* `OP_DMT` soft fork.

Steps 1–6 require **no fork**. A node that never upgrades relays, validates and
stores every DMT transaction correctly and stays in consensus permanently; it
simply cannot display balances. There is no activation height, no flag day, and
no split risk anywhere in this specification.
