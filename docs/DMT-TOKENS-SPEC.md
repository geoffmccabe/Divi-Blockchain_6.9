# Divi Multi-Token (DMT) — technical specification

**DMT** is Divi's general-purpose token layer: fungible tokens of any kind —
divisible currencies, indivisible units (tickets, passes, credits, vouchers,
licences, points), collectible fungibles, community/meme coins. It is
deliberately **not** specialised to any one category; divisibility, supply
policy and transferability are per-token settings chosen at issuance.

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
| ticker_len    | 1    | 3–12                                               |
| ticker        | var  | ASCII, `A–Z` and `0–9`, first char `A–Z`           |
| salt          | 20   | reveals the commitment                             |
| premine       | var  | units credited to the issuer (may be 0)            |
| cap           | var  | *(open-mint only)* total mintable, 0 = unlimited   |
| per_mint      | var  | *(open-mint only)* units per claim, must be > 0    |
| height_start  | var  | *(open-mint only)* 0 = immediately                 |
| height_end    | var  | *(open-mint only)* 0 = no end                      |
| metadata_ptr  | 32   | *(if flagged)* Arweave tx id                       |

**Flags**

| bit  | meaning                                                          |
|------|------------------------------------------------------------------|
| 0x01 | open mint — anyone may claim (§5.3)                              |
| 0x02 | supply locked at issue — issuer can never mint again             |
| 0x04 | metadata pointer present                                         |
| 0x08 | **non-transferable** — only the issuer may send; holders cannot  |
| 0x10 | issuer may mint later (mutable supply)                           |
| rest | reserved; **must be zero** in version 0x01                       |

`0x02` and `0x10` are mutually exclusive; both set is invalid. `0x08` exists for
tickets, credentials, memberships and non-tradable points.

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

Invalid, and ignored, if: the token is not open-mint; the current height is
outside `[height_start, height_end]`; or the cap is reached. **If the claim would
exceed the remaining cap it is ignored entirely** — it does not mint a partial
amount, and it does **not** count against the cap. ~4 bytes.

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

Registration therefore requires the ISSUE transaction to **destroy DIVI** via a
provably-unspendable output, scaled inversely to ticker length:

| ticker length | cost   |
|---------------|--------|
| 3             | TBD-A  |
| 4             | TBD-B  |
| 5             | TBD-C  |
| 6–7           | TBD-D  |
| 8–12          | TBD-E  |

**The schedule shape is specified; the values are an open decision for Geoff**
(§13), as is burn-versus-treasury. Burning is recommended: it needs no trusted
recipient, no key management, and is verifiable by anyone.

Tokens do **not** expire. Unlike domain names, a token with holders must not
evaporate; expiry would strand real balances. Squatting is priced against, not
timed out.

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
3. **Buying tokens with DIVI — unsolved, and stated as such.** An overlay cannot
   escrow the chain's native coin. This is exactly what broke both Counterparty
   and Omni: a buyer matches an order, freezes the seller's tokens for a
   settlement window, then walks away at zero cost — a free option and a
   griefing tool. Counterparty's dispenser workaround is popular but its own lead
   maintainer calls it "a blockchain-hosted *centralized* service" where "it's
   trivial for the seller to front-run the buyer".

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

## 13. Open decisions

1. **What DMT stands for.** Used here as **Divi Multi-Token** — chosen to be
   category-neutral, since DMT explicitly covers divisible currencies,
   indivisible tickets/passes/credits, and community tokens alike. Easy to change
   while unimplemented; it should be settled before it reaches an opcode name.
2. **Ticker pricing values** (§7.3), and **burn versus treasury**. Burn
   recommended.
3. **Genesis height** for the ledger.
4. Whether attach-to-coin (§10.3) is pursued at all.

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
