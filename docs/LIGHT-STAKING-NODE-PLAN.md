# Divi Light Staking Node for phones — plan

**Goal:** let someone with only a phone stake their DIVI overnight, earn rewards, and help
secure the network — without downloading the chain, without melting the phone, and
without breaking Apple's or Google's rules.

**Status:** design verified against the Divi source (facts below are read out of the code,
not assumed). Nothing built yet. This document is the build plan and the safety contract.

---

## 1. The enabling fact (verified)

The calculation that decides whether one of your coins wins the right to make a block does
**not touch the blockchain**. From `divi/src/ProofOfStakeCalculator.cpp`:

```
ss << stakeModifier << coinstakeStartTime << prevout.n << prevout.hash << hashproofTimestamp
```

Five small inputs: one network value (the stake modifier), the coin's own identity
(`prevout.hash`, `prevout.n`), when the coin was created, and a candidate timestamp. Three
are the user's own coin details; the rest is a couple of numbers the network knows.

So "did my coin win this minute?" is a tiny hash, not a chain lookup. That is what makes a
phone staker possible at all.

**Crucially: this check needs no private key.** Every input is public. That fact drives the
whole architecture in §3.

### Other verified parameters
| Fact | Value | Source |
|---|---|---|
| Block spacing | 60 seconds | `chainparams.cpp` `nTargetSpacing` |
| Coin maturity | 20 confirmations | `chainparams.cpp` `nMaturity` |
| Minimum coin age to stake | 1 hour | `chainparams.cpp` `nMinCoinAgeForStaking` |
| Cold staking / delegation | **does not exist** | no matches anywhere in source |
| Block is signed by the staking key | **yes** | `BlockSigning.cpp` |

No consensus change and no fork is required: a block produced this way is an ordinary valid
block. The network cannot tell it came from a phone.

---

## 2. ⚠ The security finding that shapes everything

`BlockSigning.cpp` signs the **block hash** with the staker's private key:

```
key.SignCompact(block.GetHash(), block.vchBlockSig)   // (or key.Sign(...) for TX_PUBKEY)
```

That means the phone's staking key must produce a signature over a 32-byte digest.

**The danger:** if the phone accepts a 32-byte digest *from the server* and signs it blindly,
a malicious or compromised relay can send the sighash of a transaction that spends the
user's coins to an attacker. The resulting signature is ordinary ECDSA — the `(r,s)` values
from a compact signature can be re-encoded in DER form and used as a spending signature.
**That is direct theft of funds, not just lost earnings.**

This corrects an earlier assumption that "the worst a bad server can do is cost you a
reward." That is only true if the following rules are enforced.

### Cardinal security rules (non-negotiable)
1. **The phone constructs everything it signs.** It builds the coinstake transaction and the
   block header itself, and hashes the header locally. It must **never** sign a digest
   supplied by the server.
2. **The phone verifies what it signs**: the coinstake must spend *its own* UTXO and pay back
   to *its own* address, and the header it builds must commit to that coinstake.
3. **Keys never leave the device** — generated and stored in iOS Keychain / Android Keystore,
   never transmitted, never backed up to the relay.
4. The relay is treated as **untrusted infrastructure** at all times.

With these rules, a hostile relay can only waste attempts or withhold service — the honest
"you don't earn, you never lose" property the design is meant to have.

---

## 3. Recommended architecture: *the server searches, the phone signs*

Because the win-check needs no private key (§1), the **relay does the searching** and the
phone acts like a hardware signing key.

```
  ┌── Fasthosts relay (untrusted) ──────────┐        ┌── Phone (holds keys) ──┐
  │ • tracks registered public addresses    │        │                        │
  │ • each block: recompute modifier/target │        │                        │
  │ • run win-check over registered UTXOs   │        │                        │
  │            │ a coin wins                │        │                        │
  │            └─── win details ───────────────────► │ builds coinstake +     │
  │                                          │       │ block header ITSELF,   │
  │  ◄──── signed coinstake + block sig ─────────────┤ verifies, signs        │
  │ • assembles block, broadcasts to network │       │                        │
  └──────────────────────────────────────────┘       └────────────────────────┘
```

### Why this shape, specifically

**It solves the battery problem.** The phone runs no search loop and does not poll every
second. It holds one idle connection and does nothing until it actually wins — which for a
small stake is rare. Radio wake-ups, not CPU, are what drain phone batteries; this design has
almost none. The on-device work when a win happens is a few milliseconds of signing.

**It solves the app-store problem.** Both stores ban on-device mining and both explicitly
allow the off-device version:
- **Apple, Guideline 3.1.5(b):** apps "may not mine for cryptocurrencies unless the processing
  is performed off device (e.g. cloud-based mining)."
- **Google Play:** doesn't allow apps that mine cryptocurrency on devices, but permits apps
  that *remotely manage* mining.

By moving the search to the relay, the phone performs no mining-like computation at all. It is
a non-custodial wallet that signs — the shape both stores already accept. (Apple also requires
wallet apps to be published by an **organization**, not an individual developer account.)

**The trade-off to disclose honestly:** the relay learns which addresses/UTXOs a user stakes
(a privacy cost), but never gains any ability to move funds. Non-custodial is preserved.

### The timing constraint (the real engineering risk)
Blocks are 60 seconds apart. A winning stake must be signed and published within roughly a
second or two, or another staker's block wins the height and ours is wasted. So the phone must
be reachable **instantly** — via a live connection, not a push notification (push wake-up is
seconds-to-never and will lose most races). This is what forces the platform model below.

---

## 4. Platform reality — be honest about this

| | Android | iOS |
|---|---|---|
| Overnight, screen off | ✅ Foreground service + persistent notification keeps the socket alive | ❌ Not permitted |
| Realistic model | Plug in, leave running overnight | **Plug in and leave the app open** (disable idle timer) |
| Store risk | Low, if search is off-device | Low-moderate; avoid "run a node / mine" framing |

Android is the real target for "earn while you sleep." iOS works while the app is open and
charging. This is Apple policy, not a technical limit — do not promise iOS background staking.

Android 14+ requires a declared **foreground service type** that matches actual behavior;
`dataSync` is the plausible fit (the app maintains a synced connection to a server). Play
reviews these declarations, so it must be accurate.

---

## 5. Build phases

**Phase 0 — Prove it on regtest (go / no-go gate).**
Trace the full staking path once (win-check → coinstake → block assembly → `SignBlock` →
broadcast) and reproduce a successful stake with the **signing step performed out-of-process**,
simulating the phone. If a block produced this way is accepted, the concept is proven. Nothing
else starts until this passes.

**Phase 1 — The relay service (on the Fasthosts node).**
- Register a user's public staking addresses (watch-only; no keys, ever).
- Track their eligible UTXOs (≥ 20 confirmations, ≥ 1 hour old).
- Each block: recompute the modifier/target and run the win-check across registered UTXOs.
- On a win, send the phone everything it needs to build the header **itself** (previous block
  hash, bits, time, the transaction set / merkle path — never a pre-made digest).
- Accept the signed coinstake + block signature, assemble the block, broadcast.
- Hardening: authentication, strict rate limits, abuse/DoS protection, and a hard rule that the
  service holds no key material.

**Phase 2 — The phone client (Tauri 2 mobile, reusing the existing React UI).**
- Key generation/import into Keychain/Keystore.
- Divi address derivation, coinstake construction, block-header construction and signing — in
  Rust, on-device.
- **Validation gate:** prove the Rust implementation produces byte-identical output to the C++
  node on regtest before it ever touches real coins. (Same discipline used for the OpenSSL
  removal — compare against the reference implementation, don't assume.)
- Persistent connection; Android foreground service.
- UX: honest earnings expectations, battery/data disclosure, clear "must stay open & charging".

**Phase 3 — Store submission.**
Android first (the real product), iOS as an app-open companion. Position as a non-custodial
wallet with **remote** staking. Organization developer account for Apple.

**Phase 4 (future) — the clean end-state.**
If Divi adds **cold staking / delegation** via soft fork (fits the existing
`docs/SOFTFORK-OPCODES.md` workstream), the phone would not need to be online at all: a hot
node could stake on the user's behalf while keys stay entirely cold. That removes the timing
constraint, the foreground-service requirement, and most of the iOS limitation in one change.
It is the single highest-leverage future unlock for this product.

---

## 6. Honest risks and limits

- **Earnings are proportional to stake.** A user with a small balance will win rarely. This is
  aimed at people with little money — the app must show realistic expected earnings and must
  not imply meaningful nightly income. Overstating this would be the worst failure of the
  project.
- **Real costs to the user:** charging overnight ages a phone battery, and mobile data (even
  small amounts) costs money on prepaid plans common in the target markets. Both should be
  disclosed, and the client should prefer Wi-Fi and minimise bytes.
- **The relay is a centralisation point** — if it is down, nobody stakes. It is also a new
  public attack surface on the Fasthosts node and must be isolated from anything custodial.
- **Implementing consensus-critical signing on mobile is the main technical risk.** Mitigated
  by the byte-identical validation gate in Phase 2.
- **No slashing exists in Divi**, so a failed or duplicated attempt costs nothing but the
  opportunity — a genuinely forgiving environment for this design.
- Avoid staking the same UTXO from two places at once (phone + desktop); it only wastes
  attempts, but the client should warn.

---

## 7. Decisions needed from Geoff

1. **Android-first?** (Recommended — it's the only platform where "earn while you sleep"
   is genuinely true.)
2. **Confirm the relay runs on Fasthosts but isolated** from the custodial DiviGo wallet and
   from any personal wallet.
3. **Is the privacy trade-off acceptable** (relay sees staking addresses, never keys)?
4. **Should cold-staking delegation be promoted** in the soft-fork roadmap? It is the change
   that makes this product dramatically better.

---

## 8. Relationship to the "full node on a phone" idea

A pruned full node on Android is separately feasible but far heavier: it needs **pruning**
(Divi has none — the chain is 6.1GB and grows forever), **fast-sync/assumevalid** (also
absent), and an ARM build of the old C++ core. That is months of core work, and Apple would
still block it on iOS.

The light staker above achieves the same user-facing goal — *stake from a phone, support the
network* — with none of that. Recommendation: build the light staker now; treat pruning and
fast-sync as their own roadmap items that benefit the desktop node too.
