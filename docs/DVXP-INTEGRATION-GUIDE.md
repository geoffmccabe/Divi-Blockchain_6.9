# DVXP / DMT integration guide for other agents

**Audience:** Claude agents working on DD69, scan.divi.love, Lovenode, DiviGo,
LW-SSO, or anything else that may need to read Divi overlay data.

**Status:** backend is under active construction. Record format and rules are
settled and implemented; the chain scanner and HTTP API are not built yet. Build
against the shapes below, but expect the API surface to firm up.

**Read this first if you are about to build anything that displays token or
collectible balances.** The most important content here is §2 (what you must
never claim) and §7 (the three integration targets).

---

## 1. What is being built

Three overlay protocols share one on-chain envelope and one indexer core:

| type | name | what it is | owner |
|------|------|-----------|-------|
| 0x01 | **PoE** | Proof of Existence timestamps | chain workstream |
| 0x02 | **NFD** | Divi Collectibles, encrypted-Arweave NFTs | NFD workstream |
| 0x03 | **PoE batch** | Merkle-batched timestamps | chain workstream |
| 0x04 | **DMT** | **Divi Meta Tokens**, general-purpose fungible tokens | this workstream |

**DMT is deliberately category-neutral.** It covers divisible currencies,
indivisible units (tickets, passes, credits, licences, vouchers), and community
tokens. Divisibility, supply policy, pricing and transferability are per-token
settings chosen when the token is created, not protocol categories.

**None of this requires a fork.** Records ride in `OP_META`, Divi's `OP_RETURN`
(opcode `0x6a`). A node that never upgrades relays, validates and stores every
DMT transaction correctly and stays in consensus permanently. It simply cannot
display balances. There is no activation height and no split risk.

Authoritative specs in this repo:
- `docs/DMT-TOKENS-SPEC.md` (tokens, normative)
- `docs/NFD-COLLECTIBLES-SPEC.md` (collectibles)
- `docs/POE-NFT-RECORD-FORMAT.md` (shared envelope)
- `docs/SOFTFORK-OPCODES.md` (future opcodes)

---

## 2. The trust model, and what you must never claim in UI

**DMT is an overlay.** The Divi chain **carries and orders** records
permanently. **Software interprets** them into balances. The network does not
validate token rules, and no opcode could make it.

- Accurate: *"permanently recorded and ordered by the Divi chain."*
- **Never** display or imply: *"the network enforces this"*, *"guaranteed by
  consensus"*, or *"validated by the blockchain."*

This is the same honesty standard used for NFDs, where the defensible claim is
"permanent and private", not "uncopyable".

Two consequences you must design around:

1. **A light client cannot verify its own balance.** Proving you still hold
   something requires proving nobody moved it earlier, and an absence cannot be
   proven from a data record. Every wallet, explorer and phone client is
   trusting an indexer's answer. Say so somewhere in the UI.
2. **Two indexers can disagree.** Mitigated by the state fingerprint (§5), not
   eliminated.

**There is no verification, no badge, and no "verified" flag** (spec §7.6).
Marking a token verified is an implied endorsement carrying legal exposure, and
it teaches users to outsource judgement. You may display **facts** that are
chain-verifiable and endorse nothing: issuance height, issuer address, supply,
whether supply is locked, holder count, and whether a name is confusable with
something the user already holds. Anything that reads as approval is out of
scope, permanently.

---

## 3. On-chain record format

### Envelope (shared by all four types)

```
scriptPubKey = OP_META(0x6a) PUSHDATA(payload)

payload = "DVXP" (4) | version (1) | type (1) | subtype (1) | body
```

- Usable payload is about **599 bytes** (`MAX_OP_META_RELAY` is 603 measured
  over the whole script). Capacity is not a constraint: a transfer entry costs
  about 24 bytes, so roughly 24 recipients fit in one transaction.
- **One data output per transaction** (relay policy in `MempoolConsensus.cpp`).
  Exactly one DMT record per transaction; if more appear, only the first counts.

### Identity rules

- **Sender** = the address funding **`vin[0]`**. Deterministic, one prevout
  lookup, unambiguous. Divi has no SegWit, so the txid-ambiguity bugs that
  forced two separate Counterparty fixes cannot occur.
- **Token ID** = `(block height, tx index within that block)` of its ISSUE.
  Compact, collision-free, needs no registry. **Always resolve by ID, never by
  ticker, in any security-relevant path.**
- **Addresses in payloads** = 21 bytes (1 type byte, `0x00` P2PKH / `0x01` P2SH,
  then the 20-byte hash). Recipients travel *in the payload*, not as outputs, so
  a transfer creates nothing spendable.

### DMT subtypes

| subtype | record | notes |
|---------|--------|-------|
| 0x01 | ISSUE | create a token; ticker optional |
| 0x02 | TRANSFER | grouped by token, all-or-nothing |
| 0x03 | MINT | claim from an open mint |
| 0x04 | NAME COMMIT | `Hash160(salt ‖ ticker)` |
| 0x05 | BURN | the only record that destroys units |
| 0x06 | LOCK SUPPLY | issuer-only, irreversible |
| 0x07 | ISSUER TRANSFER | hands over the token, ticker included |
| 0x08 | TICKER TRANSFER | only while the ticker is unused |

---

## 4. Rules a front end must reflect

### Address balances, never coin-bound (the critical one)

**Token balances are held against an address, like an account. Tokens are never
attached to particular coins.** This is not a preference; it is forced by Divi
being proof-of-stake.

Verified in Divi's own source: `CWallet::SelectStakeCoins` continuously selects
spendable coins and coinstake consumes them, automatically and unattended. The
only guard, `lockunspent`, does cover the staking path but the lock set is
**memory-only** and is cleared on every restart. Any design binding an asset to
a spendable coin would have the wallet eat it overnight.

**What this means for you:**
- **Do not build coin-protection UI, lock lists, or "protected coin" markers.**
  They are unnecessary and would imply a hazard that does not exist.
- Staking, consolidating and sweeping are all completely safe.
- **Wallets must keep a small DIVI reserve at token-holding addresses**, because
  authorising a transfer means spending a coin from that address. Running dry is
  a "cannot send right now", never a loss. Handle it silently.

### Divisibility is display-only

All arithmetic is integer, in smallest units, everywhere: in records, in the
ledger, and in every API response you will receive. Divide by `10^decimals` for
display and multiply on input. **`decimals = 0` means indivisible** (tickets,
passes, seats) and must render as whole units with no decimal point.

### Names

- 3 to 8 characters, `A-Z`, `0-9`, and `!#^-_+.`, first character a letter,
  **no lowercase** (so `DIVI` and `divi` can never be different tokens).
- Reserved names are blocked after normalisation, so `D1VI`, `D!VI`, `D-I-V-I`
  and `DIVI.` all collide with `DIVI` and none can be registered.
- **`!` reads as `I`.** Beyond the reserved list, wallets and explorers **must**
  warn when a name is visually confusable with something the user already holds.
  That check is deliberately outside the protocol so it can evolve.
- **`! # ^ +` are URL and shell metacharacters.** Percent-encode tickers in URLs
  (`#` truncates at the fragment, `+` decodes as a space) and never interpolate
  a ticker into a shell command.

### Registration is commit then reveal

Claiming a name is two transactions with a **12-block wait** (about 12 minutes
on Divi's 60-second blocks, versus 2 hours on Bitcoin). Present the wait as
front-running protection, not as an apology: it converts a mempool race, which
an attacker wins by paying a higher fee, into a 12-block reorg, which they
cannot win.

### Fees (compiled-in constants, never fetched at runtime)

| operation | cost | destination |
|-----------|------|-------------|
| Create a token | 10,000 DIVI | Divi Love treasury |
| Register a 3-char ticker | 50,000 DIVI | treasury |
| 4-char | 20,000 DIVI | treasury |
| 5-char | 10,000 DIVI | treasury |
| 6 to 8-char | 5,000 DIVI | treasury |

Creating a token and registering a name are **separate** operations. A token
always has a numeric ID and works with no name at all.

⚠ **The treasury address is still a placeholder.** The indexer reports itself
unconfigured until it is set, and any deployment must refuse to start in that
state, because fees paid to a wrong address are lost silently.

### Selling tokens

- **Primary sale (issuer to public) is solved and safe.** A priced open mint is
  atomic: the buyer's payment and their claim are **one transaction**, terms
  were fixed immutably at issuance, and the issuer is not a participant, so
  there is nothing to withhold, empty or reprice. Safe to build a buy button on.
- **Secondary sale (holder to holder for DIVI) is unsolved.** An overlay cannot
  escrow the native coin. **Do not build a DIVI-denominated order book.** This
  is what broke Counterparty and Omni, and their dispenser workaround lets a
  seller keep both the coin and the tokens.
- Token-for-token trading and native HTLC swaps are viable and not yet built.

### Nothing malformed ever destroys value

Any invalid, malformed or unrecognised record is **skipped entirely** with no
state change. BURN is the only record that destroys units. This is a deliberate
rejection of Runes' "cenotaph" design, where a malformed record burns every
token in the transaction and an unrecognised field destroys the holdings of
anyone on older software.

---

## 5. The state fingerprint, and how clients should use it

Every block produces a **chained fingerprint**: a hash covering the values of
everything that changed, folded into the previous block's fingerprint.

- It attests to **resulting state**, not to the sequence of writes, so an
  independent implementation that reaches the same ledger by a different route
  still agrees. That makes it a genuine cross-check rather than a check that two
  programs share code.
- Because it is a chain, divergence propagates forward permanently. Two
  operators comparing one number know instantly whether they agree.

**Recommended client behaviour:** if you query more than one indexer, compare
fingerprints at the same height before trusting balances. If they differ,
surface it rather than silently picking one. Do not average, do not retry until
they agree.

**Reorgs.** The indexer retains **200 blocks** of undo data. Divi hard-caps
reorgs at 100 blocks, so that window is provably twice the deepest reorg the
chain permits. Beyond it, the indexer **halts** rather than serving state it
cannot justify. Clients must treat "indexer halted" as a normal, recoverable
state and show it honestly, not as a crash.

**Versioning.** An envelope version the indexer cannot read also halts it. An
indexer that stops and asks to be upgraded is unavailable, which is recoverable;
two indexers silently disagreeing is divergence, which is not.

---

## 6. Node requirements

The indexer needs a Divi node with:

- **`txindex=1`** — REQUIRED. Resolving the sender means looking up the funding
  output of `vin[0]`. ⚠ Enabling this needs a one-time reindex with the node
  offline for hours. **If `addressindex` is also being enabled for the explorer,
  do both in the same reindex** rather than taking the node down twice.
- **`rpcthreads=16` and `rpcworkqueue=64`** — strongly recommended. The default
  of 4 threads starves under concurrent load; this was already diagnosed and
  fixed once on the scan node.
- **`rpcbind=127.0.0.1`** if `rpcallowip` is set. Binding dual-stack (`::`) can
  throw `RPCAcceptHandler: Error: Invalid argument` in a tight loop on macOS,
  pinning a core while the daemon looks hung.

---

## 7. The three integration targets

### 7.1 scan.divi.love (block explorer)

Repo `geoffmccabe/Divilovescan`, Cloudflare Pages, React SPA, styled from DD69's
design tokens.

**Decision: the DMT indexer reuses the existing scan.divi.love proxy.** One
node, one hardened boundary, one thing to secure.

Existing chain: Divi node (IONOS) → `server/divi-rpc-proxy.py` running as
`divi-scan-proxy.service` on `127.0.0.1:5174` → Cloudflare Tunnel → Pages
Function → SPA. **The proxy is the real security boundary**, because anything
hitting the tunnel hostname bypasses the Worker. Any new DMT method must be
added to the proxy's allow-list, not only to the Worker.

Suggested explorer sections:
- **Token list** — ticker, name, supply, holders, issuance height. Facts only.
- **Token detail** — supply policy, mint progress and current price if open,
  issuer, whether supply is locked, holder distribution.
- **Address view** — add a token balances panel alongside the existing DIVI
  balance. This is where most users will first encounter DMT.
- **Transaction view** — decode any DVXP record and render it in plain language.
  Also render PoE and NFD records, since they share the envelope.
- **Fingerprint** — publish the current height and fingerprint. This is what
  makes independent verification possible at all, and it is cheap to expose.

⚠ Remember the PoS quirk already found here: a coinstake is marked by **first
output value 0**, and its reward is outputs minus inputs. A naive reading
overstates by roughly 21x.

### 7.2 DD69 (Divi Desktop 6.9)

The wallet is the only place that **creates** records, so it owns the hard UX.

Needs: token balances per address; send; the create-token flow; the two-step
name registration with its 12-minute wait explained; a buy/claim button for open
mints; and confusable-name warnings.

Must **not** build: coin-protection UI (§4), a verified badge (§2), or a
DIVI-denominated order book (§4).

Must silently maintain a small DIVI reserve at token-holding addresses.

### 7.3 Lovenode (light node for phones)

Works by asking the user's DD69 wallet, or the scanner node, for help.

**Be honest about what it can and cannot do.** A light client **cannot** verify
token balances itself. This is structural, not an implementation gap: verifying
you still hold something requires proving nobody moved it earlier, and absence
cannot be proven from a data record. Lovenode is therefore **trusting whichever
indexer it asks**.

Recommended design:
- Prefer the user's **own DD69** when reachable, since trusting your own machine
  is strictly better than trusting a server.
- Fall back to the scanner node.
- **When both are reachable, compare fingerprints at the same height.** If they
  differ, tell the user rather than silently choosing. This is the one place
  where a phone client can get a real integrity signal cheaply.
- Cache balances with the height and fingerprint they came from, so stale data
  is visibly stale.

---

## 8. Current build state

| component | state |
|-----------|-------|
| Record parsing, all 8 subtypes | done, tested |
| Ticker rules, reserved-name defence | done, tested |
| Fee table | done, tested |
| Ledger and rules engine | done, tested |
| Reorg rollback and fingerprint | done, tested |
| Chain scanner (RPC follower) | **not built** |
| HTTP API | **not built** |
| Token-for-token trading | **not built** |
| OP_DMT soft fork | deliberately later |

Code: `contrib/dmt-indexer/` (token rules), `contrib/dvxp-core/` (shared
envelope, codecs, handler registry, fingerprint). Both Rust, per `ROADMAP.md`.
`contrib/nfd-indexer/` is the NFD equivalent.

**The HTTP API does not exist yet, so its shape is not fixed.** If you are
building a front end now, code against the concepts above (token ID, address
balances, decimals, fingerprint at height) and expect to adapt the transport.
Tell this workstream what you need and it can be shaped to fit rather than
retrofitted.

---

## 9. Questions to send back

If you are integrating and something here is ambiguous, ask rather than guess.
Two indexers or two front ends quietly assuming different rules is the specific
failure this whole design is built to avoid.
