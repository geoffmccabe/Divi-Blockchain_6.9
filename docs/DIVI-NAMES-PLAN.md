# Divi Names (HRAs): plan

**Goal.** Let users buy, own, sell and trade human readable addresses on Divi,
Namecoin style, and hang extra identity records off them (EVM address, ENS name,
Telegram, phone, avatar) ENS style.

**Headline finding.** We do not need a new system. The name registry already
exists inside `contrib/dmt-indexer/` as the DMT ticker registry: commit reveal,
20 byte salt, 12 block maturity, length tiered pricing, normalised reserved name
matching, and an owned transferable name asset (subtype `0x08` TICKER TRANSFER).
Divi Names is that registry, hoisted one level up and given more record types.

**Status of the pieces.** DMT record parsing, ticker rules, fee table, ledger,
reorg undo and fingerprint are built and tested. The chain scanner and HTTP API
are not built. Nothing is on mainnet. That matters: the unification below is
cheap now and impossible after launch.

**Fork requirement: none.** Everything in v1 rides in `OP_META` exactly like PoE,
NFD and DMT. The soft fork (§8) is optional polish, added later once the format
is proven.

---

## 1. The one decision that shapes everything: one namespace, not two

**Recommendation: a single name registry. A token ticker is just a short name.**

The alternative (a separate HRA namespace beside the ticker namespace) means
`GEOFF` the person and `GEOFF` the token are different objects owned by different
people. Every wallet then has to disambiguate, and that ambiguity is a phishing
surface we would be creating on purpose.

| | unified (recommended) | separate namespaces |
|---|---|---|
| `GEOFF` collision | impossible | permanent UX and scam hazard |
| code to write | hoist one module | a second registry, second reserved list, second fee table |
| resell market | one market, deeper | two thin markets |
| risk | buying a name that names a token also buys issuer control (§6) | none |

**Length and charset.** Keep the existing charset exactly: `A-Z`, `0-9` and
`!#^-_+.`, first character a letter, no lowercase. Extend the length range from
3..8 to **3..32**. Tickers stay 3..8 (a token may only attach to a name in that
range); personal names may run long and cost less.

Keeping uppercase only is the single best security property we have and it must
not be traded away for prettiness. It makes the whole **Unicode homoglyph attack
class structurally impossible**, which is a live, unsolved problem for ENS. The
wallet renders names in lowercase for looks (`geoff`), the record stores
uppercase, so `geoff`, `Geoff` and `GEOFF` can never be three different people.
That is a genuine, marketable advantage over ENS, and it is free.

`contrib/dmt-indexer/src/ticker.rs` already implements the fold then strip
normaliser and its regression tests. It moves to the shared crate unchanged.

---

## 2. Shape of the change

New shared crate `contrib/name-registry/` holding: charset and normalisation
(moved from `ticker.rs`), the commit reveal rule, the fee table, name ownership
state, and the record subtypes below. `dmt-indexer` depends on it instead of
owning it, and asks it "who owns this name, and is it free to bind?".

New DVXP **type `0x05` = NAME**, registered as one more `RecordHandler` in
`contrib/dvxp-core/src/registry.rs`. The envelope, fingerprint, reorg window and
scanner are untouched. That plug in point is exactly what the registry was built
for, so this is additive, not a refactor of anything shipped.

### Subtypes

| subtype | record | body |
|---|---|---|
| `0x01` | NAME COMMIT | `Hash160(salt ‖ name)`, reused as is from DMT `0x04` |
| `0x02` | NAME REGISTER | reveal: salt + name, fee output to treasury |
| `0x03` | NAME TRANSFER | new owner (21 bytes). Generalises DMT `0x08` |
| `0x04` | SET RECORD | key id + value (repeatable, several per tx) |
| `0x05` | CLEAR RECORD | key id |
| `0x06` | SET PRIMARY | reverse resolution, address to name |
| `0x07` | RENEW | extends expiry |
| `0x08` | LIST | price + minimum listing lifetime in blocks |
| `0x09` | BUY | pays the seller and claims the name in one transaction |
| `0x0A` | DELIST | takes effect only after the committed lifetime |

---

## 3. The extra records (EVM, ENS, Telegram, phone, avatar)

A name owns a small key/value record set, ENS resolver style, but with **1 byte
key ids instead of ENS's string keys**, because our payload budget is ~599 bytes
per transaction and ENS pays for strings with gas we do not have.

| key | meaning | value |
|---|---|---|
| `0x01` | Divi address | 21 bytes, the actual HRA payoff |
| `0x02` | EVM address | 20 raw bytes + optional chain id (mirrors ENSIP-11) |
| `0x03` | other chain address | SLIP-44 coin type varint + raw address (mirrors ENSIP-9, so existing multichain wallet code maps 1:1) |
| `0x10` | ENS name | UTF-8, e.g. `geoff.eth` |
| `0x20` | Telegram handle | UTF-8 |
| `0x21` | X handle | UTF-8 |
| `0x22` | email | UTF-8 |
| `0x23` | url | UTF-8 |
| `0x24` | avatar | 32 byte Arweave txid, reuses the NFD relay |
| `0x30` | phone | **commitment or encrypted blob only, never plaintext** |
| `0x40` | profile pointer | 32 byte Arweave txid to a JSON profile |
| `0xFF` | custom | ENSIP-5 style string key + value, for anything we did not foresee |

**Two rules that keep this from going wrong:**

1. **`0x40` is the escape valve.** Anything large, private, or fast changing goes
   in an Arweave JSON profile and only its 32 byte pointer goes on chain.
   Optionally encrypted with the NFD sign to derive X25519 scheme we already
   built (`crates/supervisor/src/crypto_nfd.rs`). This gives unlimited records
   and private records without bloating the chain, and it reuses working code.
2. **Phone numbers must never be stored in the clear.** A permanent public chain
   plus a phone number is a doxxing and SIM swap gift, and unlike a website you
   cannot take it down, ever. Store a salted commitment (proves a number you
   already know, reveals nothing) or an encrypted blob readable only by people
   the owner gave the key to. Same treatment for email if the owner chooses.

**Reverse resolution (address to name).** SET PRIMARY is sent by the address
itself, naming the name. It is honoured **only if that name's `0x01` record
points back at the sender.** Both sides must agree, so nobody can make their
address display as somebody else's identity.

---

## 4. Buying, owning, selling, trading

**Registration.** Commit, wait 12 blocks, reveal, pay the treasury. Already
specified and implemented for tickers, including why the wait is a feature: it
turns a mempool race (winnable by fee bumping) into a 12 block reorg (not
winnable). On 60 second blocks that is 12 minutes, versus 2 hours on Bitcoin.

**Pricing by length**, extending the existing table downward for long names:

| length | cost |
|---|---|
| 3 | 50,000 DIVI |
| 4 | 20,000 DIVI |
| 5 | 10,000 DIVI |
| 6 to 8 | 5,000 DIVI |
| 9 to 16 | 2,000 DIVI |
| 17 to 32 | 1,000 DIVI |

Compiled in constants, changed only by a version bump with a published activation
height. **No spork**, for the reasons already settled in the DMT spec.

**Selling for DIVI: the honest part.** The DMT spec correctly says secondary
sales for the native coin are unsolved for tokens. Names are an easier case,
because a name is a single indivisible object with exactly one owner, and this
design closes the Counterparty dispenser hole:

- LIST commits a price **and a minimum lifetime in blocks**. DELIST does not take
  effect until that window expires. So a seller cannot pull the listing out from
  under an in flight buyer, which is precisely the attack their own maintainer
  admits to.
- BUY is **one transaction** built by the buyer that pays the seller and carries
  the claim. The seller is not a participant, so there is nothing to withhold.
- First BUY in block order wins.

**Residual risk, stated plainly:** two buyers in the same block. The loser's DIVI
has already gone to the seller and they get nothing. Bounded and rare, the same
edge case DMT already identified at a mint cap. Mitigations: the wallet checks
the mempool for a competing BUY before broadcasting, and for high value names
offer the **interactive co-signed sale** (both parties online, one transaction,
fully atomic, no fork, no race). Do not paper over this in the UI.

**Name for name and name for token** trades use the per-block uniform price
clearing already specified for DMT.

---

## 5. Expiry and renewal: the Namecoin lesson

Namecoin names expire after 36,000 blocks (about 250 days) and are renewed by
spending them. Of roughly 120,000 names registered, a Princeton study found 28 in
genuine use. Their own wiki's conclusion on squatting is "raise renewal fees".
The cryptography worked; the economics did not.

**Recommendation: names expire, tokens do not.**

- Annual renewal at the same length tiered fee. Recurring cost is what actually
  deters squatting; a one time fee just sets the squatter's entry price.
- 90 day grace period where only the previous owner may renew.
- Then a **decaying price release over about 21 days** (a Dutch auction, ENS's
  proven premium decay) rather than a first come land grab at the expiry block.
- **A name bound to a live token becomes perpetual** and stops expiring. A token
  with holders must never have its identity evaporate. The token creation fee
  covers this.

---

## 6. Ownership, freezing, and the one warning to ship

The DMT hard rule stays: a name is freely transferable until it names a live
token, and the **binding** to that token is permanent afterwards, so nobody can
rename a token under its holders' feet. But the name as a whole can still be
sold, which is what ISSUER TRANSFER already means.

Consequence to warn about loudly in the wallet: **buying a name that names a
token also buys issuer control of that token**, including any open mint proceeds.
Show that on the buy screen in words, not a footnote.

---

## 7. What we reuse (file by file)

**Chain repo `Divi-Blockchain_6.9`:**
- `contrib/dvxp-core/` (envelope, handler registry, chained fingerprint, varint,
  address codec): no changes, register one more handler.
- `contrib/dmt-indexer/src/ticker.rs`: moves to the new shared crate as is,
  tests included.
- `contrib/dmt-indexer/src/record/simple.rs`: NAME COMMIT and TICKER TRANSFER,
  generalised.
- `contrib/dmt-indexer/src/ledger/reorg.rs`, `state.rs`, `fees.rs`: copy the
  pattern. Reorg undo and fee gating are the expensive, already solved parts.
- `contrib/nfd-indexer/`: the ownership ledger shape for a one of a kind object.

**Wallet repo `Divi-Desktop-6.9` (and the `dd69-nfd` worktree):**
- `crates/supervisor/src/crypto_nfd.rs`, `nfd_storage.rs`, `nfd-relay/`: Arweave
  plus encryption for avatars and private profile blobs.
- `ui/src/wallet/dmt/TokenCreate.tsx`: literally the commit reveal flow with the
  12 block wait already explained to users. Clone to `ui/src/wallet/names/`.
- `ui/src/wallet/AddressBook.tsx`, `contacts.ts`, `addressNames.ts`: where
  resolution lands. A contact gains a name; Send resolves a name to an address.
- `docs/NFD-GALLERY-GRID-CONTRACT.md`: reuse for "my names" and the marketplace.

---

## 8. Soft fork (optional, later)

None of the above needs a fork. When the format is settled by real use, allocate
**`OP_NAME`** from a free NOP slot alongside `OP_POE` and `OP_NFD`
(`docs/SOFTFORK-OPCODES.md`), by the same flag day mechanism proven in August
2023. What it buys: native `resolvename` / `getname` / `listnames` RPCs and a
built in index, so third parties need no external indexer and no `txindex`.
What it does not buy: enforcement. An opcode cannot make the network validate
name ownership. Marketing line stays "permanently recorded and ordered by the
Divi chain", never "the network enforces it".

---

## 9. Build order

1. Hoist `contrib/name-registry/` out of `dmt-indexer`, unify the namespace,
   extend length to 32. Existing tests must still pass.
2. Type `0x05` handler: commit, register, transfer, set/clear record, set
   primary. Regtest end to end.
3. Expiry, renewal, grace period, decaying release.
4. DD69 panel: register (reuse TokenCreate), my names, edit records, set primary.
5. Resolution everywhere: Send box accepts a name, **always shows the resolved
   raw address before broadcast**, Contacts stores it, explorer shows it.
6. LIST / BUY / DELIST marketplace, plus the co-signed sale for high value names.
7. Later: `OP_NAME` soft fork.

Steps 1 to 6 need no fork of any kind.

---

## 10. Honest caveats

- This is an overlay. The chain carries and orders the records; software
  resolves them. Never claim the network enforces it.
- **Resolution is the highest stakes thing we have ever shipped.** A wrong token
  balance is embarrassing; a wrong address resolution sends someone's money to a
  stranger. DD69 must resolve from its own local index where possible, and must
  always display the resolved raw address before a send.
- A light client cannot verify a resolution itself. It is trusting an indexer.
  Compare fingerprints across two indexers where both are reachable, and say so
  in the UI.
- Expiry means a name you rely on can lapse. Renewal reminders are a product
  requirement, not a nicety.
