# NFD content moderation — abuse, illegal content, and the marketplace

How Divi Collectibles keeps illegal and adult content out of the **marketplace**,
given a permanent storage layer we cannot delete from. Written for the NFD +
wallet + explorer agents and for Geoff. This is policy + architecture, not yet
fully built — §6 lists what exists vs what's needed.

---

## 1. The two content surfaces (this distinction is everything)

Every NFD has two parts, with completely different moderation problems:

| Surface | What it is | Who sees it | Moderation problem |
|---|---|---|---|
| **PUBLIC** | thumbnail image, collection cover, collection name/description, item name, trait text, tier | **anyone** — this is what the marketplace *displays* | "block XXX / illegal from showing in our marketplace" — **tractable** |
| **PRIVATE** | the full-resolution encrypted original | **only the owner** (holds the key) | it is never displayed anywhere; the only issue is *hosting* encrypted bytes we can't read — see §5 |

**The marketplace only ever shows the PUBLIC surface.** The encrypted original is
not shown to browsers, ever. So "stop XXX showing in our marketplace" is a problem
about the **public thumbnails, covers, names and trait text** — and those all pass
through one choke point we control (the relay) before they become permanent.

---

## 2. The hard constraint: Arweave is permanent

Uploaded data **cannot be deleted, ever**. So moderation is never "take it down at
the storage layer." It splits into two things we *can* do:

1. **PREVENT** — scan and reject at the **relay**, *before* the bytes become
   permanent. This is the only place prevention is possible.
2. **SUPPRESS** — refuse to *display* it in our marketplace afterward, via a
   **denylist**. We can't delete the bytes; we fully control what our surfaces show.

The relay is the single choke point we own: **every public image and metadata JSON
passes through it before Arweave.** Encrypted blobs pass through too, but we can't
read those (§5).

---

## 3. Layer 1 — PREVENT (relay-side, before permanent upload)

Runs on public content only (images + metadata). The relay must scan **whatever it
is handed** — client-side checks (the wallet's thumbnail/EXIF step) are worthless
here, because an attacker can POST to the relay directly and skip the wallet
entirely. **The relay is the trust boundary.**

**3a. CSAM — mandatory, hard block.** This is the legally critical one and is not
optional. Hash-match every public image against known-CSAM hash lists (PhotoDNA /
NCMEC hash-sharing, or a commercial API such as Hive/Thorn/Cloudflare CSAM Scanning
which is free). A match → reject the upload, do not touch Arweave, log it, and
follow the jurisdiction's reporting duty. Because Arweave is permanent, **this
must happen before upload — there is no after.**

**3b. Adult / NSFW — legal but restricted → flag & gate, don't necessarily block.**
Run an automated nudity/explicit classifier (Hive, AWS Rekognition, Cloudflare) on
public images. Recommended policy (matches OpenSea and mainstream marketplaces):
allow legal adult content to *exist*, but require it be **labelled NSFW**, and have
the marketplace **blur it behind an opt-in**. Hard-block only illegal material;
gate legal-adult. (Geoff decides the exact line; the mechanism supports either.)

**3c. Text — names, traits, description, collection titles.** Untrusted creator
strings. Run a denylist/classifier for slurs, illegal solicitation, doxxing, and
obvious spam. Reject or flag. Also enforce length/'schema limits (a name is not
10 KB) so it can't break or flood the UI.

**3d. Raise the cost of abuse.** The mint fee already imposes a small cost.
Add: **per-address** rate limiting (not just per-IP — IPs rotate trivially), and
consider a small **stake/hold** to mint into a public collection. Spam and abuse
scale only when they're free.

---

## 4. Layer 2 — SUPPRESS (display-side denylist)

Prevention will never be perfect (false negatives, new content, text that slips a
classifier), and content is permanent. So the marketplace needs a **denylist** —
the real "takedown" mechanism here.

- **A signed, published blocklist** of banned NFD ids / thumbnail pointers /
  creator addresses / collection ids. Compliant marketplaces (**DD69 wallet** and
  **divi.love website** — the two identical marketplaces) refuse to display
  anything on it. Signed by the project key so both surfaces trust the same list;
  third-party marketplaces and the explorer can subscribe to it too.
- **Report button** on every marketplace item and collection → a review queue →
  additions to the denylist. This is how real-world reports become suppression.
- **Creator ban.** A repeat offender's address goes on the denylist and *all*
  their items and collections are suppressed at once.
- **Launch curated, open later.** Simplest and safest at launch: the marketplace
  shows only **approved** collections (an allowlist), not everything on-chain. Move
  to open-with-denylist once the scanning + report pipeline is proven. An allowlist
  is a denylist's inverse and needs no scanning to be safe on day one.

The denylist is client-enforced (there is no central marketplace server — each
wallet/site builds the view). That means a hostile fork could ignore it; that is
inherent to a decentralised, permanent system and is true of every NFT platform.
What we control — *our* wallet and *our* website — honours it.

---

## 5. The encrypted-original problem (honest, and genuinely hard)

We permanently host encrypted bytes **we cannot read**. If someone uploads an
encrypted illegal file, we've paid to store it forever and can't scan it. This is
an unsolved tension in *every* encrypted-permanent-storage system, and I won't
pretend there's a clean fix. What is true:

- **It is never displayed.** The marketplace shows only the public thumbnail, so
  this is not a "showing XXX in our marketplace" problem — it's a hosting-liability
  problem, separate and narrower.
- **We are a blind pipe.** We cannot decrypt it, so we cannot "knowingly" host
  specific content — encryption cuts both ways. That is a weaker position than
  active scanning but not nothing.
- **Partial mitigations:** require a public thumbnail (so *something* is
  scannable); raise cost-to-abuse (stake/fee/per-address limits) so it isn't free
  to spam; and if a valid report ever arrives with the key/preimage, add it to the
  denylist so *our* relay and gateway stop serving it (Arweave itself still holds
  the bytes — we can't change that).
- **Legal counsel should weigh in** before public launch on the relay's status as
  a hosting provider and the reporting obligations. Flagging, not advising.

---

## 6. Current state vs needed

| Control | Status |
|---|---|
| Relay content-type whitelist (octet-stream/webp/json) | ✅ built |
| Relay size cap + per-IP rate limit + optional bearer token | ✅ built (per-IP only; see 3d) |
| Client-side EXIF strip + WebP-only thumbnail | ✅ built — but **not a security control** (bypassable) |
| **CSAM hash-scan at the relay (3a)** | ❌ **needed — highest priority** |
| NSFW image classifier + label (3b) | ❌ needed |
| Text denylist / limits (3c) | ❌ needed |
| Per-address rate limit + stake-to-mint (3d) | ❌ needed |
| **Signed denylist + marketplace enforcement (4)** | ❌ needed |
| Report button (4) | ❌ needed |
| Curated allowlist for launch (4) | ❌ recommended for v1 |

---

## 7. Recommended order

1. **Curated allowlist launch** — marketplace shows only approved collections.
   Safe on day one, zero scanning required, buys time to build the rest.
2. **CSAM hash-scan at the relay** — the one legal must-have; only possible
   pre-upload. A free option exists (Cloudflare CSAM Scanning).
3. **Signed denylist + report button** — the ongoing takedown pipeline.
4. **NSFW classifier + blur/gate** — for legal-adult content.
5. **Per-address limits + optional stake** — raise cost of abuse.
6. Then **open the marketplace** (denylist-based instead of allowlist).

Get legal counsel on §5 and §3a reporting duties before any public release.
