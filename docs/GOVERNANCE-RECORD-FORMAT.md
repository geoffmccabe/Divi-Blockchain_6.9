# Divi Governance on-chain record format (DVXP type `0x06`)

How Divi Governance (the DAO) writes its tamper-evident anchors on the Divi
chain. Uses the **shared DVXP envelope** (same OP_META envelope as PoE / NFD /
DMT / Names), so one indexer core reads everything. **No consensus change** —
OP_META already carries up to 603 bytes, on by default; a node that never
upgrades still relays and orders every record and stays in consensus.

Verified end-to-end on regtest (anchor -> mine -> read back): both record types
round-trip. Reference tool + test: `contrib/governance/gov_anchor.py`.

## Trust model (state it in UI, same honesty standard as DMT/NFD)

The chain **carries and orders** these records permanently and timestamps them.
It does **not** enforce governance rules. The result is computed off-chain by
software from the anchored data plus the public signed votes. Accurate claim:
*"permanently recorded and ordered by the Divi chain."* Never imply *"the network
enforces the vote."* The anchors make the process **auditable and tamper-evident**
(nobody can silently alter a proposal after voting opens, or forge a tally),
which is what decentralised governance actually needs.

## What lives where

- **OP_META (on-chain):** only a tiny anchor (hashes / pointer / heights).
- **Arweave (off-chain, permanent, public):** the full proposal document (text,
  images, PDF) and, at close, the full set of signed votes. The on-chain hash
  proves the fetched content is the one that was voted on.

## Envelope

```
scriptPubKey = OP_META(0x6a) PUSHDATA(payload)
payload = "DVXP"(4) | version(1)=0x01 | type(1)=0x06 | subtype(1) | body
```

One OP_META output per transaction (standardness). Zero value (dust-exempt).

## subtype `0x01` — PROPOSAL OPEN

Written when voting opens. Freezes the proposal text **and** the voter roll.

| field          | size | meaning                                                   |
|----------------|------|-----------------------------------------------------------|
| kind           | 1    | 0x01 funding, 0x02 board election, 0x03 meta/param, 0x04 poll |
| snapshotHeight | 4    | block height whose balances set voting weight (uint32 LE) |
| hashAlg        | 1    | 0x01 = SHA-256                                             |
| docHash        | 32   | SHA-256 of the Arweave proposal document                  |
| arweaveId      | 32   | raw 32-byte Arweave tx id (pointer to the document)       |

Body 70 bytes; whole record 77 bytes.

**Proposal ID** = `(blockHeight, txIndex)` of this transaction — the DVXP
convention (compact, collision-free, no registry). Always resolve proposals by
ID, never by title.

## subtype `0x02` — TALLY

Written when voting closes. Freezes the result and commits to every vote.

| field          | size | meaning                                                   |
|----------------|------|-----------------------------------------------------------|
| propHeight     | 4    | block height of the PROPOSAL OPEN tx (uint32 LE)          |
| propTxIndex    | 2    | its index within that block (uint16 LE) — together = Proposal ID |
| snapshotHeight | 4    | echoed snapshot height (uint32 LE)                        |
| outcome        | 1    | 0x00 rejected, 0x01 passed                                |
| yesWeight      | 8    | total YES voting weight in satoshis (uint64 LE)           |
| noWeight       | 8    | total NO voting weight in satoshis (uint64 LE)            |
| votesRoot      | 32   | RFC-6962 Merkle root over the signed votes                |

Body 59 bytes; whole record 66 bytes. The yes/no totals are a convenience
commitment; the authoritative result is recomputed from the public vote set,
whose root must equal `votesRoot`.

**Merkle construction** = RFC-6962 (Certificate Transparency), identical to the
PoE batch tree (`leaf = SHA256(0x00||vote)`, `node = SHA256(0x01||l||r)`, odd
levels promoted). See `docs/POE-NFT-RECORD-FORMAT.md`.

## Reserved for later subtypes

`0x03` chat/discussion batch root (periodic Merkle root over governance chat, so
discussion is timestamped and un-editable without posting each message on-chain);
board-membership and milestone-release anchors. Add as new subtypes; never
repurpose an assigned one.

## Verify a single record

1. Fetch the tx (`getrawtransaction <txid> 1`); block time = the timestamp.
2. Parse the OP_META output: check magic `DVXP`, version, type `0x06`, subtype.
3. For a proposal: fetch the Arweave document, SHA-256 it, compare to `docHash`.
   For a tally: recompute the Merkle root from the public votes, compare to
   `votesRoot`; recount weights against the snapshot and compare to the totals.

A light indexer is only needed to *enumerate* proposals and compute live state.
