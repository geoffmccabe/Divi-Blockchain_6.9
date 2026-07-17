# Divi on-chain record format ("DV") — Proof-of-Existence & NFTs

A shared, extensible envelope for putting small records on the Divi chain in an
**OP_META** output (Divi's `OP_RETURN`, opcode `0x6a`). It is used by
Proof-of-Existence today and by the encrypted-Arweave NFT layer later, so both
speak one format. **No consensus change** — OP_META already exists, is standard
(`nulldata`), on by default, and carries up to **603 bytes** (`-datacarriersize`).
Verified end-to-end on regtest: anchor → mine → read back (hash matches).

## Output

```
scriptPubKey = OP_META(0x6a)  PUSHDATA(payload)
```
One OP_META output per transaction (standardness rule). Value 0 (dust-exempt).

## Payload envelope

| field   | size | meaning                                   |
|---------|------|-------------------------------------------|
| magic   | 4    | `"DVXP"` (0x44 0x56 0x58 0x50) — Divi metadata record |
| version | 1    | `0x01`                                    |
| type    | 1    | record type (below)                       |
| ...     | var  | type-specific body                        |

### type `0x01` — Proof of Existence
| field    | size | meaning                       |
|----------|------|-------------------------------|
| hashAlg  | 1    | `0x01` = SHA-256              |
| hash     | 32   | hash of the document          |

Total 39 bytes. The **block timestamp** proves the document existed by then; the
document itself never touches the chain (private + tiny).

### type `0x02` — NFT (reserved, for the Arweave layer)
Body: Arweave tx-id pointer + content integrity hash + owner reference. The same
content hash doubles as a PoE record, so an NFT mint *is* a timestamp. Spec TBD
in the NFT workstream.

### type `0x03` — PoE batch root (for scale)
| field    | size | meaning                       |
|----------|------|-------------------------------|
| hashAlg  | 1    | `0x01` = SHA-256              |
| root     | 32   | Merkle root over many document hashes |

Total 39 bytes — identical size to a single PoE record, but it timestamps an
unlimited number of documents at once. Each document keeps a small **audit path**
(its siblings up to the root) off-chain; anyone recomputes the root from
`document + path` and checks it against this on-chain record. The block timestamp
proves the whole batch existed by then.

**Merkle construction — RFC 6962 (Certificate Transparency), not Bitcoin's.**
```
leaf hash = SHA-256(0x00 || doc_hash)
node hash = SHA-256(0x01 || left || right)
```
The `0x00`/`0x01` domain separation is deliberate: it blocks the second-preimage
/ internal-node forgery that plain Bitcoin-style Merkle trees allow
(CVE-2012-2459, where duplicating trailing nodes yields the same root). Odd
levels are **promoted**, never duplicated. Split point for a subtree of `n`
leaves is the largest power of two strictly less than `n`.

Reference + tests: `contrib/poe/poe_batch.py` (`selftest` proves the tree math
offline over many sizes with tamper checks; `anchor`/`verify` do it on-chain).
Verified end-to-end on regtest: 5 docs → one anchor → each proves, an outsider
is rejected.

## Anchor (create) — reference

`contrib/poe/poe_anchor.py` is the tested reference: it SHA-256s a document,
builds the envelope, creates the OP_META output via `createrawtransaction`
(Divi accepts a `"data"` output natively), signs, broadcasts, mines, and reads
it back to confirm. Divi's ~60s blocks confirm timestamps ~10× faster than
Bitcoin.

## Verify

1. Fetch the tx (`getrawtransaction <txid> 1`); read its block time = the
   proven-existed-by timestamp.
2. Parse the OP_META output: check magic `DV`, version, type, then compare the
   embedded hash to your document's hash. Match = proven.

No index or extra infrastructure is required to verify a single anchor; a light
indexer is only needed to *enumerate* many records or to compute batch/NFT state.
