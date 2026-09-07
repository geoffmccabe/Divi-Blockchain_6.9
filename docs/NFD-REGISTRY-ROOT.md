# NFD registry root — frozen wire format v1

**Audience:** whoever implements a verifier on another chain, in Solidity or
anything else. Implement against **this document**, not against
`contrib/dvxp-scan/src/registry.rs`. If the two ever disagree, that is a bug in
one of them and worth finding out about loudly.

Agreed with the DIVA lane, 2026-Sep-06.

---

## 1. What a root attests, and what it does not

A transaction inclusion proof shows a record is **in a block**. It does not show
the record **did anything**: a malformed NFD record, or one sent by somebody who
did not own the collectible, is still in the block and still provably included.
Only the overlay rules decide whether ownership moved.

A registry root attests to the **interpreted result**: "an indexer that followed
these rules found that, at height H, collectible X was owned by address A."

The two compose. Transaction inclusion gives a receiving chain an immediate
**provisional** answer; the next registry root gives the **authoritative** one.
That is why the epoch can be unhurried without making a bridge feel slow.

**A root is a commitment, not an oracle.** It is exactly as trustworthy as
whoever signed it. Today that is one key, which is no better than a coordinator
signature. This document fixes the *format*; who signs is a separate and later
question, and until DIVA has a validator set the honest description is "the shape
is ready", never "it is decentralized".

## 2. Scope

**Collectibles only.** Fungible tokens are deliberately excluded: they move
through a different mechanism, and their volume and churn would bloat the tree
for no benefit to anyone verifying ownership of a single item.

## 3. Hash

**SHA-256**, everywhere, no exceptions.

Chosen to match the rest of the overlay. On an EVM chain keccak256 is cheaper
(SHA-256 is the precompile at `0x2`, roughly twice the gas per hash), but a root
is verified about once per bridge operation over a proof a handful of hashes
deep, so the difference is negligible. One hash across every implementation
minimises the surface where two of them can disagree, which is the priority.

## 4. Leaf encoding

Each entry contributes exactly **53 bytes**, fixed width, no length prefixes and
no separators:

| offset | size | field |
|--------|------|-------|
| 0      | 32   | collectible id (the mint transaction id, **raw byte order**, not display order) |
| 32     | 1    | address kind: `0x00` P2PKH, `0x01` P2SH |
| 33     | 20   | address hash160 |

Every field is fixed width, so no two different entries can encode to the same
bytes. The address kind is part of the leaf: the same hash160 under a different
kind is a different owner and must hash differently.

## 5. Tree: RFC 6962

The construction is **RFC 6962** (Certificate Transparency), which the DIVA lane
asked for so that audited reference verifiers apply.

```
leaf_hash(entry)      = SHA256(0x00 || entry_bytes)          // 53 bytes in
node_hash(left,right) = SHA256(0x01 || left || right)         // 32 + 32 bytes in
```

- **Domain separation.** The `0x00` and `0x01` prefixes are not optional. Without
  them an internal node is indistinguishable from a leaf, both being 32 bytes,
  and can be presented as one to prove membership of something never in the set.
- **An unpaired node is promoted unchanged**, never hashed with itself.
  Duplicating it is the CVE-2012-2459 flaw, where two different trees produce one
  root and the root therefore stops identifying a single set.
- **Leaves are sorted ascending and de-duplicated** before the tree is built, by
  the 53 encoded bytes. The root is a function of the *set*, so two indexers that
  walked their state in different orders still agree.
- **An empty registry commits to 32 zero bytes.** Distinguishable from any real
  root, and meaning "nothing existed", not "nothing was checked".

The reference implementation builds bottom-up (pair, promote, repeat) rather than
top-down. That is proven equal to RFC 6962's recursive definition for every leaf
count from 1 to 64 by the test `the_tree_is_rfc_6962`, which checks it against an
independent implementation of the RFC's own wording.

## 6. Epoch boundaries

Determined by **block-height modulus**, never wall clock, so both chains agree
with no clock to disagree about.

```
epoch_of(height)     = height / EPOCH_BLOCKS
end_height(epoch)    = (epoch + 1) * EPOCH_BLOCKS - 1     // the LAST block
is_boundary(height)  = (height + 1) % EPOCH_BLOCKS == 0
```

`EPOCH_BLOCKS` defaults to **60**, which is an hour of Divi's one-minute blocks.
It is configurable rather than compiled in, so it can be tuned once DIVA's
validator set and real load exist.

**A verifier must never assume a schedule.** It binds to the **published
height**, which is signed. The schedule is only how a publisher chooses which
heights to cut at; two publishers on different schedules still produce roots
anyone can line up, because the height says exactly what each one covers.

## 7. What is signed

The root alone is not enough: a verifier handed a bare 32 bytes cannot tell which
epoch it belongs to, and an old root presented as the current one verifies
perfectly against proofs from its own epoch. So the header is signed as a whole.

Signing bytes, concatenated, fixed width, **big-endian**:

| size | field |
|------|-------|
| 25   | ASCII tag `DVXP-NFD-REGISTRY-ROOT-v1` |
| 8    | epoch, big-endian u64 |
| 8    | height, big-endian u64 |
| 8    | leaf count, big-endian u64 |
| 32   | root |

The tag means a signature over a root header can never be replayed as a signature
over anything else in the system. The leaf count is included because RFC 6962's
tree shape is determined by the number of leaves, so committing to the count
removes any question of a differently-sized tree being presented.

A signer that prefers a single digest may sign `SHA256(signing_bytes)`.

## 8. Proof format

A proof is the sibling hashes from the leaf upward. Each step is 33 bytes:

| size | field |
|------|-------|
| 1    | side: `0x00` sibling is on the LEFT, `0x01` sibling is on the RIGHT |
| 32   | sibling hash |

A promoted node contributes **no step**, so proofs are not all the same length
even within one tree. Verification:

```
running = leaf_hash(entry)
for (side, sibling) in path:
    running = side == LEFT  ? node_hash(sibling, running)
                            : node_hash(running, sibling)
accept if running == root
```

The proof deliberately does **not** carry the entry. The verifier already knows
which collectible and which owner it is being asked about; a proof that carried
its own claim would invite checking the proof against that claim rather than
against the question actually asked.

## 9. Test vectors

Pinned by `mod vectors` in the reference implementation. If any of these ever
changes, the wire format changed and every deployed verifier is now wrong.

Entries, using repeated bytes for legibility:

```
v1 = id 0x01*32, kind 0x00, hash160 0x02*20
v2 = id 0x03*32, kind 0x00, hash160 0x04*20
v3 = id 0x05*32, kind 0x01, hash160 0x06*20     (note: P2SH kind)
```

Leaf hashes:

```
leaf(v1) = 144329472f5aa0e2145989b5418b8481b5457621d17328b1266e11ed0717b2a2
leaf(v2) = 03ba3cd42eaae6ca2259e61ef7e78b249030628637411fa3e127d8892c19e648
leaf(v3) = 7c93babe0009547810aa990c9b345c714619ccf8fe2fb35cef4284174fb1ef1b
```

Roots:

```
root[v1]         = 144329472f5aa0e2145989b5418b8481b5457621d17328b1266e11ed0717b2a2
root[v1,v2]      = 53b7c6f2f96ffa9294e3db507e3fed686cdfae514c282b56d6e19812f4093df8
root[v1,v2,v3]   = b5f681547da3a628a8bae98c0dfbfb53ea6ec7a9cf1f35c5b823910b466248e9
```

A single-entry root **is** its leaf hash, because there is nothing to pair it
with and promotion carries it straight to the top. The three-entry case exercises
promotion, which is where independent implementations most often disagree, so it
is the one to check first.

## 10. Changing any of this

Every value above is load-bearing for anyone who has deployed a verifier. A
change to the hash, the leaf layout, the tags, the promotion rule, the signing
bytes or the tag string is a **new version**, with a new tag string, not an edit
to v1.
