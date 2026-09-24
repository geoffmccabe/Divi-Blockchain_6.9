# Peer Relay: reaching home nodes through the nodes that can be reached

Draft 1, 2026-Sep-24. For Geoff's approval before any code. Written in plain
language on purpose; the protocol detail is in the tables.

## Status

- 2026-Sep-24: **Part A built and proven** on a private chain (node build
  `-dd69.3`): new address kind, `sendaddrv2`/`addrv2` gossip, peers-file
  format 2, node key, and the two inspection RPCs `addpeeraddress` /
  `getnodeaddresses`. A new node learned relayed addresses from another new
  node and kept them across a restart; an old 69.0.4 node connected
  throughout, received only plain addresses, and was never banned. 402 of
  402 unit tests pass. Relayed addresses are never dialled until Part B.
- 2026-Sep-24, later: **Part B built and proven** on a private chain
  (`divi/contrib/relay-regtest.sh`): a home node with listening OFF
  registered with a helper, announced `relay:<key>@<helper>`, a third node
  dialled it through the helper, both completed the Divi handshake, pings
  ran at 0.5 ms, and blocks mined on the home node reached the caller over
  the pipe. 402 of 402 unit tests pass. Wire names fit the 12-character
  limit: rlyregister, rlyaccept, rlyrefuse, rlyconnect, rlyok, rlyerror,
  rlyincoming, rlyanswer. Differences from the draft: no separate heartbeat
  (a registration lives with the home node's ordinary connection to the
  helper, whose pings are the heartbeat); the registration is signed, the
  gossip entry is not (a fake entry fails at the helper); "am I a home
  node" is a heuristic for now (no inbound peer 3 minutes after start with
  at least two outbound), the connect-back check is a later refinement; the
  per-connection bandwidth cap is not yet enforced; B4 encryption not done.
  Two regtest-only flags for the test: -relaytestforcehome,
  -relaytestlocalhelpers.

## Why

Of the 863 node addresses Geoff's wallet knows, 116 can be reached and 747
cannot. Most of the 747 are not dead: they are home machines behind routers
or mobile carriers that never accept an incoming connection (Andy's node in
Nigeria is one). They take part in the network by connecting *outward*, but
nobody can connect *to* them, so they are grey on every map, have no lines,
and cannot be counted. DD69 is a wallet for exactly these users.

Tor would solve it but means Tor on every install, flagging by antivirus and
some networks, and slower links. A relay run by us solves it but makes
reachability a service we operate. This design keeps the property that
matters: **no operator, nothing extra installed, ordinary Divi traffic on
the ordinary port.**

## The idea in one paragraph

A home node that cannot be reached chooses two or three of the reachable
nodes it is already connected to as **helpers**. The network is told "this
node is reachable through that helper". Anyone who wants to talk to the home
node connects to a helper and asks to be put through; the helper joins the
two connections and forwards bytes. Any reachable node can be a helper, with
limits so it cannot be abused. This is the design libp2p calls "circuit
relay v2"; we are applying it to the Divi node.

## Terms

| Term | Meaning |
|---|---|
| Reachable node | Accepts incoming connections on its Divi port (public IP, port open). |
| Home node | Cannot accept incoming connections (NAT, carrier NAT, firewall). |
| Helper | A reachable node that agrees to forward traffic for one or more home nodes. |
| Node key | A key pair every node makes once and keeps (the same secp256k1 kind the node already uses, but a separate key that never touches coins). The public key (33 bytes) is the node's identity. |
| Relayed address | "Node with key K, reachable via helper H". A new kind of address the network can carry. |

## Part A. The foundation (needed by relay, Tor, and IPv6 alike)

The node today stores every address in a fixed 16-byte slot and gossips
addresses in a message that only fits that slot. Both change:

**A1. Address type.** Addresses become `(kind, bytes)`: IPv4 (4), IPv6 (16),
relayed (33-byte node key + the helper's own address), and room for Tor v3
(32) later. Saving, loading, comparing, printing, and the peers file all use
the new type. Old-style addresses are unchanged on the wire, so nodes that
have not updated keep working; they simply never hear about the new kinds.

**A2. Address gossip.** A second address message that carries the new type,
announced by a capability flag at handshake so each side knows whether the
other understands it (this is Bitcoin's BIP 155 shape; we follow it exactly
where we can so future Tor support is a small step).

**A3. Node key.** Each node makes a secp256k1 key on first start and stores it
in its data folder. The public key is shown in the wallet (Settings >
Network) and is the identity relayed addresses are built on. Nothing about
the key touches coins or the wallet's money keys.

Rollout of Part A is its own node release (69.0.5). Nothing visible changes
for users; every updated node can then carry any address kind.

## Part B. The relay

### B1. Becoming relayed (home node side)

1. On start, a node tries to be reachable as it does today (UPnP, then a
   self-check: it asks two peers to connect back to it).
2. If the self-check fails for 3 minutes, it is a home node. It picks up to
   **3 helpers** from its current outbound peers that advertised the
   `relay` capability, preferring ones in different /16 address blocks and
   different countries.
3. To each helper it sends `relay-register` (its node key, a signature over
   the helper's address and the current time, so a helper cannot claim a
   node it does not hold a live connection to). The helper answers
   `relay-accept` or `relay-refuse` (with a reason: full, not offering).
4. The home node now announces its relayed addresses through the new gossip
   (A2): one address per helper, each signed by the node key. It re-signs
   every 6 hours; addresses older than 24 hours are dropped by everyone.
5. A heartbeat every 30 seconds on each helper link. Two missed heartbeats
   and the helper drops the registration; the home node notices its own
   missed heartbeats the same way and picks a replacement helper.

### B2. Being a helper (reachable node side)

- Offered by default by any reachable node, off with a setting.
- Limits, all settings with defaults: at most **8 relayed nodes**, at most
  **4 relayed connections per relayed node**, at most **2 relayed
  connections from the same /16 block**, and **50 KB/s** per relayed
  connection. Beyond a limit the helper refuses; nothing queues.
- A helper forwards bytes and nothing else. It does not parse the node
  protocol inside the relayed connection.

### B3. Connecting to a relayed node (anyone)

1. A node that wants to reach node K reads K's relayed addresses from its
   address book and picks one helper H (random among those it can reach).
2. It connects to H normally and sends `relay-connect` (K's key).
3. H checks it holds a live registration for K and is under its limits,
   then sends `relay-incoming` to K over K's existing link. K opens a
   **new** outbound connection to H and sends `relay-answer` (a one-time
   token H gave in `relay-incoming`), so the relayed traffic never shares a
   socket with the control link.
4. H now has two sockets, one to the caller and one to K, and joins them:
   every byte in one goes out the other. Both sides then run the ordinary
   Divi handshake and protocol over the joined path, exactly as if they
   were directly connected. To the caller it is a peer whose address is
   "K via H"; to K it is an inbound peer.
5. Either side closing its socket closes the other.

### B4. Encryption

Divi node traffic is in the clear today, so a helper could read what it
forwards (blocks and transactions, all of which are public anyway). Still,
relayed connections wrap the joined path in a simple authenticated
encryption keyed from both node keys (the same construction as BIP 324's
transport, used only on relayed paths at first). This is listed as **B4,
optional for the first release**, because it is independent of everything
above and the first goal is reachability.

### B5. What the wallet shows

Settings > Network: "Reachable: yes / through 3 helpers / no"; the node's
key; who its helpers are; how many nodes it is helping. The map: a
relayed node is a node like any other (blue, counted, in the mesh); the
liveness probe reaches it the same way a peer would (B3), so "grey" comes
to mean "nobody can reach it, not even through a helper". Its hover says
"reachable through <helper name>".

## Messages (the whole new vocabulary)

| Message | From → To | Carries |
|---|---|---|
| capability flag `relay` | handshake | "I offer helping" / "I understand relayed addresses" |
| `relay-register` | home → helper | node key, signature over (helper address, time) |
| `relay-accept` / `relay-refuse` | helper → home | reason code |
| `relay-heartbeat` | both ways | nothing |
| `relay-connect` | caller → helper | target node key |
| `relay-incoming` | helper → home | caller's address block, one-time token |
| `relay-answer` | home → helper (new socket) | the token |
| `relay-error` | helper → caller | unknown node, full, refused |
| gossip (A2) entry | any | relayed address = node key + helper address + signature + time |

Nine things. Nothing else changes in the node protocol.

## What can go wrong, and what the design does about it

| Risk | Answer |
|---|---|
| A helper is abused as a free tunnel | Limits in B2; bytes are only forwarded to a registered Divi node that completes the Divi handshake; the caller's traffic goes nowhere else. |
| Someone announces relayed addresses for a node they do not hold | Every relayed address is signed by the node's own key; a helper only accepts a registration signed for *its* address and *this* time. |
| Helpers vanish | Three helpers, heartbeats, automatic replacement; addresses expire in 24 h so stale ones disappear from everyone's book. |
| The network's "one outbound per /16 block" rule starves relayed nodes | A relayed address is grouped by the *home node's key*, not the helper's IP, so many home nodes behind one helper each count as their own group. |
| A home node's own helpers are all home nodes | Only nodes that passed the self-check (B1 step 1) offer helping. |
| Old nodes never hear of relayed nodes | True until they update; the count of updated nodes is visible on the map (hearts) so the rollout is measurable. |
| Bandwidth cost to helpers | About one extra peer's worth per relayed node, capped by B2; a home node is relayed by at most 3 helpers at once. |

## Rollout

1. **Node 69.0.5: Part A.** New address type, new gossip, node key. Test on
   a private chain: old and new nodes mixed, addresses of every kind
   flowing, the peers file surviving upgrade and downgrade. Roll to all.
2. **Node 69.0.6: Part B without encryption.** Test on a private chain
   with a node made deliberately unreachable (firewalled), prove another
   node connects to it through a helper, prove helper loss and replacement,
   prove every limit refuses. Then a real test: Andy's node.
3. **Wallet:** Settings > Network as in B5; the map treats relayed nodes as
   nodes.
4. **Node 69.0.7: B4 encryption**, if wanted.

Each step is measured by the same number as everything else this month: how
many of the 863 known nodes are alive and reachable on the map.

## Decisions for Geoff

1. **Go / no-go on this design** over Tor and over relay servers.
2. **Helping on by default** for reachable nodes (recommended: yes; it is
   what makes the network reach its own home nodes), with the limits above.
3. **Encryption (B4) in the first release or later** (recommended: later).
4. **Where the spec lives:** it becomes the node's own document in
   `Divi-Blockchain_6.9/docs/` once approved; this copy is for reading.

## Not in this design

- Any server of ours in the path.
- Any change to blocks, transactions, staking or wallet keys.
- Tor. The foundation (Part A) leaves room for it; nothing here needs it.
