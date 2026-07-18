#!/usr/bin/env python3
# Merkle-batched Proof-of-Existence for Divi (record type 0x03).
#
# One OP_META output timestamps an unlimited number of documents: we build a
# Merkle tree over their SHA-256 hashes and anchor only the single 32-byte root.
# Each document then keeps a small off-chain proof (its "audit path" to the
# root). Anyone can later recompute the root from a document + its path and
# check it against the on-chain record -- the block's timestamp proves the whole
# batch existed by then. Forkless: same OP_META data carrier as single PoE.
#
# Hashing is RFC 6962 (Certificate Transparency), chosen deliberately:
#     leaf hash = SHA256(0x00 || doc_hash)
#     node hash = SHA256(0x01 || left || right)
# The 0x00 / 0x01 domain-separation prevents the second-preimage / internal-node
# forgery that plain Bitcoin-style Merkle trees allow (CVE-2012-2459: duplicated
# trailing nodes yield the same root). Odd levels are promoted, never duplicated.
#
# Record envelope (shared "DVXP" format, see docs/POE-NFT-RECORD-FORMAT.md):
#   OP_META(0x6a) PUSH(payload)
#   payload = "DVXP"(4) | version(1) | type=0x03 | hashAlg(1)=SHA256 | root(32)
#   => 39 bytes total, identical size to a single-document PoE record.
#
# Usage:
#   poe_batch.py selftest                     # offline Merkle correctness tests
#   poe_batch.py anchor <file1> <file2> ...    # timestamp many files, write proofs
#   poe_batch.py verify <file> <proof.json>    # check one file against the chain
import hashlib, json, re, subprocess, sys, os

CLI = os.environ.get("DIVI_CLI", "divi-cli")
DATADIR = os.environ.get("DIVI_DATADIR", os.path.expanduser("~/.divi"))

HEX64 = re.compile(r"^[0-9a-f]{64}$")
FEE_SATS = 10_000       # 0.0001 DIVI
MIN_CHANGE_SATS = 1_000  # keep change above dust
MAX_PATH = 64            # a real batch never needs a proof path this deep (2**64 leaves)

MAGIC = b"DVXP"; VERSION = 1; TYPE_BATCH = 0x03; ALG_SHA256 = 0x01
BATCH_LEN = len(MAGIC) + 3 + 32   # 39


def rpc(*args):
    out = subprocess.run([CLI, f"-datadir={DATADIR}", *[str(a) for a in args]],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"rpc {args[0]} failed: {out.stderr.strip()}")
    s = out.stdout.strip()
    try: return json.loads(s)
    except Exception: return s


# ── RFC 6962 Merkle tree over a list of 32-byte document hashes ──────────────
def mth(leaves):
    """Merkle Tree Hash of D[n]. leaves: list of 32-byte document hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < n:            # largest power of two strictly less than n
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def audit_path(m, leaves):
    """PATH(m, D[n]): siblings needed to recompute the root from leaf m.
    Returns [(sibling_hash, sibling_is_right)], bottom level first."""
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return audit_path(m, leaves[:k]) + [(mth(leaves[k:]), True)]
    return audit_path(m - k, leaves[k:]) + [(mth(leaves[:k]), False)]


def root_from_proof(doc_hash, path):
    """Recompute the Merkle root from a document hash and its audit path."""
    cur = hashlib.sha256(b"\x00" + doc_hash).digest()
    for sib_hex, sib_is_right in path:
        sib = bytes.fromhex(sib_hex)
        if sib_is_right:
            cur = hashlib.sha256(b"\x01" + cur + sib).digest()
        else:
            cur = hashlib.sha256(b"\x01" + sib + cur).digest()
    return cur


# ── DVXP envelope (type 0x03) + OP_META script ───────────────────────────────
def build_batch_payload(root: bytes) -> bytes:
    assert len(root) == 32
    return MAGIC + bytes([VERSION, TYPE_BATCH, ALG_SHA256]) + root


def op_meta_script_hex(payload: bytes) -> str:
    n = len(payload)
    if n <= 75:
        prefix = bytes([n])
    elif n <= 255:
        prefix = bytes([0x4c, n])          # OP_PUSHDATA1
    else:
        raise ValueError("record too large for OP_PUSHDATA1 (max 255)")
    return "6a" + prefix.hex() + payload.hex()


def parse_batch(script_hex: str):
    """Parse a type-0x03 batch record from an OP_META scriptPubKey, or None.
    Bounds-checked: safe against arbitrary / truncated on-chain nulldata."""
    try:
        b = bytes.fromhex(script_hex)
    except (ValueError, TypeError):
        return None
    if len(b) < 2 or b[0] != 0x6a:
        return None
    if b[1] <= 75:
        plen, off = b[1], 2
    elif b[1] == 0x4c and len(b) >= 3:
        plen, off = b[2], 3
    else:
        return None
    payload = b[off:off + plen]
    if len(payload) != plen:
        return None
    m = len(MAGIC)
    if len(payload) < BATCH_LEN or payload[:m] != MAGIC or payload[m + 1] != TYPE_BATCH:
        return None
    return {"version": payload[m], "type": payload[m + 1], "alg": payload[m + 2],
            "root": payload[m + 3:m + 3 + 32].hex()}


def sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.digest()


# ── Commands ─────────────────────────────────────────────────────────────────
def cmd_anchor(paths):
    if not paths:
        print("give one or more files to timestamp"); sys.exit(2)
    leaves = [sha256_file(p) for p in paths]
    root = mth(leaves)
    print(f"documents       : {len(leaves)}")
    print(f"merkle root     : {root.hex()}")

    payload = build_batch_payload(root)
    print(f"record bytes    : {len(payload)} (limit 603)")

    # Smallest spendable output that covers the fee plus non-dust change, with
    # satoshi math -- avoids negative/zero/dust change (which the node rejects).
    need = FEE_SATS + MIN_CHANGE_SATS
    ok = [x for x in rpc("listunspent")
          if x.get("spendable", True) and round(float(x["amount"]) * 1e8) >= need]
    if not ok:
        print(">>> FAILED: no spendable output large enough (need ~0.0002 DIVI)."); sys.exit(1)
    u = min(ok, key=lambda x: round(float(x["amount"]) * 1e8))
    change = (round(float(u["amount"]) * 1e8) - FEE_SATS) / 1e8
    change_addr = rpc("getnewaddress")
    inputs = json.dumps([{"txid": u["txid"], "vout": u["vout"]}])
    try:                                         # 'data' output convention...
        outputs = json.dumps({change_addr: change, "data": payload.hex()})
        raw = rpc("createrawtransaction", inputs, outputs)
    except RuntimeError:                         # ...or raw OP_META script as the key
        outputs = json.dumps({change_addr: change, op_meta_script_hex(payload): 0})
        raw = rpc("createrawtransaction", inputs, outputs)
    signed = rpc("signrawtransaction", raw)
    assert signed["complete"], "sign incomplete"
    txid = rpc("sendrawtransaction", signed["hex"])
    rpc("setgenerate", 1)                       # mine it into a block
    print(f"anchored txid   : {txid}")

    # write one small proof file per document
    for i, p in enumerate(paths):
        proof = {
            "txid": txid,
            "type": "divi-poe-batch-1",
            "doc_sha256": leaves[i].hex(),
            "index": i,
            "count": len(leaves),
            "root": root.hex(),
            "path": [[s.hex(), r] for (s, r) in audit_path(i, leaves)],
        }
        out = p + ".diviproof.json"
        with open(out, "w") as f:
            json.dump(proof, f, indent=2)
        # sanity: the proof we just wrote must reproduce the root
        assert root_from_proof(leaves[i], proof["path"]) == root
        print(f"  proof         : {out}")
    print("\n>>> BATCH ANCHORED. Keep the .diviproof.json files.")


def _validate_proof(proof):
    """Structural checks so a hostile/garbled proof fails cleanly (not a crash),
    and so proof['txid'] can never smuggle a leading-dash CLI option into rpc()."""
    if not isinstance(proof, dict):
        return "proof is not a JSON object"
    if not (isinstance(proof.get("txid"), str) and HEX64.match(proof["txid"])):
        return "proof 'txid' is not a 64-hex transaction id"
    if not (isinstance(proof.get("doc_sha256"), str) and HEX64.match(proof["doc_sha256"])):
        return "proof 'doc_sha256' is not a 64-hex hash"
    path = proof.get("path")
    if not isinstance(path, list) or len(path) > MAX_PATH:
        return "proof 'path' is missing, not a list, or too long"
    for step in path:
        if (not isinstance(step, list) or len(step) != 2
                or not (isinstance(step[0], str) and HEX64.match(step[0]))
                or not isinstance(step[1], bool)):
            return "proof 'path' has a malformed step"
    return None


def cmd_verify(path, proof_path):
    try:
        with open(proof_path) as f:
            proof = json.load(f)
    except (OSError, ValueError) as e:
        print(f">>> FAILED: cannot read proof file ({e})."); sys.exit(1)
    err = _validate_proof(proof)
    if err:
        print(f">>> FAILED: {err}."); sys.exit(1)

    doc_hash = sha256_file(path)
    if doc_hash.hex() != proof["doc_sha256"]:
        print(">>> FAILED: this file does not match the hash in the proof."); sys.exit(1)

    recomputed = root_from_proof(doc_hash, proof["path"])
    onchain = rpc("getrawtransaction", proof["txid"], 1)
    conf = onchain.get("confirmations", 0)
    rec = None
    for v in onchain["vout"]:
        r = parse_batch(v["scriptPubKey"]["hex"])
        if r:
            rec = r; break
    block_time = onchain.get("blocktime")

    ok = rec and rec["root"] == recomputed.hex() and conf >= 1
    print(f"recomputed root : {recomputed.hex()}")
    print(f"on-chain root   : {rec['root'] if rec else '(no batch record found)'}")
    print(f"confirmations   : {conf}")
    print(f"block time      : {block_time}")
    print("\n>>> VERIFIED: file was in the batch timestamped at the block time above."
          if ok else "\n>>> FAILED: file is not proven by this transaction.")
    sys.exit(0 if ok else 1)


def cmd_selftest():
    """Offline correctness: every leaf in trees of many sizes must prove, and
    any tamper (wrong hash, swapped sibling, flipped direction) must fail."""
    import random
    random.seed(1)
    checks = 0
    for n in list(range(1, 33)) + [64, 100, 257]:
        leaves = [hashlib.sha256(f"doc-{n}-{i}".encode()).digest() for i in range(n)]
        root = mth(leaves)
        for i in range(n):
            path = [(s.hex(), r) for (s, r) in audit_path(i, leaves)]
            assert root_from_proof(leaves[i], path) == root, f"n={n} i={i} path failed"
            # tamper: wrong document must not verify
            bad = hashlib.sha256(f"forged-{i}".encode()).digest()
            assert root_from_proof(bad, path) != root, f"n={n} i={i} forged hash verified!"
            # tamper: flip a direction bit (if any) must not verify
            if path:
                j = random.randrange(len(path))
                flipped = list(path)
                flipped[j] = (flipped[j][0], not flipped[j][1])
                assert root_from_proof(leaves[i], flipped) != root, f"n={n} i={i} flipped dir verified!"
            checks += 1
    # known single-leaf vector (RFC 6962 leaf hashing)
    d = bytes.fromhex("00" * 32)
    assert mth([d]).hex() == hashlib.sha256(b"\x00" + d).digest().hex()
    # envelope round-trips through the on-chain script parser
    root = mth([hashlib.sha256(b"x").digest()])
    rec = parse_batch(op_meta_script_hex(build_batch_payload(root)))
    assert rec and rec["root"] == root.hex() and rec["type"] == TYPE_BATCH
    # parser rejects junk / single PoE records / truncation
    for bad in ["", "6a", "6a2700", "ff00", op_meta_script_hex(b"DVXP" + bytes([1, 1, 1]) + b"\x00" * 32)]:
        assert parse_batch(bad) is None, f"parser should reject {bad!r}"
    print(f">>> SELFTEST PASSED ({checks} leaf proofs across many tree sizes; "
          f"tamper + envelope + parser checks OK)")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "selftest":
        cmd_selftest()
    elif cmd == "anchor":
        cmd_anchor(sys.argv[2:])
    elif cmd == "verify" and len(sys.argv) == 4:
        cmd_verify(sys.argv[2], sys.argv[3])
    else:
        print(__doc__); sys.exit(2)


if __name__ == "__main__":
    main()
