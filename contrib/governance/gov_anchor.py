#!/usr/bin/env python3
# Reference anchor for Divi Governance records. Uses the shared "DVXP" OP_META
# envelope (same one PoE/NFD/DMT/Names use), type 0x06 = GOVERNANCE. Proves both
# governance record types round-trip on-chain end to end on regtest:
#   - subtype 0x01 PROPOSAL OPEN : freezes the proposal doc + voter snapshot
#   - subtype 0x02 TALLY         : freezes the final result + vote Merkle root
# No consensus change: OP_META already carries up to 603 bytes, on by default.
#
# Run against the isolated spike regtest:
#   DIVI_CLI=/Users/geoffreymccabe/Divi-Blockchain_6.9/divi/src/divi-cli \
#   DIVI_DATADIR=<gov-regtest datadir> python3 gov_anchor.py
import hashlib, json, subprocess, sys, os, struct

CLI = os.environ.get("DIVI_CLI", "divi-cli")
DATADIR = os.environ.get("DIVI_DATADIR", os.path.expanduser("~/.divi"))

def rpc(*args):
    out = subprocess.run([CLI, f"-datadir={DATADIR}", *[str(a) for a in args]],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"rpc {args[0]} failed: {out.stderr.strip()}")
    s = out.stdout.strip()
    try: return json.loads(s)
    except Exception: return s

# ---- Shared DVXP envelope (see docs/DVXP-INTEGRATION-GUIDE.md) --------------
#   payload = "DVXP"(4) | version(1) | type(1) | subtype(1) | body
MAGIC = b"DVXP"; VERSION = 1
TYPE_GOV = 0x06                 # Governance (0x01 PoE, 0x02 NFD, 0x03 batch, 0x04 DMT, 0x05 Names)
SUB_PROPOSAL = 0x01
SUB_TALLY    = 0x02
ALG_SHA256   = 0x01

# proposal "kind" so the indexer can route without fetching Arweave
KIND_FUNDING = 0x01; KIND_ELECTION = 0x02; KIND_META = 0x03; KIND_POLL = 0x04

def _hdr(subtype): return MAGIC + bytes([VERSION, TYPE_GOV, subtype])

def build_proposal(kind, snapshot_height, doc_sha256, arweave_id_raw):
    # body: kind(1) | snapshotHeight(4 LE) | hashAlg(1) | docHash(32) | arweaveId(32) = 70
    assert len(doc_sha256) == 32 and len(arweave_id_raw) == 32
    body = bytes([kind]) + struct.pack("<I", snapshot_height) + bytes([ALG_SHA256]) + doc_sha256 + arweave_id_raw
    return _hdr(SUB_PROPOSAL) + body

def build_tally(prop_height, prop_txindex, snapshot_height, passed, yes_sat, no_sat, votes_root):
    # body: propHeight(4) | propTxIndex(2) | snapshotHeight(4) | outcome(1) | yes(8) | no(8) | votesRoot(32) = 59
    assert len(votes_root) == 32
    body = (struct.pack("<I", prop_height) + struct.pack("<H", prop_txindex) +
            struct.pack("<I", snapshot_height) + bytes([1 if passed else 0]) +
            struct.pack("<Q", yes_sat) + struct.pack("<Q", no_sat) + votes_root)
    return _hdr(SUB_TALLY) + body

def op_meta_script_hex(payload: bytes) -> str:
    n = len(payload)
    if n <= 75: prefix = bytes([n])
    elif n <= 255: prefix = bytes([0x4c, n])   # OP_PUSHDATA1
    else: raise ValueError("record too large for OP_PUSHDATA1")
    return "6a" + prefix.hex() + payload.hex()

def _payload_from_script(script_hex):
    b = bytes.fromhex(script_hex)
    if len(b) < 2 or b[0] != 0x6a: return None
    if b[1] <= 75: plen, off = b[1], 2
    elif b[1] == 0x4c and len(b) >= 3: plen, off = b[2], 3
    else: return None
    p = b[off:off+plen]
    return p if len(p) == plen else None

def parse_gov(script_hex):
    p = _payload_from_script(script_hex)
    if not p or len(p) < 7 or p[:4] != MAGIC or p[5] != TYPE_GOV: return None
    version, subtype, body = p[4], p[6], p[7:]
    if subtype == SUB_PROPOSAL and len(body) >= 70:
        return {"type": "proposal", "version": version, "kind": body[0],
                "snapshotHeight": struct.unpack("<I", body[1:5])[0], "hashAlg": body[5],
                "docHash": body[6:38].hex(), "arweaveId": body[38:70].hex()}
    if subtype == SUB_TALLY and len(body) >= 59:
        return {"type": "tally", "version": version,
                "propHeight": struct.unpack("<I", body[0:4])[0],
                "propTxIndex": struct.unpack("<H", body[4:6])[0],
                "snapshotHeight": struct.unpack("<I", body[6:10])[0],
                "passed": bool(body[10]),
                "yesSat": struct.unpack("<Q", body[11:19])[0],
                "noSat": struct.unpack("<Q", body[19:27])[0],
                "votesRoot": body[27:59].hex()}
    return None

def anchor(payload):
    """Fund + build + sign + broadcast + mine an OP_META tx; return its txid."""
    script = op_meta_script_hex(payload)
    u = rpc("listunspent")[0]
    fee = 0.0001
    change = round(float(u["amount"]) - fee, 8)
    inputs = json.dumps([{"txid": u["txid"], "vout": u["vout"]}])
    outputs = json.dumps({rpc("getnewaddress"): change, "data": payload.hex()})
    try:
        raw = rpc("createrawtransaction", inputs, outputs)
    except RuntimeError:
        outputs = json.dumps({rpc("getnewaddress"): change, script: 0})
        raw = rpc("createrawtransaction", inputs, outputs)
    signed = rpc("signrawtransaction", raw)
    assert signed["complete"], "sign incomplete"
    txid = rpc("sendrawtransaction", signed["hex"])
    rpc("setgenerate", 1)
    return txid

def read_back(txid):
    onchain = rpc("getrawtransaction", txid, 1)
    dvout = [v for v in onchain["vout"] if v["scriptPubKey"]["hex"].startswith("6a")][0]
    rec = parse_gov(dvout["scriptPubKey"]["hex"])
    # locate (blockHeight, txIndex) = the DVXP-convention record ID
    blk = rpc("getblock", onchain["blockhash"])
    return rec, blk["height"], blk["tx"].index(txid), onchain.get("confirmations", 0)

def main():
    fails = 0
    tip = rpc("getblockcount")

    # ---- 1. PROPOSAL OPEN ----
    doc = b"Proposal: fund a Divi mobile staking widget. 12,000 DIVI, 4 milestones."
    doc_hash = hashlib.sha256(doc).digest()
    arweave_id = hashlib.sha256(b"fake-arweave-tx-id-for-regtest").digest()  # stand-in 32B pointer
    p_payload = build_proposal(KIND_FUNDING, tip, doc_hash, arweave_id)
    print(f"proposal record : {len(p_payload)} bytes (limit 603)")
    p_txid = anchor(p_payload)
    p_rec, p_h, p_idx, p_conf = read_back(p_txid)
    print(f"  anchored txid={p_txid[:16]}.. height={p_h} txindex={p_idx} conf={p_conf}")
    print(f"  parsed back   : {p_rec}")
    for label, ok in [
        ("magic/type/subtype parse", p_rec is not None and p_rec["type"] == "proposal"),
        ("docHash round-trips", p_rec and p_rec["docHash"] == doc_hash.hex()),
        ("arweaveId round-trips", p_rec and p_rec["arweaveId"] == arweave_id.hex()),
        ("snapshotHeight round-trips", p_rec and p_rec["snapshotHeight"] == tip),
        ("kind = funding", p_rec and p_rec["kind"] == KIND_FUNDING),
        ("confirmed on-chain", p_conf >= 1),
    ]:
        fails += not ok; print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

    # ---- 2. TALLY referencing that proposal by (height, txindex) ----
    votes_root = hashlib.sha256(b"merkle-root-over-signed-votes").digest()
    yes_sat, no_sat = 8_000 * 100000000, 3_000 * 100000000
    t_payload = build_tally(p_h, p_idx, tip, True, yes_sat, no_sat, votes_root)
    print(f"tally record    : {len(t_payload)} bytes (limit 603)")
    t_txid = anchor(t_payload)
    t_rec, _, _, t_conf = read_back(t_txid)
    print(f"  parsed back   : {t_rec}")
    for label, ok in [
        ("tally parse", t_rec is not None and t_rec["type"] == "tally"),
        ("references proposal (height,txindex)", t_rec and t_rec["propHeight"] == p_h and t_rec["propTxIndex"] == p_idx),
        ("votesRoot round-trips", t_rec and t_rec["votesRoot"] == votes_root.hex()),
        ("outcome=passed", t_rec and t_rec["passed"] is True),
        ("yes/no weights round-trip", t_rec and t_rec["yesSat"] == yes_sat and t_rec["noSat"] == no_sat),
        ("confirmed on-chain", t_conf >= 1),
    ]:
        fails += not ok; print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

    print("\nRESULT:", "ALL PASS" if fails == 0 else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
