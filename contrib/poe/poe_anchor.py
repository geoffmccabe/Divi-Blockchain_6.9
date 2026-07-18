#!/usr/bin/env python3
# Reference proof-of-existence anchor for Divi. Hashes a document, embeds the hash
# in an OP_META (OP_RETURN-equivalent) output using the shared "DVXP" record envelope,
# funds+signs+broadcasts the tx, mines it, then reads it back from the chain and
# confirms the anchored hash matches. End-to-end proof that PoE works on Divi.
import hashlib, json, subprocess, sys, os

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

# --- Shared "DVXP" metadata record envelope (PoE + future NFTs) ---
# scriptPubKey = OP_META(0x6a) PUSH(payload)
# payload = magic "DVXP" (4) | version(1) | type(1) | [type-specific]
#   type 0x01 PoE:  hashAlgo(1, 0x01=SHA256) | hash(32)   => 39 bytes total
# A 4-byte magic keeps false-matches against unrelated OP_META data negligible
# before the NFT layer locks the format in.
MAGIC = b"DVXP"; VERSION = 1; TYPE_POE = 0x01; ALG_SHA256 = 0x01
POE_LEN = len(MAGIC) + 3 + 32   # 39

def build_poe_payload(doc_sha256: bytes) -> bytes:
    assert len(doc_sha256) == 32
    return MAGIC + bytes([VERSION, TYPE_POE, ALG_SHA256]) + doc_sha256

def op_meta_script_hex(payload: bytes) -> str:
    # OP_META then a minimal push. Handles the >75-byte records the future NFT /
    # batch types will need (OP_PUSHDATA1), matching parse below.
    n = len(payload)
    if n <= 75:
        prefix = bytes([n])
    elif n <= 255:
        prefix = bytes([0x4c, n])          # OP_PUSHDATA1
    else:
        raise ValueError("record too large for OP_PUSHDATA1 (max 255)")
    return "6a" + prefix.hex() + payload.hex()

def parse_poe(script_hex: str):
    """Parse a PoE record from an OP_META scriptPubKey, or None if it isn't one.
    Bounds-checked: safe against arbitrary/truncated on-chain nulldata outputs."""
    try:
        b = bytes.fromhex(script_hex)
    except (ValueError, TypeError):
        return None
    if len(b) < 2 or b[0] != 0x6a:
        return None
    if b[1] <= 75:                          # single-byte push
        plen, off = b[1], 2
    elif b[1] == 0x4c and len(b) >= 3:      # OP_PUSHDATA1
        plen, off = b[2], 3
    else:
        return None
    payload = b[off:off + plen]
    if len(payload) != plen:                # truncated push
        return None
    m = len(MAGIC)
    if len(payload) < POE_LEN or payload[:m] != MAGIC or payload[m + 1] != TYPE_POE:
        return None
    return {"version": payload[m], "type": payload[m + 1], "alg": payload[m + 2],
            "hash": payload[m + 3:m + 3 + 32].hex()}

def main():
    # 1. the "document" to timestamp + its SHA-256
    doc = b"Divi proof-of-existence reference test document."
    h = hashlib.sha256(doc).digest()
    print("document sha256 :", h.hex())

    payload = build_poe_payload(h)
    script = op_meta_script_hex(payload)
    print("record bytes    :", len(payload), "(limit 603)")
    print("OP_META script  :", script)

    # 2. pick a UTXO to fund the anchor
    # Smallest spendable output covering fee + non-dust change (satoshi math).
    fee_sats, min_change_sats = 10_000, 1_000
    ok = [x for x in rpc("listunspent")
          if x.get("spendable", True) and round(float(x["amount"]) * 1e8) >= fee_sats + min_change_sats]
    if not ok:
        print(">>> FAILED: no spendable output large enough (need ~0.0002 DIVI)."); sys.exit(1)
    u = min(ok, key=lambda x: round(float(x["amount"]) * 1e8))
    change = (round(float(u["amount"]) * 1e8) - fee_sats) / 1e8
    change_addr = rpc("getnewaddress")

    # 3. build raw tx: 1 input, change output + the OP_META data output (0 value)
    inputs = json.dumps([{"txid": u["txid"], "vout": u["vout"]}])
    outputs = json.dumps({change_addr: change, "data": payload.hex()})  # try 'data' convention
    try:
        raw = rpc("createrawtransaction", inputs, outputs)
    except RuntimeError:
        # fallback: raw hex script as the output key
        outputs = json.dumps({change_addr: change, script: 0})
        raw = rpc("createrawtransaction", inputs, outputs)
    print("raw tx built    :", raw[:40], "...")

    # 4. confirm the node parses our OP_META output before broadcasting
    dec = rpc("decoderawtransaction", raw)
    data_vout = [v for v in dec["vout"] if v["scriptPubKey"]["hex"].startswith("6a")]
    assert data_vout, "no OP_META output in tx!"
    print("node sees data  : type=%s asm=%s" % (data_vout[0]["scriptPubKey"].get("type"),
                                                 data_vout[0]["scriptPubKey"]["asm"][:40]))

    # 5. sign + broadcast + mine it into a block
    signed = rpc("signrawtransaction", raw)
    assert signed["complete"], "sign incomplete"
    txid = rpc("sendrawtransaction", signed["hex"])
    print("broadcast txid  :", txid)
    rpc("setgenerate", 1)  # mine it

    # 6. read it BACK from the chain and verify the anchored hash
    onchain = rpc("getrawtransaction", txid, 1)
    conf = onchain.get("confirmations", 0)
    dvout = [v for v in onchain["vout"] if v["scriptPubKey"]["hex"].startswith("6a")][0]
    rec = parse_poe(dvout["scriptPubKey"]["hex"])
    print("confirmations   :", conf)
    print("recovered record:", rec)
    ok = rec and rec["hash"] == h.hex() and conf >= 1
    print("\n>>> PoE ANCHOR VERIFIED ON-CHAIN" if ok else "\n>>> FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
