#!/usr/bin/env python3
# Reference proof-of-existence anchor for Divi. Hashes a document, embeds the hash
# in an OP_META (OP_RETURN-equivalent) output using the shared DV record envelope,
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

# --- Shared DV metadata record envelope (PoE + future NFTs) ---
# scriptPubKey = OP_META(0x6a) PUSH(payload)
# payload = magic "DV" | version(1) | type(1) | [type-specific]
#   type 0x01 PoE:  hashAlgo(1, 0x01=SHA256) | hash(32)
MAGIC = b"DV"; VERSION = 1; TYPE_POE = 0x01; ALG_SHA256 = 0x01

def build_poe_payload(doc_sha256: bytes) -> bytes:
    assert len(doc_sha256) == 32
    return MAGIC + bytes([VERSION, TYPE_POE, ALG_SHA256]) + doc_sha256   # 37 bytes

def op_meta_script_hex(payload: bytes) -> str:
    assert len(payload) <= 75, "single-byte pushdata path (fits PoE/NFT records)"
    return "6a" + bytes([len(payload)]).hex() + payload.hex()

def parse_poe(script_hex: str):
    b = bytes.fromhex(script_hex)
    if not b or b[0] != 0x6a: return None
    push = b[1]; payload = b[2:2+push]
    if payload[:2] != MAGIC: return None
    return {"version": payload[2], "type": payload[3], "alg": payload[4],
            "hash": payload[5:37].hex()}

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
    u = rpc("listunspent")[0]
    fee = 0.0001
    change = round(float(u["amount"]) - fee, 8)
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

main()
