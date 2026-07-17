#!/usr/bin/env python3
# Light indexer for Divi on-chain records (the "verify tool + index" piece).
#
# Verifying ONE proof needs no index -- you already have the txid (see
# poe_anchor.py / poe_batch.py `verify`). This tool is for the other job:
# ENUMERATING records. It walks the chain, finds every DVXP OP_META record
# (type 0x01 Proof-of-Existence and type 0x03 Merkle batch root), and stores a
# tiny row per record in a local SQLite file so you can list them or look one
# up instantly without re-scanning.
#
# It is "light": no address/UTXO index, no daemon -- just a append-only catalog
# of metadata records, scanned incrementally (it remembers the last height).
#
# Usage:
#   poe_index.py scan [from_height]     # index new blocks (or from a height)
#   poe_index.py lookup <hash|root>     # which tx/block anchored this 32-byte hash?
#   poe_index.py list [limit]           # recent records
#   poe_index.py stats                  # counts + how far the index has scanned
#
# Env: DIVI_CLI, DIVI_DATADIR (like the other tools), DIVI_INDEX_DB (db path).
import json, os, sqlite3, subprocess, sys

CLI = os.environ.get("DIVI_CLI", "divi-cli")
DATADIR = os.environ.get("DIVI_DATADIR", os.path.expanduser("~/.divi"))
DB_PATH = os.environ.get("DIVI_INDEX_DB", os.path.join(DATADIR, "poe_index.sqlite"))

MAGIC = b"DVXP"
TYPE_POE, TYPE_BATCH = 0x01, 0x03
TYPE_NAME = {TYPE_POE: "poe", TYPE_BATCH: "batch"}


def rpc(*args):
    out = subprocess.run([CLI, f"-datadir={DATADIR}", *[str(a) for a in args]],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"rpc {args[0]} failed: {out.stderr.strip()}")
    s = out.stdout.strip()
    try: return json.loads(s)
    except Exception: return s


def parse_record(script_hex: str):
    """Return {type, digest} for a DVXP PoE (0x01) or batch (0x03) OP_META
    output, else None. Bounds-checked against arbitrary/truncated nulldata."""
    try:
        b = bytes.fromhex(script_hex)
    except ValueError:
        return None
    if len(b) < 2 or b[0] != 0x6a:                 # OP_META (OP_RETURN)
        return None
    if b[1] <= 75:
        plen, off = b[1], 2
    elif b[1] == 0x4c and len(b) >= 3:             # OP_PUSHDATA1
        plen, off = b[2], 3
    else:
        return None
    payload = b[off:off + plen]
    m = len(MAGIC)
    if len(payload) != plen or len(payload) < m + 3 + 32 or payload[:m] != MAGIC:
        return None
    rectype = payload[m + 1]
    if rectype not in (TYPE_POE, TYPE_BATCH):
        return None
    return {"type": rectype, "digest": payload[m + 3:m + 3 + 32].hex()}


def db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS records(
        txid TEXT, vout INTEGER, height INTEGER, block_time INTEGER,
        rectype INTEGER, digest TEXT, PRIMARY KEY(txid, vout))""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_digest ON records(digest)")
    con.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    return con


def get_last_height(con):
    row = con.execute("SELECT v FROM meta WHERE k='last_height'").fetchone()
    return int(row[0]) if row else -1


def cmd_scan(from_height=None):
    con = db()
    tip = int(rpc("getblockcount"))
    start = int(from_height) if from_height is not None else get_last_height(con) + 1
    if start < 0:
        start = 0
    found = 0
    for h in range(start, tip + 1):
        blockhash = rpc("getblockhash", h)
        block = rpc("getblock", blockhash, "true")
        btime = block.get("time")
        for txid in block.get("tx", []):
            try:
                tx = rpc("getrawtransaction", txid, 1)
            except RuntimeError as e:
                if "No information available" in str(e):
                    print("\n>>> This node has no transaction index. Add 'txindex=1' to "
                          "divi.conf and restart the node once with -reindex, then scan again.")
                    sys.exit(3)
                raise
            for v in tx.get("vout", []):
                rec = parse_record(v["scriptPubKey"]["hex"])
                if rec:
                    con.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?)",
                                (txid, v["n"], h, btime, rec["type"], rec["digest"]))
                    found += 1
        con.execute("INSERT OR REPLACE INTO meta VALUES ('last_height', ?)", (str(h),))
        if h % 500 == 0 or h == tip:
            con.commit()
            print(f"  scanned to height {h}/{tip} ({found} records so far)")
    con.commit()
    print(f">>> scan complete: indexed to height {tip}, {found} new record(s) this run.")


def cmd_lookup(digest):
    con = db()
    digest = digest.strip().lower()
    rows = con.execute(
        "SELECT rectype, txid, height, block_time FROM records WHERE digest=? ORDER BY height",
        (digest,)).fetchall()
    if not rows:
        print(">>> not found in the index. (Scan first, or this hash was never anchored.)")
        sys.exit(1)
    for rectype, txid, height, btime in rows:
        kind = TYPE_NAME.get(rectype, f"0x{rectype:02x}")
        note = " (a batch ROOT — the individual documents are proven off-chain)" if rectype == TYPE_BATCH else ""
        print(f"[{kind}] tx {txid}  block {height}  time {btime}{note}")


def cmd_list(limit=20):
    con = db()
    rows = con.execute(
        "SELECT rectype, digest, txid, height, block_time FROM records ORDER BY height DESC LIMIT ?",
        (int(limit),)).fetchall()
    if not rows:
        print("(index empty — run 'scan' first)"); return
    for rectype, digest, txid, height, btime in rows:
        print(f"[{TYPE_NAME.get(rectype, rectype)}] {digest}  block {height}  tx {txid[:16]}…")


def cmd_stats():
    con = db()
    last = get_last_height(con)
    total = con.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    by = con.execute("SELECT rectype, COUNT(*) FROM records GROUP BY rectype").fetchall()
    print(f"index db        : {DB_PATH}")
    print(f"scanned through : height {last}")
    print(f"records total   : {total}")
    for rectype, c in by:
        print(f"  {TYPE_NAME.get(rectype, rectype):<6}      : {c}")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "scan":
        cmd_scan(sys.argv[2] if len(sys.argv) > 2 else None)
    elif cmd == "lookup" and len(sys.argv) == 3:
        cmd_lookup(sys.argv[2])
    elif cmd == "list":
        cmd_list(sys.argv[2] if len(sys.argv) > 2 else 20)
    elif cmd == "stats":
        cmd_stats()
    else:
        print(__doc__); sys.exit(2)


if __name__ == "__main__":
    main()
