#!/usr/bin/env python3
"""End-to-end harness: put real DMT records on a real chain.

Everything the wallet will eventually do in Rust, done here against a throwaway
regtest node so the whole stack can be exercised at once: encoder -> transaction
-> node -> scanner -> ledger -> read API.

The record bytes come from `cargo run --example emit_record`, never from a
literal in this file. A fixture that drifts from the encoder proves nothing.
"""
import json
import subprocess
import sys
import urllib.request
import hashlib

RPC_URL = "http://127.0.0.1:54900/"
RPC_AUTH = "dmt:dmt_local_regtest_only"
CRATE = "/Users/geoffreymccabe/Divi-Blockchain_6.9/contrib/dmt-indexer"

# The token creation fee, in DIVI. Checked by the ledger against the treasury
# address, which is still the all-zero placeholder upstream.
CREATION_FEE = 10000
NETWORK_FEE = 0.001

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "1.0", "id": "e2e", "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"content-type": "application/json"})
    import base64
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(RPC_AUTH.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.load(r)
    except urllib.error.HTTPError as e:
        payload = json.load(e)
    if payload.get("error"):
        raise RuntimeError(f"{method}: {payload['error']}")
    return payload["result"]


def base58check(version, payload20):
    raw = bytes([version]) + payload20
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    full = raw + checksum
    n = int.from_bytes(full, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(full) - len(full.lstrip(b"\x00"))) + out


# Divi P2PKH is 30 on mainnet and 139 on testnet/regtest. The DMT treasury is still the all-zero
# placeholder, so this is the address the fee check currently accepts: an
# address nobody controls. That is exactly why the daemon refuses to index a
# real chain in this state.
TREASURY = base58check(139, bytes(20))  # regtest version byte; mainnet is 30


def emit(*args):
    """Ask the real encoder for a record."""
    out = subprocess.run(
        ["cargo", "run", "--offline", "--quiet", "--example", "emit_record", "--", *[str(a) for a in args]],
        cwd=CRATE, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"encoder refused: {out.stderr.strip()}")
    fields = dict(line.split(maxsplit=1) for line in out.stdout.strip().splitlines())
    return fields["script"]


def send_record(script_hex, pay_fee_to_treasury=False, label="", from_address=None):
    """Build, sign and broadcast a transaction carrying one record.

    `from_address` is not optional in spirit, and this is THE lesson of running
    this against a real chain.

    A record's sender is the address funding vin[0]. Ordinary coin selection
    picks whatever inputs are convenient, which is usually a change address that
    holds no tokens. The record is then perfectly valid, gets mined, costs a fee,
    and is IGNORED, because the sender does not own what it is trying to move.
    Nothing tells the user. The first run of this harness lost three records
    exactly that way: "insufficient balance" and "only the issuer may lock
    supply", both from funding out of the wrong pocket.

    So a wallet sending tokens must constrain coin selection to the address that
    holds them. This mirrors that.
    """
    needed = NETWORK_FEE + (CREATION_FEE if pay_fee_to_treasury else 0)

    # Coinbase outputs on regtest are individually small, so inputs are
    # accumulated until they cover the fee rather than assuming one will.
    pool = rpc("listunspent", [0, 9999999, [from_address]]) if from_address \
        else rpc("listunspent")
    unspent = sorted((u for u in pool if u["spendable"]), key=lambda u: -u["amount"])
    inputs, gathered = [], 0.0
    for u in unspent:
        inputs.append({"txid": u["txid"], "vout": u["vout"]})
        gathered = round(gathered + u["amount"], 8)
        if gathered >= needed + 0.01:
            break
    if gathered < needed + 0.01:
        raise RuntimeError(f"wallet holds {gathered}, need {needed}; mine more blocks")

    # Change goes BACK to the same address, so the next record from this
    # identity can still be funded by it. Sending change elsewhere would move
    # the sender out from under the token holdings.
    change_addr = from_address or rpc("getnewaddress")
    change = round(gathered - needed, 8)

    outputs = {script_hex: 0, change_addr: change}
    if pay_fee_to_treasury:
        outputs[TREASURY] = CREATION_FEE

    raw = rpc("createrawtransaction", [inputs, outputs])
    signed = rpc("signrawtransaction", [raw])
    if not signed.get("complete"):
        raise RuntimeError(f"signing incomplete: {signed.get('errors')}")
    txid = rpc("sendrawtransaction", [signed["hex"]])
    print(f"  sent {label:<24} {txid}")
    return txid


def main():
    print(f"treasury (placeholder, unspendable): {TREASURY}")
    print(f"height before: {rpc('getblockcount')}")

    # One identity owns this token, and every record about it is funded from
    # that address. See the note in send_record: this is not tidiness, it is
    # the difference between the records applying and being ignored.
    issuer = rpc("getnewaddress")
    rpc("sendtoaddress", [issuer, CREATION_FEE + 100])
    rpc("setgenerate", [1])
    print(f"issuer address: {issuer}")

    # 1. Create a token. This is the one record that must pay the registry fee.
    print("\nissuing a token with a premine of 1000")
    issue_txid = send_record(emit("issue", 1000), pay_fee_to_treasury=True,
                             label="ISSUE", from_address=issuer)
    rpc("setgenerate", [1])
    issue_height = rpc("getblockcount")

    # A token's id is (height, index-in-block) of the transaction that issued
    # it, so it is only knowable after the record is mined.
    block = rpc("getblock", [rpc("getblockhash", [issue_height])])
    tx_index = block["tx"].index(issue_txid)
    token = f"{issue_height}:{tx_index}"
    print(f"  token id {token}  (block {issue_height}, tx #{tx_index})")

    # 2. Send some of it to a fresh address.
    recipient = rpc("getnewaddress")
    validated = rpc("validateaddress", [recipient])
    hash160 = validated.get("pubkeyhash") or validated.get("hash160")
    if not hash160:
        # Derive it ourselves if the node does not expose it.
        n = 0
        for ch in recipient:
            n = n * 58 + B58.index(ch)
        decoded = n.to_bytes(25, "big")
        hash160 = decoded[1:21].hex()
    print(f"\nsending 300 to {recipient}")
    send_record(emit("send", issue_height, tx_index, 300, 0, hash160),
                label="TRANSFER", from_address=issuer)

    # 3. Burn some. The only record that ever destroys units.
    print("\nburning 100")
    send_record(emit("burn", issue_height, tx_index, 100), label="BURN", from_address=issuer)

    # 4. Freeze the supply.
    print("\nlocking supply")
    send_record(emit("lock", issue_height, tx_index), label="LOCK SUPPLY", from_address=issuer)

    rpc("setgenerate", [1])
    print(f"\nheight after: {rpc('getblockcount')}")
    print(f"\nTOKEN={token}")
    print(f"RECIPIENT={recipient}")
    print(f"ISSUER={issuer}")
    print(f"ISSUE_HEIGHT={issue_height}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"failed: {e}", file=sys.stderr)
        sys.exit(1)
