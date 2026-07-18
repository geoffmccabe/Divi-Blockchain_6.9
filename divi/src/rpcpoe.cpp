// Copyright (c) 2026 The Divi developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Convenience RPCs for the OP_POE proof-of-existence opcode.
//   createpoe "<64-hex sha256>" (subtype)  -> anchor the hash, return txid
//   verifypoe "<txid>" "<64-hex sha256>"   -> {matched, confirmations, blocktime, subtype}

#include "base58.h"
#include <blockmap.h>
#include <chain.h>
#include <ChainstateManager.h>
#include "init.h"
#include "net.h"
#include "primitives/transaction.h"
#include <rpcprotocol.h>
#include "rpcserver.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include <sync.h>
#include <TransactionDiskAccessor.h>
#include <txmempool.h>
#include "uint256.h"
#include "utilstrencodings.h"
#include <ValidationState.h>
#include "wallet.h"
#include "wallet_ismine.h"
#include <WalletTx.h>

using namespace json_spirit;
using namespace std;

extern CCriticalSection cs_main;

// Anchor economics, in satoshis so the arithmetic is exact.
static const CAmount POE_FEE_SATS = 10000;        // 0.0001 DIVI
static const CAmount POE_MIN_CHANGE_SATS = 1000;  // keep change comfortably above dust
static const unsigned char POE_VERSION = 0x01;

static bool IsSha256HexLower(const string& h)
{
    if (h.size() != 64) return false;
    for (unsigned char c : h)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

Value createpoe(const Array& params, bool fHelp, CWallet* pwallet)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "createpoe \"hash\" ( subtype )\n"
            "\nAnchor a document's SHA-256 hash on-chain in an OP_POE output.\n"
            "\nArguments:\n"
            "1. \"hash\"    (string, required) the 64-hex-char lowercase SHA-256 to anchor\n"
            "2. subtype    (numeric, optional, default=1) 1 = single document, 3 = Merkle batch root\n"
            "\nResult: \"txid\" (string) the anchoring transaction id\n");

    if (!pwallet)
        throw JSONRPCError(RPC_WALLET_ERROR, "No wallet is enabled");

    const string hashHex = params[0].get_str();
    if (!IsSha256HexLower(hashHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "hash must be 64 lowercase hex characters (a SHA-256)");

    int subtype = 1;
    if (params.size() > 1)
        subtype = params[1].get_int();
    if (subtype != 1 && subtype != 3)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "subtype must be 1 (single) or 3 (batch)");

    EnsureWalletIsUnlocked(pwallet);

    // OP_POE payload: version(1) | subtype(1) | digest(32) == 34 bytes.
    vector<unsigned char> payload;
    payload.push_back(POE_VERSION);
    payload.push_back((unsigned char)subtype);
    const vector<unsigned char> digest = ParseHex(hashHex);
    payload.insert(payload.end(), digest.begin(), digest.end());
    CScript poeScript;
    poeScript << OP_POE << payload;

    LOCK2(cs_main, pwallet->getWalletCriticalSection());

    // Smallest spendable output covering fee + non-dust change (satoshi math).
    // Smallest-sufficient keeps big/staking coins untouched and never builds a
    // dust/zero-change tx.
    vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs, false);
    const CAmount need = POE_FEE_SATS + POE_MIN_CHANGE_SATS;
    const COutput* best = NULL;
    for (const COutput& out : vecOutputs) {
        if (!out.fSpendable)
            continue;
        const CAmount v = out.tx->vout[out.i].nValue;
        if (v < need)
            continue;
        if (best == NULL || v < best->tx->vout[best->i].nValue)
            best = &out;
    }
    if (best == NULL)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           "Need a little spendable DIVI (about 0.0002) to anchor a proof");

    const CAmount inValue = best->tx->vout[best->i].nValue;
    const CAmount change = inValue - POE_FEE_SATS;  // >= POE_MIN_CHANGE_SATS by selection

    // Change returns to a fresh key of ours; confirm the node agrees it's ours
    // before signing the input away (defence-in-depth against a tampered node).
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out, please call keypoolrefill first");
    const CKeyID changeKeyID = newKey.GetID();
    const CScript changeScript = GetScriptForDestination(changeKeyID);
    if (IsMine(*pwallet, changeScript) == isminetype::ISMINE_NO)
        throw JSONRPCError(RPC_WALLET_ERROR, "Change address is not owned by this wallet; aborting for safety");

    CMutableTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(best->tx->GetHash(), best->i)));
    tx.vout.push_back(CTxOut(0, poeScript));           // the anchor (0-value, unspendable)
    tx.vout.push_back(CTxOut(change, changeScript));   // change back to us

    if (!SignForOutput(*pwallet, best->tx->vout[best->i], tx, 0, SIGHASH_ALL))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign the anchor transaction");

    const CTransaction finalTx(tx);
    CValidationState state;
    if (!SubmitTransactionToMempool(GetTransactionMemoryPool(), finalTx, state)) {
        if (state.IsInvalid())
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                               strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
        throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
    }
    RelayTransactionToAllPeers(finalTx);
    return finalTx.GetHash().GetHex();
}

Value verifypoe(const Array& params, bool fHelp, CWallet* pwallet)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "verifypoe \"txid\" \"hash\"\n"
            "\nCheck whether a transaction anchors a document's SHA-256 hash in an OP_POE output.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) the anchoring transaction id (64-hex)\n"
            "2. \"hash\"    (string, required) the 64-hex-char lowercase SHA-256 to look for\n"
            "\nResult: { matched, confirmations, blocktime, subtype }\n");

    const string txidHex = params[0].get_str();
    const string hashHex = params[1].get_str();
    if (!IsSha256HexLower(txidHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be 64 lowercase hex characters");
    if (!IsSha256HexLower(hashHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "hash must be 64 lowercase hex characters (a SHA-256)");

    const uint256 txid = ParseHashV(params[0], "txid");
    const vector<unsigned char> wantDigest = ParseHex(hashHex);

    CTransaction tx;
    uint256 hashBlock = 0;
    int confirmations = 0;
    int blockTime = 0;
    {
        LOCK(cs_main);
        if (!GetTransaction(txid, tx, hashBlock, true))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

        const ChainstateManager::Reference chainstate;
        const auto& chain = chainstate->ActiveChain();
        const auto& blockMap = chainstate->GetBlockMap();
        const auto mi = blockMap.find(hashBlock);
        if (mi != blockMap.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex)) {
                confirmations = 1 + chain.Height() - pindex->nHeight;
                blockTime = pindex->GetBlockTime();
            }
        }
    }

    // Scan EVERY output for a matching OP_POE record (a tx may carry more than one).
    bool matched = false;
    int foundSubtype = 0;
    for (const CTxOut& out : tx.vout) {
        const CScript& spk = out.scriptPubKey;
        if (spk.size() < 1 || spk[0] != OP_POE)
            continue;
        CScript::const_iterator pc = spk.begin() + 1;
        opcodetype op;
        vector<unsigned char> data;
        if (!spk.GetOp(pc, op, data))
            continue;
        if (data.size() != 34 || data[0] != POE_VERSION)
            continue;
        const int st = data[1];
        if (st != 1 && st != 3)
            continue;
        if (equal(wantDigest.begin(), wantDigest.end(), data.begin() + 2)) {
            matched = true;
            foundSubtype = st;
            break;
        }
    }

    Object result;
    result.push_back(Pair("matched", matched));
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("blocktime", blockTime));
    result.push_back(Pair("subtype", foundSubtype));
    return result;
}
