#include "PeerRelay.h"

#include "Node.h"
#include "NodeKey.h"
#include "NetworkLocalAddressHelpers.h"
#include "net.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "streams.h"
#include "version.h"
#include "sync.h"
#include "Logging.h"
#include "utiltime.h"
#include "utilstrencodings.h"
#include "Settings.h"
#include "timedata.h"

#include <boost/thread.hpp>
#include <map>
#include <set>

extern Settings& settings;

namespace PeerRelay
{
namespace
{
CCriticalSection cs_relay;

/* ---- HELPER state ---- */
struct Registration {
    NodeId control;          // the home node's ordinary connection to us
    int64_t since;
    unsigned int connections; // relayed connections open right now
    std::map<std::vector<unsigned char>, unsigned int> perGroup; // caller group -> count
};
std::map<std::vector<unsigned char>, Registration> g_registered; // key -> registration

struct Pending {
    NodeId caller;
    std::vector<unsigned char> key;
    std::vector<unsigned char> callerGroup;
    int64_t expires;
};
std::map<std::vector<unsigned char>, Pending> g_pending; // token -> pending
/* Which pipe belongs to which registration, to count connections down. */
std::map<NodeId, std::vector<unsigned char>> g_pipeOwner;

/* ---- HOME state ---- */
struct HelperLink {
    NodeId node;
    CService helperAddr;     // the address we dialled
    bool accepted;
    int64_t askedAt;
};
std::map<NodeId, HelperLink> g_helpers;
int64_t g_startedAt = 0;
int64_t g_lastAnnounce = 0;
bool g_forceHome = false;

std::vector<unsigned char> RandomToken()
{
    std::vector<unsigned char> t(16);
    GetRandBytes(t.data(), t.size());
    return t;
}

uint256 RegisterHash(const std::vector<unsigned char>& key, const std::string& helperAddr, int64_t time)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("DiviRelayRegister") << key << helperAddr << time;
    return ss.GetHash();
}

void CountDown(NodeId pipe)
{
    auto it = g_pipeOwner.find(pipe);
    if (it == g_pipeOwner.end()) return;
    auto reg = g_registered.find(it->second);
    if (reg != g_registered.end() && reg->second.connections > 0) reg->second.connections--;
    g_pipeOwner.erase(it);
}

/* ---- raw-socket framing for the two handshakes ----
   A message on the wire is a header plus payload, exactly as PushMessage
   makes one; these do the same by hand on a socket that has no CNode yet. */
bool SendRaw(SOCKET hSocket, const char* command, const CDataStream& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    NetworkMessageSerializer::BeginMessage(ss, command);
    ss.write(&payload[0], payload.size());
    unsigned int size = 0;
    NetworkMessageSerializer::EndMessage(ss, size);
    size_t sent = 0;
    while (sent < ss.size()) {
        int n = send(hSocket, &ss[0] + sent, ss.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool ReadRaw(SOCKET hSocket, std::string& command, CDataStream& payload, int timeoutMs)
{
    CNetMessage msg(SER_NETWORK, PROTOCOL_VERSION);
    int64_t deadline = GetTimeMillis() + timeoutMs;
    char buf[4096];
    while (!msg.complete()) {
        int64_t left = deadline - GetTimeMillis();
        if (left <= 0) return false;
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(hSocket, &fdset);
        struct timeval tv;
        tv.tv_sec = left / 1000;
        tv.tv_usec = (left % 1000) * 1000;
        int r = select(hSocket + 1, &fdset, NULL, NULL, &tv);
        if (r <= 0) return false;
        int n = recv(hSocket, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        const char* p = buf;
        int remaining = n;
        while (remaining > 0) {
            int handled = msg.in_data ? msg.readData(p, remaining) : msg.readHeader(p, remaining);
            if (handled < 0) return false;
            p += handled;
            remaining -= handled;
            if (msg.complete()) break;
        }
    }
    command = msg.hdr.GetCommand();
    payload = msg.vRecv;
    return true;
}

bool IsHomeNode()
{
    if (g_forceHome) return true;
    if (!ClientEnabled()) return false;
    if (g_startedAt == 0) g_startedAt = GetTime();
    if (GetTime() - g_startedAt < UNREACHABLE_AFTER_SECONDS) return false;
    return GetInboundPeerCount() == 0 && GetOutboundPeerCount() >= 2;
}

void AnnounceRelayedAddresses()
{
    std::vector<CAddress> mine = LocalRelayedAddresses();
    if (mine.empty()) return;
    ForEachNode([&](CNode* pnode) {
        if (!pnode->fWantsAddrV2 || pnode->fRelayPipe) return;
        for (const CAddress& a : mine) pnode->PushAddress(a);
    });
    g_lastAnnounce = GetTime();
}
} // namespace

bool HelpingEnabled()
{
    return settings.GetBoolArg("-relayhelper", true);
}

bool ClientEnabled()
{
    return settings.GetBoolArg("-relayclient", true);
}

void ForceHomeNodeForTesting(bool on)
{
    LOCK(cs_relay);
    g_forceHome = on;
}

bool IsRelayCommand(const std::string& c)
{
    return c == "rlyregister" || c == "rlyaccept" || c == "rlyrefuse" || c == "rlyconnect"
        || c == "rlyok" || c == "rlyerror" || c == "rlyincoming" || c == "rlyanswer";
}

bool IsPreVersionCommand(const std::string& c)
{
    return c == "rlyconnect" || c == "rlyanswer";
}

std::vector<CAddress> LocalRelayedAddresses()
{
    std::vector<CAddress> out;
    std::vector<unsigned char> key = GetNodeKeyBytes();
    if (key.empty()) return out;
    LOCK(cs_relay);
    for (const auto& h : g_helpers) {
        if (!h.second.accepted) continue;
        CNetAddr r;
        if (!r.SetRelay(key, h.second.helperAddr)) continue;
        CAddress a(CService(r, h.second.helperAddr.GetPort()), GetLocalServices());
        a.nTime = GetAdjustedTime();
        out.push_back(a);
    }
    return out;
}

void OnPeerDisconnected(CNode* pnode)
{
    LOCK(cs_relay);
    const NodeId id = pnode->GetId();
    /* helper side */
    for (auto it = g_registered.begin(); it != g_registered.end();) {
        if (it->second.control == id) {
            LogPrint("net", "relay: registration of %s ended (peer=%d gone)\n", HexStr(it->first).substr(0, 12), id);
            it = g_registered.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = g_pending.begin(); it != g_pending.end();) {
        if (it->second.caller == id) it = g_pending.erase(it); else ++it;
    }
    CountDown(id);
    /* home side */
    if (g_helpers.erase(id)) LogPrint("net", "relay: helper peer=%d gone\n", id);
}

static bool Refuse(CNode* pfrom, unsigned char reason)
{
    pfrom->PushMessage("rlyrefuse", reason);
    return true;
}

bool HandleMessage(CNode* pfrom, const std::string& command, CDataStream& vRecv)
{
    LOCK(cs_relay);
    const NodeId id = pfrom->GetId();

    /* ---- HELPER: a home node asks to be relayed through us ---- */
    if (command == "rlyregister") {
        std::vector<unsigned char> key, sig;
        std::string helperAddr;
        int64_t time = 0;
        vRecv >> key >> helperAddr >> time >> sig;
        if (!HelpingEnabled()) return Refuse(pfrom, 1);            // not offering
        if (key.size() != RELAY_KEY_SIZE) return false;             // junk: drop the peer
        if (std::llabs(GetAdjustedTime() - time) > REGISTER_TIME_SLACK) return Refuse(pfrom, 2); // stale
        CPubKey pub(key);
        if (!pub.IsFullyValid() || !pub.Verify(RegisterHash(key, helperAddr, time), sig)) return false;
        auto have = g_registered.find(key);
        if (have != g_registered.end() && have->second.control != id) return Refuse(pfrom, 3); // held elsewhere
        if (have == g_registered.end() && g_registered.size() >= MAX_RELAYED_NODES) return Refuse(pfrom, 4); // full
        Registration& reg = g_registered[key];
        reg.control = id;
        if (have == g_registered.end()) { reg.since = GetTime(); reg.connections = 0; }
        pfrom->PushMessage("rlyaccept");
        LogPrint("net", "relay: helping %s (peer=%d)\n", HexStr(key).substr(0, 12), id);
        return true;
    }

    /* ---- HOME: a helper's answer ---- */
    if (command == "rlyaccept" || command == "rlyrefuse") {
        auto h = g_helpers.find(id);
        if (h == g_helpers.end()) return true;                      // never asked: ignore
        if (command == "rlyaccept") {
            h->second.accepted = true;
            LogPrintf("relay: reachable through helper %s\n", h->second.helperAddr.ToString());
            AnnounceRelayedAddresses();
        } else {
            unsigned char reason = 0;
            vRecv >> reason;
            LogPrint("net", "relay: helper %s refused (%d)\n", h->second.helperAddr.ToString(), reason);
            g_helpers.erase(h);
        }
        return true;
    }

    /* ---- HELPER: a caller wants to be put through ---- */
    if (command == "rlyconnect") {
        std::vector<unsigned char> key;
        vRecv >> key;
        auto reg = g_registered.find(key);
        unsigned char err = 0;
        std::vector<unsigned char> group = pfrom->GetCAddress().GetGroup();
        if (reg == g_registered.end()) err = 1;                                   // unknown node
        else if (reg->second.connections >= MAX_CONNECTIONS_PER_NODE) err = 2;      // that node is full
        else if (reg->second.perGroup[group] >= MAX_CONNECTIONS_PER_GROUP) err = 3; // too many from your block
        if (err) {
            pfrom->PushMessage("rlyerror", err);
            pfrom->FlagForDisconnection();
            return true;
        }
        std::vector<unsigned char> token = RandomToken();
        g_pending[token] = Pending{ id, key, group, GetTime() + PENDING_SECONDS };
        bool told = WithNodeById(reg->second.control, [&](CNode* control) {
            control->PushMessage("rlyincoming", token);
        });
        if (!told) {
            g_pending.erase(token);
            pfrom->PushMessage("rlyerror", (unsigned char)1);
            pfrom->FlagForDisconnection();
        }
        return true;
    }

    /* ---- HOME: a helper says someone is calling ---- */
    if (command == "rlyincoming") {
        std::vector<unsigned char> token;
        vRecv >> token;
        auto h = g_helpers.find(id);
        if (h == g_helpers.end() || !h->second.accepted) return true; // not our helper: ignore
        const CService helper = h->second.helperAddr;
        /* Answering means opening a new connection, which blocks: not on the
           message thread. */
        boost::thread(boost::bind(&AcceptRelayedConnection, helper, token)).detach();
        return true;
    }

    /* ---- HELPER: the home node answered on a fresh connection ---- */
    if (command == "rlyanswer") {
        std::vector<unsigned char> token;
        vRecv >> token;
        auto p = g_pending.find(token);
        if (p == g_pending.end() || p->second.expires < GetTime()) {
            if (p != g_pending.end()) g_pending.erase(p);
            pfrom->PushMessage("rlyerror", (unsigned char)4);        // too late
            pfrom->FlagForDisconnection();
            return true;
        }
        Pending pending = p->second;
        g_pending.erase(p);
        auto reg = g_registered.find(pending.key);
        bool joined = WithNodeById(pending.caller, [&](CNode* caller) {
            /* Both told first, then joined: the ok goes out ahead of any
               forwarded bytes because sends keep their order. */
            caller->PushMessage("rlyok");
            pfrom->PushMessage("rlyok");
            caller->SpliceWith(pfrom);
            pfrom->fRelayed = true;
            caller->fRelayed = true;
        });
        if (!joined) {
            pfrom->PushMessage("rlyerror", (unsigned char)5);        // caller gave up
            pfrom->FlagForDisconnection();
            return true;
        }
        if (reg != g_registered.end()) {
            reg->second.connections++;
            reg->second.perGroup[pending.callerGroup]++;
            g_pipeOwner[id] = pending.key;
            g_pipeOwner[pending.caller] = pending.key;
        }
        LogPrint("net", "relay: joined peer=%d to %s\n", pending.caller, HexStr(pending.key).substr(0, 12));
        return true;
    }

    /* relay-ok / relay-error arriving here (rather than in a raw handshake)
       mean nothing: ignore. */
    return true;
}

void ClientMaintenance()
{
    /* Expire pending requests (helper side). */
    {
        LOCK(cs_relay);
        const int64_t now = GetTime();
        for (auto it = g_pending.begin(); it != g_pending.end();) {
            if (it->second.expires < now) {
                WithNodeById(it->second.caller, [](CNode* caller) {
                    caller->PushMessage("rlyerror", (unsigned char)4);
                    caller->FlagForDisconnection();
                });
                it = g_pending.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (!IsHomeNode()) return;
    std::vector<unsigned char> key = GetNodeKeyBytes();
    if (key.empty()) return;

    LOCK(cs_relay);
    /* Drop helpers we asked that never answered. */
    const int64_t now = GetTime();
    for (auto it = g_helpers.begin(); it != g_helpers.end();) {
        if (!it->second.accepted && now - it->second.askedAt > 60) it = g_helpers.erase(it); else ++it;
    }
    unsigned int have = g_helpers.size();
    if (have < MAX_HELPERS) {
        /* Candidates: outbound peers that offer helping, one per address
           group, not already ours. */
        std::set<std::vector<unsigned char>> groups;
        for (const auto& h : g_helpers) groups.insert(h.second.helperAddr.GetGroup());
        ForEachNode([&](CNode* pnode) {
            if (have >= MAX_HELPERS) return;
            if (pnode->fInbound || pnode->fRelayPipe || pnode->fRelayed || pnode->GetVersion() == 0) return;
            if (!(pnode->GetServices() & NODE_RELAY_HELPER)) return;
            if (g_helpers.count(pnode->GetId())) return;
            const CService addr = pnode->GetCAddress();
            if (addr.IsRelay()) return;
            if (!addr.IsRoutable() && !(RelayAllowLocalHelpers() && addr.IsLocal())) return;
            if (groups.count(addr.GetGroup())) return;
            const int64_t time = GetAdjustedTime();
            std::vector<unsigned char> sig;
            if (!GetNodeKey().Sign(RegisterHash(key, addr.ToString(), time), sig)) return;
            pnode->PushMessage("rlyregister", key, addr.ToString(), time, sig);
            g_helpers[pnode->GetId()] = HelperLink{ pnode->GetId(), addr, false, now };
            groups.insert(addr.GetGroup());
            have++;
            LogPrint("net", "relay: asking %s to help\n", addr.ToString());
        });
    }
    /* Re-announce every six hours (spec B1 step 4). */
    if (now - g_lastAnnounce > 6 * 60 * 60) AnnounceRelayedAddresses();
}

bool CallerHandshake(SOCKET hSocket, const std::vector<unsigned char>& key, std::string& error)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << key;
    if (!SendRaw(hSocket, "rlyconnect", payload)) { error = "could not ask the helper"; return false; }
    std::string reply;
    CDataStream body(SER_NETWORK, PROTOCOL_VERSION);
    if (!ReadRaw(hSocket, reply, body, RAW_TIMEOUT_MS)) { error = "the helper did not answer"; return false; }
    if (reply == "rlyok") return true;
    if (reply == "rlyerror") {
        unsigned char reason = 0;
        try { body >> reason; } catch (...) {}
        error = strprintf("the helper refused (%d)", reason);
        return false;
    }
    error = "unexpected reply " + SanitizeString(reply);
    return false;
}

bool AnswerHandshake(SOCKET hSocket, const std::vector<unsigned char>& token, std::string& error)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << token;
    if (!SendRaw(hSocket, "rlyanswer", payload)) { error = "could not answer the helper"; return false; }
    std::string reply;
    CDataStream body(SER_NETWORK, PROTOCOL_VERSION);
    if (!ReadRaw(hSocket, reply, body, RAW_TIMEOUT_MS)) { error = "the helper did not confirm"; return false; }
    if (reply == "rlyok") return true;
    error = "the helper said " + SanitizeString(reply);
    return false;
}

json_spirit::Value Status()
{
    using namespace json_spirit;
    LOCK(cs_relay);
    Object o;
    o.push_back(Pair("helping", HelpingEnabled()));
    o.push_back(Pair("client", ClientEnabled()));
    o.push_back(Pair("home_node", g_forceHome || (g_startedAt && GetTime() - g_startedAt >= UNREACHABLE_AFTER_SECONDS && GetInboundPeerCount() == 0 && GetOutboundPeerCount() >= 2)));
    Array helpers;
    for (const auto& h : g_helpers) {
        Object e;
        e.push_back(Pair("helper", h.second.helperAddr.ToString()));
        e.push_back(Pair("accepted", h.second.accepted));
        helpers.push_back(e);
    }
    o.push_back(Pair("helpers", helpers));
    Array relayed;
    for (const CAddress& a : LocalRelayedAddresses()) relayed.push_back(a.ToStringIP());
    o.push_back(Pair("relayed_addresses", relayed));
    Array helping;
    for (const auto& r : g_registered) {
        Object e;
        e.push_back(Pair("node", HexStr(r.first)));
        e.push_back(Pair("since", r.second.since));
        e.push_back(Pair("connections", (int)r.second.connections));
        helping.push_back(e);
    }
    o.push_back(Pair("helping_nodes", helping));
    return o;
}
} // namespace PeerRelay
