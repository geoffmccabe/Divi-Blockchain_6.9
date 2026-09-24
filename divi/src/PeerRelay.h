// Peer Relay: reaching home nodes through the nodes that can be reached.
// docs/PEER-RELAY-SPEC.md, Part B.
//
// Three roles, all in this one module because a node can be any of them:
//   HOME    cannot be reached; registers with up to three reachable peers
//           (its helpers) and announces "reachable through them".
//   HELPER  a reachable node that accepts registrations and, when a caller
//           asks, joins the caller's connection to a fresh connection from
//           the home node and forwards bytes between them.
//   CALLER  any node that wants to reach a home node: connects to the
//           helper, asks to be put through, then talks Divi as usual.
//
// The whole vocabulary is eight messages (wire names fit the 12-character
// limit): rlyregister, rlyaccept, rlyrefuse, rlyconnect, rlyok, rlyerror,
// rlyincoming, rlyanswer. A registration lives exactly as long as the home node's
// ordinary connection to the helper (the pings on that connection are the
// heartbeat), so there is no separate heartbeat message.
#ifndef DIVI_PEERRELAY_H
#define DIVI_PEERRELAY_H

#include "compat.h"
#include "netbase.h"
#include "protocol.h"

#include <string>
#include <vector>

class CNode;
class CDataStream;
class CAddress;
#include "json/json_spirit_value.h"

namespace PeerRelay
{
/** Helper limits (spec B2). */
static const unsigned int MAX_RELAYED_NODES = 8;
static const unsigned int MAX_CONNECTIONS_PER_NODE = 4;
static const unsigned int MAX_CONNECTIONS_PER_GROUP = 2;
/** Home-node limits (spec B1). */
static const unsigned int MAX_HELPERS = 3;
/** How long a caller's request may wait for the home node to answer. */
static const int64_t PENDING_SECONDS = 15;
/** How long a node waits for a reply in the raw handshakes. */
static const int RAW_TIMEOUT_MS = 15000;
/** A registration is signed over a time this close to now. */
static const int64_t REGISTER_TIME_SLACK = 10 * 60;
/** A node with no inbound peer this long after start is a home node. */
static const int64_t UNREACHABLE_AFTER_SECONDS = 3 * 60;

/** Is this one of ours? */
bool IsRelayCommand(const std::string& command);
/** Allowed before the version handshake: the raw handshakes use them. */
bool IsPreVersionCommand(const std::string& command);
/** Handle one of ours. Returns false if the peer should be dropped. */
bool HandleMessage(CNode* pfrom, const std::string& command, CDataStream& vRecv);

/** A peer went away: forget what it registered and any pending request. */
void OnPeerDisconnected(CNode* pnode);

/** Settings: -relayhelper (offer helping) and -relayclient (use helpers). */
bool HelpingEnabled();
bool ClientEnabled();

/** Periodic (every minute): decide whether we are a home node, keep three
 *  helpers registered, announce our relayed addresses. */
void ClientMaintenance();

/** Our relayed addresses right now (one per helper that accepted). */
std::vector<CAddress> LocalRelayedAddresses();

/** CALLER: on a fresh socket to the helper, ask to be put through to `key`.
 *  Returns once the helper says ok (the socket is then the peer) or fails. */
bool CallerHandshake(SOCKET hSocket, const std::vector<unsigned char>& key, std::string& error);

/** HOME: on a fresh socket to the helper, answer an incoming request. */
bool AnswerHandshake(SOCKET hSocket, const std::vector<unsigned char>& token, std::string& error);

/** For getnetworkinfo. */
json_spirit::Value Status();

/** Test hook: make the node consider itself unreachable at once. */
void ForceHomeNodeForTesting(bool on);
} // namespace PeerRelay

#endif
