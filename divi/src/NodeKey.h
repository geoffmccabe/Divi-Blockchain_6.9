// The node's own identity key (docs/PEER-RELAY-SPEC.md, Part A3).
//
// A secp256k1 key made once on first start and kept in the data folder. Its
// public key is how a node is named in a relayed address and what signs the
// relay registrations. It is the same kind of key the wallet uses for coins
// and is deliberately a different key: it never holds or spends anything,
// and it is never derived from the wallet's seed.
#ifndef DIVI_NODEKEY_H
#define DIVI_NODEKEY_H

#include <string>
#include <vector>

class CKey;
class CPubKey;

/** Load the key from <datadir>/nodekey.dat, making one if there is none.
 *  Returns false only if the file cannot be read or written. */
bool LoadOrCreateNodeKey(std::string& error);

/** The key, valid once LoadOrCreateNodeKey succeeded. */
const CKey& GetNodeKey();
CPubKey GetNodePubKey();

/** The public key as raw bytes (33), empty if not loaded. */
std::vector<unsigned char> GetNodeKeyBytes();

#endif
