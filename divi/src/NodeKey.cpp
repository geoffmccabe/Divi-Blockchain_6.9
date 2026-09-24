#include "NodeKey.h"

#include "key.h"
#include "pubkey.h"
#include "util.h"
#include "DataDirectory.h"
#include "utilstrencodings.h"
#include "Logging.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

namespace {
CKey g_nodeKey;
bool g_loaded = false;

boost::filesystem::path KeyPath()
{
    return GetDataDir() / "nodekey.dat";
}
} // namespace

bool LoadOrCreateNodeKey(std::string& error)
{
    const boost::filesystem::path path = KeyPath();
    if (boost::filesystem::exists(path)) {
        boost::filesystem::ifstream in(path);
        std::string hex;
        std::getline(in, hex);
        hex.erase(hex.find_last_not_of(" \r\n\t") + 1);
        if (!IsHex(hex) || hex.size() != 64) {
            error = "nodekey.dat is not a 64-character hex key";
            return false;
        }
        std::vector<unsigned char> raw = ParseHex(hex);
        g_nodeKey.Set(raw.begin(), raw.end(), true);
        if (!g_nodeKey.IsValid()) {
            error = "nodekey.dat does not hold a valid key";
            return false;
        }
        g_loaded = true;
        LogPrintf("nodekey: loaded, public key %s\n", HexStr(GetNodeKeyBytes()));
        return true;
    }
    g_nodeKey.MakeNewKey(true);
    {
        boost::filesystem::ofstream out(path);
        if (!out) {
            error = "cannot write nodekey.dat";
            return false;
        }
        out << HexStr(g_nodeKey.begin(), g_nodeKey.end()) << "\n";
    }
    /* Owner-only, like the wallet file. */
    boost::filesystem::permissions(path, boost::filesystem::owner_read | boost::filesystem::owner_write);
    g_loaded = true;
    LogPrintf("nodekey: created, public key %s\n", HexStr(GetNodeKeyBytes()));
    return true;
}

const CKey& GetNodeKey()
{
    return g_nodeKey;
}

CPubKey GetNodePubKey()
{
    return g_loaded ? g_nodeKey.GetPubKey() : CPubKey();
}

std::vector<unsigned char> GetNodeKeyBytes()
{
    if (!g_loaded) return {};
    CPubKey pub = g_nodeKey.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}
