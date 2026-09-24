// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#if defined(HAVE_CONFIG_H)
#include "config/divi-config.h"
#endif

#include "compat.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>

int getConnectionTimeoutDuration();
void setConnectionTimeoutDuration(int timeoutDuration);

bool getNameLookupFlag();
void setNameLookupFlag(bool updatedNameLookupFlag);

/** -timeout default */
constexpr int DEFAULT_CONNECT_TIMEOUT = 5000;
//! -dns default
constexpr bool DEFAULT_NAME_LOOKUP = true;

#ifdef WIN32
// In MSVC, this is defined as a macro, undefine it to prevent a compile and link error
#undef SetPort
#endif

enum Network {
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_TOR,
    /** A node reachable only through a helper node (docs/PEER-RELAY-SPEC.md):
     *  identified by its node key, addressed via the helper's IP and port. */
    NET_RELAY,

    NET_MAX,
};

/** Stream version flag: serialize addresses in the "addrv2" form (BIP 155
 *  shape), which can carry every kind of address. Without it the legacy
 *  16-byte form is used and extended kinds are written as all zeros, which
 *  old nodes already ignore. */
static const int ADDRV2_FORMAT = 0x20000000;

/** BIP 155 network ids on the wire, plus ours. */
enum AddrV2NetId : unsigned char {
    ADDRV2_IPV4 = 1,
    ADDRV2_IPV6 = 2,
    ADDRV2_TORV2 = 3,
    ADDRV2_RELAY = 0x80,
};

/** Size of a node key (compressed secp256k1 public key). */
static const size_t RELAY_KEY_SIZE = 33;

/** IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96)) */
class CService;

class CNetAddr
{
protected:
    unsigned char ip[16]; // in network byte order
    /** ---- EXTENDED KINDS ----
     *  The 16-byte slot above is the address for IPv4, IPv6 and legacy Tor,
     *  and every routine below keeps reading it. A relayed node does not
     *  fit: it is a node key plus the helper it is reached through. Those
     *  live here, and `m_ext` says which kind this is (NET_UNROUTABLE for a
     *  plain IP address). For an extended kind `ip` holds a hash of the
     *  extension so the old byte-based comparisons and hashes still work. */
    Network m_ext;
    std::vector<unsigned char> m_extBytes;

public:
    CNetAddr();
    CNetAddr(const struct in_addr& ipv4Addr);
    explicit CNetAddr(const char* pszIp, bool fAllowLookup = false);
    explicit CNetAddr(const std::string& strIp, bool fAllowLookup = false);
    void Init();
    void SetIP(const CNetAddr& ip);

    /**
         * Set raw IPv4 or IPv6 address (in network byte order)
         * @note Only NET_IPV4 and NET_IPV6 are allowed for network.
         */
    void SetRaw(Network network, const uint8_t* data);

    bool SetSpecial(const std::string& strName); // for Tor and relayed addresses
    /** Make this a relayed address: node `key` reachable through `helper`
     *  (which must be a plain IPv4/IPv6 address with a port). */
    bool SetRelay(const std::vector<unsigned char>& key, const CService& helper);
    bool IsRelay() const;
    /** The relayed node's key, empty if this is not a relayed address. */
    std::vector<unsigned char> RelayKey() const;
    /** The helper a relayed node is reached through (invalid if not relayed). */
    CService RelayHelper() const;
    bool IsIPv4() const;                         // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
    bool IsIPv6() const;                         // IPv6 address (not mapped IPv4, not Tor)
    bool IsRFC1918() const;                      // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
    bool IsRFC2544() const;                      // IPv4 inter-network communcations (192.18.0.0/15)
    bool IsRFC6598() const;                      // IPv4 ISP-level NAT (100.64.0.0/10)
    bool IsRFC5737() const;                      // IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    bool IsRFC3849() const;                      // IPv6 documentation address (2001:0DB8::/32)
    bool IsRFC3927() const;                      // IPv4 autoconfig (169.254.0.0/16)
    bool IsRFC3964() const;                      // IPv6 6to4 tunnelling (2002::/16)
    bool IsRFC4193() const;                      // IPv6 unique local (FC00::/7)
    bool IsRFC4380() const;                      // IPv6 Teredo tunnelling (2001::/32)
    bool IsRFC4843() const;                      // IPv6 ORCHID (2001:10::/28)
    bool IsRFC4862() const;                      // IPv6 autoconfig (FE80::/64)
    bool IsRFC6052() const;                      // IPv6 well-known prefix (64:FF9B::/96)
    bool IsRFC6145() const;                      // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
    bool IsTor() const;
    bool IsLocal() const;
    bool IsRoutable() const;
    bool IsValid() const;
    bool IsMulticast() const;
    enum Network GetNetwork() const;
    std::string ToString() const;
    std::string ToStringIP() const;
    unsigned int GetByte(int n) const;
    uint64_t GetHash() const;
    bool GetInAddr(struct in_addr* pipv4Addr) const;
    std::vector<unsigned char> GetGroup() const;
    int GetReachabilityFrom(const CNetAddr* paddrPartner = NULL) const;

    CNetAddr(const struct in6_addr& pipv6Addr);
    bool GetIn6Addr(struct in6_addr* pipv6Addr) const;

    friend bool operator==(const CNetAddr& a, const CNetAddr& b);
    friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
    friend bool operator<(const CNetAddr& a, const CNetAddr& b);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (nVersion & ADDRV2_FORMAT) {
            SerializeV2(s, ser_action, nType, nVersion);
            return;
        }
        /* Legacy form. An extended kind cannot be expressed in it and is
           written as the unspecified address, which every node discards. */
        if (ser_action.ForRead()) {
            m_ext = NET_UNROUTABLE;
            m_extBytes.clear();
            READWRITE(FLATDATA(ip));
        } else if (m_ext != NET_UNROUTABLE) {
            unsigned char zero[16] = {};
            READWRITE(FLATDATA(zero));
        } else {
            READWRITE(FLATDATA(ip));
        }
    }

    template <typename Stream, typename Operation>
    inline void SerializeV2(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        /* BIP 155 shape: one byte of network id, a compact-size length, then
           the bytes. Unknown ids are skipped by length, never fatal. */
        if (ser_action.ForRead()) {
            unsigned char id = 0;
            std::vector<unsigned char> bytes;
            READWRITE(id);
            READWRITE(bytes);
            SetFromV2(id, bytes);
        } else {
            unsigned char id;
            std::vector<unsigned char> bytes;
            ToV2(id, bytes);
            READWRITE(id);
            READWRITE(bytes);
        }
    }

    void ToV2(unsigned char& id, std::vector<unsigned char>& bytes) const;
    void SetFromV2(unsigned char id, const std::vector<unsigned char>& bytes);

    friend class CSubNet;
};



class CSubNet
{
protected:
    /// Network (base) address
    CNetAddr network;
    /// Netmask, in network byte order
    uint8_t netmask[16];
    /// Is this value valid? (only used to signal parse errors)
    bool valid;

public:
    CSubNet();
    explicit CSubNet(const std::string& strSubnet, bool fAllowLookup = false);

    bool Match(const CNetAddr& addr) const;

    std::string ToString() const;
    bool IsValid() const;

    friend bool operator==(const CSubNet& a, const CSubNet& b);
    friend bool operator!=(const CSubNet& a, const CSubNet& b);
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
protected:
    unsigned short port; // host order

public:
    CService();
    CService(const CNetAddr& ip, unsigned short port);
    CService(const struct in_addr& ipv4Addr, unsigned short port);
    CService(const struct sockaddr_in& addr);
    explicit CService(const char* pszIpPort, int portDefault, bool fAllowLookup = false);
    explicit CService(const char* pszIpPort, bool fAllowLookup = false);
    explicit CService(const std::string& strIpPort, int portDefault, bool fAllowLookup = false);
    explicit CService(const std::string& strIpPort, bool fAllowLookup = false);
    void Init();
    void SetPort(unsigned short portIn);
    unsigned short GetPort() const;
    bool GetSockAddr(struct sockaddr* paddr, socklen_t* addrlen) const;
    bool SetSockAddr(const struct sockaddr* paddr);
    friend bool operator==(const CService& a, const CService& b);
    friend bool operator!=(const CService& a, const CService& b);
    friend bool operator<(const CService& a, const CService& b);
    std::vector<unsigned char> GetKey() const;
    std::string ToString() const;
    std::string ToStringPort() const;
    std::string ToStringIPPort() const;

    CService(const struct in6_addr& ipv6Addr, unsigned short port);
    CService(const struct sockaddr_in6& addr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        /* Through the address's own serializer, so the addrv2 form and the
           extended kinds work here too (it used to write the 16 bytes raw). */
        READWRITE(*(CNetAddr*)this);
        unsigned short portN = htons(port);
        READWRITE(portN);
        if (ser_action.ForRead())
            port = ntohs(portN);
    }
};

class proxyType
{
public:
    proxyType(): randomize_credentials(false) {}
    proxyType(const CService &proxy, bool randomize_credentials=false): proxy(proxy), randomize_credentials(randomize_credentials) {}

    bool IsValid() const { return proxy.IsValid(); }

    CService proxy;
    bool randomize_credentials;
};

enum Network ParseNetwork(std::string net);
std::string GetNetworkName(enum Network net);
void SplitHostPort(std::string in, int& portOut, std::string& hostOut);
bool SetProxy(enum Network net, const proxyType &addrProxy);
bool GetProxy(enum Network net, proxyType& proxyInfoOut);
bool IsProxy(const CNetAddr& addr);
bool SetNameProxy(const proxyType &addrProxy);
bool HaveNameProxy();
bool LookupHost(const char* pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool Lookup(const char* pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char* pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char* pszName, CService& addr, int portDefault = 0);
bool ConnectSocket(const CService& addr, SOCKET& hSocketRet, int nTimeout, bool* outProxyConnectionFailed = 0);
bool ConnectSocketByName(CService& addr, SOCKET& hSocketRet, const char* pszDest, int portDefault, int nTimeout, bool* outProxyConnectionFailed = 0);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking);
/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);

#endif // BITCOIN_NETBASE_H
