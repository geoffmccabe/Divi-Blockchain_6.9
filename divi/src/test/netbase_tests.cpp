// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Dash Core developers
// Copyright (c) 2015-2017 The PIVX Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netbase.h"
#include "protocol.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"

#include <string>

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_AUTO_TEST_SUITE(netbase_tests)

BOOST_AUTO_TEST_CASE(netbase_networks)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetNetwork()                              == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("::1").GetNetwork()                                    == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("8.8.8.8").GetNetwork()                                == NET_IPV4);
    BOOST_CHECK(CNetAddr("2001::8888").GetNetwork()                             == NET_IPV6);
    BOOST_CHECK(CNetAddr("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").GetNetwork() == NET_TOR);
}

BOOST_AUTO_TEST_CASE(netbase_properties)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::FFFF:192.168.1.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::1").IsIPv6());
    BOOST_CHECK(CNetAddr("10.0.0.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("192.168.1.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("172.31.255.255").IsRFC1918());
    BOOST_CHECK(CNetAddr("2001:0DB8::").IsRFC3849());
    BOOST_CHECK(CNetAddr("169.254.1.1").IsRFC3927());
    BOOST_CHECK(CNetAddr("2002::1").IsRFC3964());
    BOOST_CHECK(CNetAddr("FC00::").IsRFC4193());
    BOOST_CHECK(CNetAddr("2001::2").IsRFC4380());
    BOOST_CHECK(CNetAddr("2001:10::").IsRFC4843());
    BOOST_CHECK(CNetAddr("FE80::").IsRFC4862());
    BOOST_CHECK(CNetAddr("64:FF9B::").IsRFC6052());
    BOOST_CHECK(CNetAddr("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").IsTor());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsLocal());
    BOOST_CHECK(CNetAddr("::1").IsLocal());
    BOOST_CHECK(CNetAddr("8.8.8.8").IsRoutable());
    BOOST_CHECK(CNetAddr("2001::1").IsRoutable());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsValid());
}

bool static TestSplitHost(string test, string host, int port)
{
    string hostOut;
    int portOut = -1;
    SplitHostPort(test, portOut, hostOut);
    return hostOut == host && port == portOut;
}

BOOST_AUTO_TEST_CASE(netbase_splithost)
{
    BOOST_CHECK(TestSplitHost("www.bitcoin.org", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("www.bitcoin.org:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("127.0.0.1", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("127.0.0.1:51472", "127.0.0.1", 51472));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]:51472", "127.0.0.1", 51472));
    BOOST_CHECK(TestSplitHost("::ffff:127.0.0.1", "::ffff:127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[::ffff:127.0.0.1]:51472", "::ffff:127.0.0.1", 51472));
    BOOST_CHECK(TestSplitHost("[::]:51472", "::", 51472));
    BOOST_CHECK(TestSplitHost("::51472", "::51472", -1));
    BOOST_CHECK(TestSplitHost(":51472", "", 51472));
    BOOST_CHECK(TestSplitHost("[]:51472", "", 51472));
    BOOST_CHECK(TestSplitHost("", "", -1));
}

bool static TestParse(string src, string canon)
{
    CService addr;
    if (!LookupNumeric(src.c_str(), addr, 65535))
        return canon == "";
    return canon == addr.ToString();
}

BOOST_AUTO_TEST_CASE(netbase_lookupnumeric)
{
    BOOST_CHECK(TestParse("127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("127.0.0.1:51472", "127.0.0.1:51472"));
    BOOST_CHECK(TestParse("::ffff:127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("::", "[::]:65535"));
    BOOST_CHECK(TestParse("[::]:51472", "[::]:51472"));
    BOOST_CHECK(TestParse("[127.0.0.1]", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse(":::", ""));
}

BOOST_AUTO_TEST_CASE(onioncat_test)
{
    // values from https://web.archive.org/web/20121122003543/http://www.cypherpunk.at/onioncat/wiki/OnionCat
    CNetAddr addr1("5wyqrzbvrdsumnok.onion");
    CNetAddr addr2("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca");
    BOOST_CHECK(addr1 == addr2);
    BOOST_CHECK(addr1.IsTor());
    BOOST_CHECK(addr1.ToStringIP() == "5wyqrzbvrdsumnok.onion");
    BOOST_CHECK(addr1.IsRoutable());
}

BOOST_AUTO_TEST_CASE(subnet_test)
{
    BOOST_CHECK(CSubNet("1.2.3.0/24") == CSubNet("1.2.3.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24") != CSubNet("1.2.4.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.2.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4/32").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.3.4").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(!CSubNet("1.2.3.4/32").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(CSubNet("::ffff:127.0.0.1").Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:0/112").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("192.168.0.1/24").Match(CNetAddr("192.168.0.2")));
    BOOST_CHECK(CSubNet("192.168.0.20/29").Match(CNetAddr("192.168.0.18")));
    BOOST_CHECK(CSubNet("1.2.2.1/24").Match(CNetAddr("1.2.2.4")));
    BOOST_CHECK(CSubNet("1.2.2.110/31").Match(CNetAddr("1.2.2.111")));
    BOOST_CHECK(CSubNet("1.2.2.20/26").Match(CNetAddr("1.2.2.63")));
    // All-Matching IPv6 Matches arbitrary IPv4 and IPv6
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1.2.3.4")));
    // All-Matching IPv4 does not Match IPv6
    BOOST_CHECK(!CSubNet("0.0.0.0/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    // Invalid subnets Match nothing (not even invalid addresses)
    BOOST_CHECK(!CSubNet().Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("").Match(CNetAddr("4.5.6.7")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("0.0.0.0")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("hab")));
    // Check valid/invalid
    BOOST_CHECK(CSubNet("1.2.3.0/0").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/-1").IsValid());
    BOOST_CHECK(CSubNet("1.2.3.0/32").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/33").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/0").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/33").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/-1").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/128").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/129").IsValid());
    BOOST_CHECK(!CSubNet("fuzzy").IsValid());
}

/* ---- Relayed addresses (docs/PEER-RELAY-SPEC.md, Part A) ---- */
static std::vector<unsigned char> TestKey(unsigned char fill)
{
    std::vector<unsigned char> k(RELAY_KEY_SIZE, fill);
    k[0] = 0x02; // looks like a compressed public key
    return k;
}

BOOST_AUTO_TEST_CASE(relay_address_forms)
{
    CService helper("93.184.216.34", 51472);
    CNetAddr r;
    BOOST_CHECK(r.SetRelay(TestKey(0x11), helper));
    BOOST_CHECK(r.IsRelay());
    BOOST_CHECK(r.IsValid());
    BOOST_CHECK(r.IsRoutable());
    BOOST_CHECK(!r.IsIPv4() && !r.IsTor());
    BOOST_CHECK_EQUAL(r.GetNetwork(), NET_RELAY);
    BOOST_CHECK(r.RelayKey() == TestKey(0x11));
    BOOST_CHECK(r.RelayHelper() == helper);
    /* Printed and parsed back: the same address. */
    std::string text = r.ToString();
    BOOST_CHECK(text.compare(0, 6, "relay:") == 0);
    BOOST_CHECK(text.find("@93.184.216.34:51472") != std::string::npos);
    CNetAddr back;
    BOOST_CHECK(back.SetSpecial(text));
    BOOST_CHECK(back == r);
    /* Bad inputs are refused. */
    CNetAddr bad;
    BOOST_CHECK(!bad.SetRelay(std::vector<unsigned char>(10, 1), helper));           // key wrong size
    BOOST_CHECK(!bad.SetRelay(TestKey(0x11), CService("93.184.216.34", 0)));          // no port
    BOOST_CHECK(!bad.SetRelay(TestKey(0x11), CService(r, 51472)));                   // helper cannot itself be relayed
    BOOST_CHECK(!bad.SetSpecial("relay:zz@1.2.3.4:1"));
    BOOST_CHECK(!bad.SetSpecial("relay:0202@nohost"));
}

BOOST_AUTO_TEST_CASE(relay_address_grouping)
{
    CService helper("93.184.216.34", 51472);
    CNetAddr a, b, c;
    a.SetRelay(TestKey(0x11), helper);
    b.SetRelay(TestKey(0x22), helper);
    c.SetRelay(TestKey(0x11), CService("151.101.1.69", 51472));
    /* Two nodes behind one helper are different groups (the one-per-group
       rule must not starve them); the same node via two helpers is one. */
    BOOST_CHECK(a.GetGroup() != b.GetGroup());
    BOOST_CHECK(a.GetGroup() == c.GetGroup());
    BOOST_CHECK(a.GetGroup() != helper.GetGroup());
    BOOST_CHECK(a != b);
    BOOST_CHECK(a != c);
    BOOST_CHECK((a < b) != (b < a));
}

BOOST_AUTO_TEST_CASE(relay_address_wire_forms)
{
    CService helper("2606:4700::1111", 51472);
    CAddress relayed(CService(CNetAddr(), 0));
    {
        CNetAddr r;
        BOOST_CHECK(r.SetRelay(TestKey(0x33), helper));
        relayed = CAddress(CService(r, 51472));
    }
    CAddress plain(CService("151.101.1.69", 51472));

    /* Legacy form: the plain address survives byte for byte; the relayed
       one is written as the unspecified address, which is invalid. */
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << plain << relayed;
        CAddress p2, r2;
        ss >> p2 >> r2;
        BOOST_CHECK(p2 == plain);
        BOOST_CHECK(!r2.IsValid());
        BOOST_CHECK(!r2.IsRelay());
    }
    /* addrv2 form: both come back exactly. */
    {
        std::vector<CAddress> v{plain, relayed};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        CAddrV2List out(v);
        ss << out;
        std::vector<CAddress> back;
        CAddrV2List in(back);
        ss >> in;
        BOOST_REQUIRE_EQUAL(back.size(), 2u);
        BOOST_CHECK(back[0] == plain);
        BOOST_CHECK(back[1] == relayed);
        BOOST_CHECK(back[1].IsRelay());
        BOOST_CHECK(back[1].RelayHelper() == helper);
    }
    /* An unknown kind on the wire is skipped, not fatal. */
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
        unsigned char unknown = 0x7f;
        std::vector<unsigned char> junk(9, 0xab);
        ss << unknown << junk;
        unsigned short port = 0;
        ss << port;
        CService got;
        ss >> got;
        BOOST_CHECK(!got.IsValid());
    }
}

BOOST_AUTO_TEST_SUITE_END()
