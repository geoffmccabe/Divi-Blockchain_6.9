// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2024 The Divi Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ALERT_H
#define BITCOIN_ALERT_H

#include <string>

class Settings;

/**
 * The signed network-alert broadcast system was removed. It let whoever held a
 * single hard-coded key (vAlertPubKey) push a status-bar message to every node
 * on the network -- a trusted-key attack surface that Bitcoin Core removed in
 * 2016. Nodes no longer send, relay, sign, verify, or store network alerts.
 *
 * What survives is only the LOCAL operator hook: CAlert::Notify runs the user's
 * own -alertnotify command for fork / safe-mode warnings. It involves no network
 * messages, no signatures and no keys.
 */
class CAlert
{
public:
    static void Notify(const Settings& settings, const std::string& strMessage, bool fThread);
};

#endif // BITCOIN_ALERT_H
