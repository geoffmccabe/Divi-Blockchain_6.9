// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2024 The Divi Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"

#include "util.h"              // runCommand
#include "utilstrencodings.h" // SanitizeString
#include "Settings.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>

// Local-only: run the operator's -alertnotify command for a fork/safe-mode
// warning. (The signed network-alert system that used to live here was removed.)
void CAlert::Notify(const Settings& settings, const std::string& strMessage, bool fThread)
{
    std::string strCmd = settings.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // The message should be plain ASCII from a trusted local source, but to be
    // safe we strip anything not in safeChars and single-quote it before the shell.
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote + safeStatus + singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    if (fThread)
        boost::thread t(runCommand, strCmd); // thread runs free
    else
        runCommand(strCmd);
}
