// Double-spend conflict log: when the mempool rejects a transaction because it
// spends a coin already spent by a transaction we hold (first-seen-wins), we
// remember that a conflict was seen. A well-connected node that hears both
// sides of a double-spend can then WARN about it (via the getmempoolconflicts
// RPC), instead of silently discarding the loser. This is the first step of the
// DiviGossip fraud-detection work; the full network-wide double-spend proof
// relay builds on top of it.
#ifndef DIVI_DSCONFLICTS_H
#define DIVI_DSCONFLICTS_H

#include <cstdint>
#include <string>
#include <vector>

struct DsConflict {
    std::string outpoint;      // the contested coin ("<txid>-<n>")
    std::string keptTxid;      // the transaction we accepted first (the "winner")
    std::string rejectedTxid;  // the conflicting transaction we refused (the "loser")
    int64_t time;              // unix seconds when the conflict was seen
};

// Record a seen conflict. Keeps only the most recent handful (bounded ring).
void RecordMempoolConflict(const std::string& outpoint, const std::string& keptTxid, const std::string& rejectedTxid);

// Recent conflicts, oldest first.
std::vector<DsConflict> GetRecentMempoolConflicts();

#endif // DIVI_DSCONFLICTS_H
