#!/bin/sh
# Three new nodes on a private chain: A helper (reachable), K home (listen=0,
# forced to think it is unreachable), C caller. Proves: K registers with A,
# A gossips K's relayed address, C dials K through A, both see each other.
SP=/private/tmp/claude-501/-Users-geoffreymccabe/ab91087d-6b03-43d5-a4cb-558fa9bd414a/scratchpad
NEW=$HOME/divi-core-nossl/divi/src
CLI="$NEW/divi-cli"
for n in A K C; do $CLI -datadir=$SP/rl$n stop >/dev/null 2>&1; done; sleep 4
for n in A K C; do rm -rf $SP/rl$n; mkdir -p $SP/rl$n; done
printf 'regtest=1\nserver=1\nrpcuser=t\nrpcpassword=t\nrpcport=19001\nport=19000\nlisten=1\ndebug=net\nexternalip=151.101.30.40\n' > $SP/rlA/divi.conf
printf 'regtest=1\nserver=1\nrpcuser=t\nrpcpassword=t\nrpcport=19011\nport=19010\nlisten=0\ndebug=net\naddnode=127.0.0.1:19000\n' > $SP/rlK/divi.conf
printf 'regtest=1\nserver=1\nrpcuser=t\nrpcpassword=t\nrpcport=19021\nport=19020\nlisten=1\ndebug=net\nexternalip=151.101.30.42\naddnode=127.0.0.1:19000\n' > $SP/rlC/divi.conf
$NEW/divid -datadir=$SP/rlA -relaytestlocalhelpers=1 -daemon >/dev/null 2>&1
$NEW/divid -datadir=$SP/rlK -relaytestforcehome=1 -relaytestlocalhelpers=1 -daemon >/dev/null 2>&1
$NEW/divid -datadir=$SP/rlC -relaytestlocalhelpers=1 -daemon >/dev/null 2>&1
up() { for i in $(seq 1 90); do ok=0; for n in A K C; do $CLI -datadir=$SP/rl$n getnetworkinfo >/dev/null 2>&1 && ok=$((ok+1)); done; [ $ok = 3 ] && return 0; sleep 3; done; return 1; }
up || { echo "nodes did not come up"; exit 1; }
echo "all three up; waiting for K to register with A (maintenance runs each minute)"
for i in $(seq 1 30); do
  acc=$($CLI -datadir=$SP/rlK getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['relay']; print(sum(1 for h in r['helpers'] if h['accepted']))")
  [ "$acc" -ge 1 ] && break; sleep 5
done
echo "--- K relay status:"; $CLI -datadir=$SP/rlK getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['relay']; print(json.dumps({k:r[k] for k in ('home_node','helpers','relayed_addresses')}, indent=1))"
echo "--- A relay status:"; $CLI -datadir=$SP/rlA getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['relay']; print(json.dumps(r['helping_nodes'], indent=1))"
REL=$($CLI -datadir=$SP/rlK getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['relay']['relayed_addresses']; print(r[0] if r else '')")
[ -n "$REL" ] || { echo "K has no relayed address; stopping here"; exit 1; }
echo "--- C dials K through A: $REL"
$CLI -datadir=$SP/rlC addnode "$REL" onetry
sleep 8
echo "--- C peers:"; $CLI -datadir=$SP/rlC getpeerinfo | python3 -c "import json,sys; [print('  ', p['addr'][:60], 'relayed' if p.get('relayed') else '', 'in' if p['inbound'] else 'out', p.get('subver','')[-8:]) for p in json.load(sys.stdin)]"
echo "--- K peers:"; $CLI -datadir=$SP/rlK getpeerinfo | python3 -c "import json,sys; [print('  ', p['addr'][:60], 'relayed' if p.get('relayed') else '', 'in' if p['inbound'] else 'out', p.get('subver','')[-8:]) for p in json.load(sys.stdin)]"
echo "--- A peers (pipes):"; $CLI -datadir=$SP/rlA getpeerinfo | python3 -c "import json,sys; [print('  ', p['addr'][:40], 'PIPE' if p.get('relaypipe') else '', 'in' if p['inbound'] else 'out') for p in json.load(sys.stdin)]"
echo "--- relay log lines:"; grep -h "relay:" $SP/rlA/regtest/debug.log $SP/rlK/regtest/debug.log $SP/rlC/regtest/debug.log | cut -c1-120 | head -20
