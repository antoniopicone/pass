#!/usr/bin/env bash
#
# Due nodi di sync sulla stessa macchina, per provare `pass sync` senza
# avere due computer.
#
#   ./sync-two-nodes.sh          prepara, accoppia, verifica, lascia i due
#                                agent accesi da usare a mano
#   ./sync-two-nodes.sh stop     ferma gli agent e cancella tutto
#
# Tre cose che sembrano dettagli e non lo sono:
#
#  1. PASS_STATE_DIR va separato per nodo. È dove vive l'op-log: due nodi
#     che se lo dividono si scambiano il contatore di sequenza e smettono
#     di convergere.
#  2. Il vault del secondo nodo è una COPIA di quello del primo, presa
#     DOPO il primo `pass unlock`. È quel primo unlock a creare la chiave
#     di sync; copiare prima dà due vault con chiavi diverse, che si
#     parlano ma non riescono ad aprire niente di ciò che si mandano.
#  3. I socket stanno sotto /tmp perché un socket Unix ha un limite duro
#     di ~108 caratteri sul path, e una home un po' profonda lo supera.
#
set -euo pipefail

ROOT=${ROOT:-/tmp/pass-sync-test}
PW=${PW:-test-password}
PORT_A=${PORT_A:-47101}
PORT_B=${PORT_B:-47102}

# Il binario di release è molto più rapido: ogni unlock è un Argon2id da
# 64 MiB, e in debug sono quasi due secondi a colpo.
PASS=${PASS:-}
if [ -z "$PASS" ]; then
    for candidate in ./target/release/pass ./target/debug/pass; do
        [ -x "$candidate" ] && PASS="$candidate" && break
    done
fi
if [ -z "$PASS" ] || [ ! -x "$PASS" ]; then
    echo "Nessun binario: esegui prima 'cargo build --release'." >&2
    exit 1
fi

# Un binario vecchio è la cosa più facile da non notare: fallisce dentro un
# agent che gira in background, e in primo piano si vede solo un unlock che
# dice che non c'è nessun agent.
if ! "$PASS" agent run --help 2>/dev/null | grep -q -- --sync; then
    echo "$PASS non conosce --sync: è di prima di questa feature." >&2
    echo "Ricompila con 'cargo build --release' (o passa PASS=./target/debug/pass)." >&2
    exit 1
fi

node() { # node <a|b> <args...>
    local n=$1; shift
    env PASS_AGENT_SOCK="$ROOT/$n/agent.sock" \
        PASS_SSH_AUTH_SOCK="$ROOT/$n/ssh.sock" \
        PASS_STATE_DIR="$ROOT/$n/state" \
        "$PASS" --vault "$ROOT/$n/vault.kdbx" "$@"
}

unlocked() { printf '%s\n' "$PW" | node "$@"; }

start_agent() { # start_agent <a|b> <porta> [peer]
    local n=$1 port=$2 peer=${3:-}
    local extra=()
    [ -n "$peer" ] && extra=(--sync-peer "$peer")
    node "$n" agent run --sync \
        --sync-port "$port" \
        --sync-bind 127.0.0.1 \
        --sync-advertise "127.0.0.1:$port" \
        --sync-interval 3 \
        "${extra[@]}" >"$ROOT/$n/agent.log" 2>&1 &
}

stop() {
    for n in a b; do
        [ -S "$ROOT/$n/agent.sock" ] && node "$n" agent stop >/dev/null 2>&1 || true
    done
    sleep 1
    rm -rf "$ROOT"
    echo "Fermati, e $ROOT rimosso."
}

if [ "${1:-}" = "stop" ]; then stop; exit 0; fi

trap 'echo; echo "Interrotto. Ferma tutto con: $0 stop"' INT

rm -rf "$ROOT"; mkdir -p "$ROOT/a" "$ROOT/b"

echo "== A: vault, una entry, agent, unlock =="
unlocked a init >/dev/null
unlocked a add --website github.com --url https://github.com --username me --generate >/dev/null
start_agent a "$PORT_A"
sleep 2
unlocked a unlock >/dev/null

echo "== B: parte da una copia del vault di A, poi agent e unlock =="
cp "$ROOT/a/vault.kdbx" "$ROOT/b/vault.kdbx"
start_agent b "$PORT_B" "127.0.0.1:$PORT_A"
sleep 2
unlocked b unlock >/dev/null

echo "== accoppiamento nei due sensi =="
KEY_A=$(unlocked a sync id | head -1)
KEY_B=$(unlocked b sync id | head -1)
unlocked a sync trust nodo-b "$KEY_B" >/dev/null
unlocked b sync trust nodo-a "$KEY_A" >/dev/null
echo "   A: $KEY_A"
echo "   B: $KEY_B"

echo "== una entry su B, e si aspetta che arrivi ad A =="
unlocked b add --website gitlab.com --url https://gitlab.com --username me --generate >/dev/null

# Si aspetta il VAULT, non il fingerprint. Sono due cose diverse e la
# differenza è utile: il fingerprint uguale dice che i due op-log hanno
# fuso allo stesso modo, non che la entry è già stata scritta nel file —
# quella arriva al passaggio successivo sul vault.
for _ in $(seq 20); do
    N_A=$(unlocked a list | grep -c "^Website" || true)
    N_B=$(unlocked b list | grep -c "^Website" || true)
    [ "$N_A" = "2" ] && [ "$N_B" = "2" ] && break
    sleep 2
done
FP_A=$(node a sync status | awk '/Fingerprint/ {print $2}')
FP_B=$(node b sync status | awk '/Fingerprint/ {print $2}')

echo
echo "== entry viste da A =="; unlocked a list | grep -E "^Website" || true
echo "== entry viste da B =="; unlocked b list | grep -E "^Website" || true
echo
if [ "${N_A:-0}" = "2" ] && [ "${N_B:-0}" = "2" ] && [ "$FP_A" = "$FP_B" ]; then
    echo "✅ Convergono: due entry su entrambi, fingerprint identico ($FP_A)"
else
    echo "❌ Non convergono: A ha ${N_A:-0} entry, B ne ha ${N_B:-0}; fingerprint A=$FP_A B=$FP_B"
    echo "   Guarda 'pass sync status' sui due nodi, e $ROOT/{a,b}/agent.log"
fi

cat <<EOF

I due agent restano accesi. Per parlarci:

  alias pa='env PASS_AGENT_SOCK=$ROOT/a/agent.sock PASS_SSH_AUTH_SOCK=$ROOT/a/ssh.sock PASS_STATE_DIR=$ROOT/a/state $PASS --vault $ROOT/a/vault.kdbx'
  alias pb='env PASS_AGENT_SOCK=$ROOT/b/agent.sock PASS_SSH_AUTH_SOCK=$ROOT/b/ssh.sock PASS_STATE_DIR=$ROOT/b/state $PASS --vault $ROOT/b/vault.kdbx'

  pa sync status        # chi conosce, quanti op, il fingerprint
  pb add --website x.com --url https://x.com --username me --generate
  pa sync now           # riconcilia subito invece di aspettare il giro

La password dei due vault è: $PW
Per fermare tutto:  $0 stop
EOF
