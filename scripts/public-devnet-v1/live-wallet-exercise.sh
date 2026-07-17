#!/usr/bin/env bash
# Live public-testnet wallet exercise: create, fund, send, receive, privacy checks.
# Intended to run on the mesh host (or any host with mfn-cli + RPC to a funded faucet).
set -euo pipefail

ROOT="${ROOT:-/root/permawrite}"
MFN_CLI="${MFN_CLI:-$ROOT/target/release/mfn-cli}"
RPC="${RPC:-127.0.0.1:18731}"
FAUCET_WALLET="${FAUCET_WALLET:-/root/testnet-wallets/validator0-faucet.json}"
WALLET_DIR="${WALLET_DIR:-/root/testnet-wallets/exercise-$(date -u +%Y%m%dT%H%M%SZ)}"
AMOUNT_FUND="${AMOUNT_FUND:-500000}"
FEE="${FEE:-10000}"
RING="${RING:-16}"
SEND_AMOUNT="${SEND_AMOUNT:-100000}"
WAIT_SLOT_SEC="${WAIT_SLOT_SEC:-35}"

PASS=0
FAIL=0
WARN=0
ERRORS=()

log() { printf '%s\n' "$*"; }
ok() { PASS=$((PASS + 1)); log "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); ERRORS+=("$*"); log "FAIL: $*"; }
warn() { WARN=$((WARN + 1)); log "WARN: $*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || { fail "missing command $1"; exit 2; }
}

json_field() {
  # portable: extract "key": value from pretty or compact JSON (first match)
  local key="$1" text="$2"
  printf '%s' "$text" | tr -d '\r' | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -1
}

json_num() {
  local key="$1" text="$2"
  printf '%s' "$text" | tr -d '\r' | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -1
}

parse_kv() {
  local key="$1" text="$2"
  printf '%s\n' "$text" | tr -d '\r' | sed -n "s/^${key}=//p" | head -1
}

cli() {
  "$MFN_CLI" --rpc "$RPC" "$@"
}

wallet_new() {
  local path="$1"
  "$MFN_CLI" --wallet "$path" wallet new
}

wallet_addr() {
  local path="$1"
  "$MFN_CLI" --wallet "$path" wallet address
}

wallet_scan() {
  local path="$1"
  # Prefer light-scan (headers + get_block_txs) — full get_block scan is too
  # slow once tip is thousands of blocks (see evidence notes).
  cli --wallet "$path" wallet light-scan
}

wallet_balance() {
  local path="$1"
  # Ensure cache is current via light-scan, then print without another full sync
  # by using wallet status cached fields when sync_needed would force get_block.
  cli --wallet "$path" wallet light-scan >/dev/null
  cli --wallet "$path" wallet status
}

wallet_send() {
  local path="$1" to="$2" amount="$3"
  cli --wallet "$path" wallet send "$to" "$amount" --fee "$FEE" --ring-size "$RING" --json
}

mkdir -p "$WALLET_DIR"
REPORT="$WALLET_DIR/report.txt"
exec > >(tee "$REPORT") 2>&1

log "=== live testnet wallet exercise ==="
log "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "rpc=$RPC faucet=$FAUCET_WALLET wallet_dir=$WALLET_DIR"
log "fund_per_send=$AMOUNT_FUND fee=$FEE ring=$RING send=$SEND_AMOUNT"

need "$MFN_CLI"
[[ -f "$FAUCET_WALLET" ]] || { fail "faucet wallet missing"; exit 2; }
[[ -x "$MFN_CLI" ]] || chmod +x "$MFN_CLI" || true

TIP_OUT="$(cli tip 2>&1 || true)"
TIP_H="$(parse_kv tip_height "$TIP_OUT")"
GENESIS="$(parse_kv genesis_id "$TIP_OUT")"
log "tip_height=$TIP_H genesis_id=$GENESIS"
[[ -n "$TIP_H" && "$TIP_H" -gt 0 ]] && ok "mesh tip height=$TIP_H" || fail "could not read tip"

STATUS="$(cli status 2>&1 || true)"
log "status_snippet<<EOF"
printf '%s\n' "$STATUS" | head -60
log "EOF"

# --- create wallets ---
CAROL="$WALLET_DIR/carol.json"
DAVE="$WALLET_DIR/dave.json"
wallet_new "$CAROL" >/dev/null
wallet_new "$DAVE" >/dev/null
[[ -f "$CAROL" && -f "$DAVE" ]] && ok "created carol+dave wallets" || fail "wallet new failed"

CAROL_ADDR_OUT="$(wallet_addr "$CAROL")"
DAVE_ADDR_OUT="$(wallet_addr "$DAVE")"
CAROL_ADDR="$(parse_kv address "$CAROL_ADDR_OUT")"
DAVE_ADDR="$(parse_kv address "$DAVE_ADDR_OUT")"
CAROL_VIEW="$(parse_kv view_pub_hex "$CAROL_ADDR_OUT")"
DAVE_VIEW="$(parse_kv view_pub_hex "$DAVE_ADDR_OUT")"
log "carol_address=$CAROL_ADDR"
log "dave_address=$DAVE_ADDR"

[[ "$CAROL_ADDR" == mf* && ${#CAROL_ADDR} -gt 100 ]] && ok "carol address encodes" || fail "carol address invalid"
[[ "$DAVE_ADDR" == mf* && ${#DAVE_ADDR} -gt 100 ]] && ok "dave address encodes" || fail "dave address invalid"
[[ "$CAROL_ADDR" != "$DAVE_ADDR" ]] && ok "addresses differ" || fail "carol/dave addresses collided"
[[ "$CAROL_VIEW" != "$DAVE_VIEW" ]] && ok "view pubs differ" || fail "view pubs collided"

# Privacy: address is not a transparent account key reuse across wallets
[[ ${#CAROL_VIEW} -eq 64 && ${#DAVE_VIEW} -eq 64 ]] && ok "view pubs are 32-byte hex" || fail "view pub length"

# --- fund carol with 2× (F7 floor) from faucet ---
log "--- funding carol (2 faucet sends) ---"
FAUCET_BAL_OUT="$(cli --wallet "$FAUCET_WALLET" wallet balance 2>&1)"
FAUCET_BAL="$(parse_kv balance "$FAUCET_BAL_OUT")"
log "faucet_balance=$FAUCET_BAL"
[[ -n "$FAUCET_BAL" && "$FAUCET_BAL" -gt $((AMOUNT_FUND * 2 + FEE * 2)) ]] && ok "faucet funded" || fail "faucet balance too low ($FAUCET_BAL)"

FUND_TXS=()
for i in 1 2; do
  SEND_OUT="$(wallet_send "$FAUCET_WALLET" "$CAROL_ADDR" "$AMOUNT_FUND" 2>&1)" || {
    fail "faucet send #$i failed: $SEND_OUT"
    continue
  }
  TX="$(json_field tx_id "$SEND_OUT")"
  OUTCOME="$(json_field outcome "$SEND_OUT")"
  RING_GOT="$(json_num ring_size "$SEND_OUT")"
  log "faucet_send_$i tx_id=$TX outcome=$OUTCOME ring_size=$RING_GOT"
  FUND_TXS+=("$TX")
  [[ "$RING_GOT" == "$RING" ]] && ok "fund send #$i ring_size=$RING" || fail "fund send #$i ring_size=$RING_GOT want $RING"
  [[ -n "$TX" && ${#TX} -eq 64 ]] && ok "fund send #$i has tx_id" || fail "fund send #$i missing tx_id"
  [[ "$OUTCOME" == "Fresh" || "$OUTCOME" == "Duplicate" || "$OUTCOME" == "AlreadyKnown" ]] && ok "fund send #$i admitted ($OUTCOME)" || fail "fund send #$i outcome=$OUTCOME"
  sleep 1
done

log "waiting ${WAIT_SLOT_SEC}s for produce..."
sleep "$WAIT_SLOT_SEC"

wallet_scan "$CAROL" >/dev/null || warn "carol scan returned non-zero"
CAROL_BAL_OUT="$(wallet_balance "$CAROL" 2>&1)"
CAROL_BAL="$(parse_kv balance_cached "$CAROL_BAL_OUT")"
CAROL_OWNED="$(parse_kv owned_count_cached "$CAROL_BAL_OUT")"
if [[ -z "$CAROL_BAL" ]]; then
  CAROL_BAL="$(parse_kv balance "$CAROL_BAL_OUT")"
fi
if [[ -z "$CAROL_OWNED" ]]; then
  CAROL_OWNED="$(parse_kv owned_count "$CAROL_BAL_OUT")"
fi
log "carol_balance=$CAROL_BAL owned_count=$CAROL_OWNED"
EXPECTED=$((AMOUNT_FUND * 2))
if [[ -n "$CAROL_BAL" && "$CAROL_BAL" -ge "$EXPECTED" ]]; then
  ok "carol received >= $EXPECTED (got $CAROL_BAL)"
else
  fail "carol balance $CAROL_BAL < expected $EXPECTED (try longer wait)"
fi
if [[ -n "$CAROL_OWNED" && "$CAROL_OWNED" -ge 2 ]]; then
  ok "carol owned_count>=2 (F7 send floor ready)"
else
  fail "carol owned_count=$CAROL_OWNED need >=2"
fi

# --- carol -> dave transfer ---
log "--- carol -> dave send ---"
SEND_OUT="$(wallet_send "$CAROL" "$DAVE_ADDR" "$SEND_AMOUNT" 2>&1)" || {
  fail "carol->dave send failed: $SEND_OUT"
  SEND_OUT=""
}
TX_SEND="$(json_field tx_id "$SEND_OUT")"
RING_SEND="$(json_num ring_size "$SEND_OUT")"
OUT_SEND="$(json_field outcome "$SEND_OUT")"
log "carol_send tx_id=$TX_SEND ring_size=$RING_SEND outcome=$OUT_SEND"
[[ "$RING_SEND" == "$RING" ]] && ok "transfer ring_size=$RING" || fail "transfer ring_size=$RING_SEND"
[[ -n "$TX_SEND" ]] && ok "transfer submitted tx_id=$TX_SEND" || fail "transfer missing tx_id"
[[ "$OUT_SEND" == "Fresh" || "$OUT_SEND" == "Duplicate" || "$OUT_SEND" == "AlreadyKnown" ]] && ok "transfer admitted ($OUT_SEND)" || fail "transfer outcome=$OUT_SEND"

log "waiting ${WAIT_SLOT_SEC}s for produce..."
sleep "$WAIT_SLOT_SEC"

wallet_scan "$CAROL" >/dev/null || true
wallet_scan "$DAVE" >/dev/null || true
CAROL_AFTER_OUT="$(cli --wallet "$CAROL" wallet status 2>&1)"
DAVE_AFTER_OUT="$(cli --wallet "$DAVE" wallet status 2>&1)"
CAROL_AFTER="$(parse_kv balance_cached "$CAROL_AFTER_OUT")"
DAVE_AFTER="$(parse_kv balance_cached "$DAVE_AFTER_OUT")"
[[ -z "$CAROL_AFTER" ]] && CAROL_AFTER="$(parse_kv balance "$CAROL_AFTER_OUT")"
[[ -z "$DAVE_AFTER" ]] && DAVE_AFTER="$(parse_kv balance "$DAVE_AFTER_OUT")"
log "carol_balance_after=$CAROL_AFTER dave_balance_after=$DAVE_AFTER"

if [[ -n "$DAVE_AFTER" && "$DAVE_AFTER" -ge "$SEND_AMOUNT" ]]; then
  ok "dave received >= $SEND_AMOUNT (got $DAVE_AFTER)"
else
  fail "dave balance $DAVE_AFTER < $SEND_AMOUNT"
fi

# Carol should have spent amount+fee from inputs (change returns) — balance drops by ~fee at minimum if change kept
if [[ -n "$CAROL_BAL" && -n "$CAROL_AFTER" ]]; then
  DROP=$((CAROL_BAL - CAROL_AFTER))
  if [[ "$DROP" -ge "$FEE" ]]; then
    ok "carol balance dropped by >= fee (drop=$DROP)"
  else
    warn "carol balance drop=$DROP (expected at least fee $FEE; may still be pending)"
  fi
fi

# --- privacy checks via get_block_txs / raw inspect ---
log "--- privacy / wire checks ---"
TIP2="$(parse_kv tip_height "$(cli tip 2>&1)")"
# Pull recent headers and look for our tx via get_mempool_tx if still pending, else scan tip for tx_id appearance in get_block_txs
FOUND_HEIGHT=""
for h in $(seq "$TIP2" -1 $((TIP2 > 12 ? TIP2 - 12 : 1))); do
  BLOCK="$(cli rpc get_block_txs "{\"height\":$h}" 2>/dev/null || true)"
  # mfn-cli may not have `rpc` subcommand — try raw TCP via python/node if needed
  if printf '%s' "$BLOCK" | grep -qi "$TX_SEND"; then
    FOUND_HEIGHT=$h
    break
  fi
done

# Use node TCP JSON-RPC for deep checks if available
PRIV_JS="$WALLET_DIR/privacy-check.mjs"
cat >"$PRIV_JS" <<'NODE'
import net from "node:net";
import fs from "node:fs";

const RPC = process.env.RPC || "127.0.0.1:18731";
const [host, portStr] = RPC.split(":");
const port = Number(portStr || 18731);
const tipH = Number(process.env.TIP || "0");
const txId = (process.env.TX_ID || "").toLowerCase();
const fundTxs = (process.env.FUND_TXS || "").split(",").filter(Boolean).map((t) => t.toLowerCase());
const carolView = (process.env.CAROL_VIEW || "").toLowerCase();
const daveView = (process.env.DAVE_VIEW || "").toLowerCase();

function rpc(method, params = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port }, () => {
      socket.write(
        JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) + "\n",
      );
    });
    let buf = "";
    const t = setTimeout(() => {
      socket.destroy();
      reject(new Error("rpc timeout " + method));
    }, 20000);
    socket.setEncoding("utf8");
    socket.on("data", (c) => {
      buf += c;
      if (buf.includes("\n")) {
        clearTimeout(t);
        socket.end();
        try {
          const msg = JSON.parse(buf.trim().split("\n")[0]);
          if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          else resolve(msg.result);
        } catch (e) {
          reject(e);
        }
      }
    });
    socket.on("error", reject);
  });
}

function summarizeTx(tx) {
  const version = tx.version ?? tx.tx_version ?? null;
  const inputs = tx.inputs || tx.tx_inputs || [];
  const outputs = tx.outputs || tx.tx_outputs || [];
  const rings = inputs.map((inp) => {
    const ring = inp.ring || inp.ring_members || inp.members || [];
    return Array.isArray(ring) ? ring.length : inp.ring_size || null;
  });
  const amountsClear = outputs.some(
    (o) => typeof o.amount === "number" || typeof o.value === "number",
  );
  const viewTags = outputs.map((o) => o.view_tag ?? o.viewTag ?? null);
  const otas = outputs.map(
    (o) =>
      (o.one_time_addr_hex || o.one_time_address || o.ota || o.pubkey || "").toLowerCase(),
  );
  return { version, inputCount: inputs.length, outputCount: outputs.length, rings, amountsClear, viewTags, otas, rawKeys: Object.keys(tx) };
}

const out = { checks: [], txs: [] };
function check(ok, msg) {
  out.checks.push({ ok, msg });
  console.log((ok ? "PASS" : "FAIL") + ": " + msg);
}

try {
  const tip = await rpc("get_tip", {});
  const tipHeight = Number(tip.tip_height ?? tipH);
  const want = new Set([txId, ...fundTxs].filter(Boolean));
  const found = [];
  for (let h = tipHeight; h >= Math.max(1, tipHeight - 20); h--) {
    const body = await rpc("get_block_txs", { height: h });
    for (const row of body.txs || []) {
      const id = String(row.tx_id || row.id || "").toLowerCase();
      if (!want.has(id) && !want.has(String(row.txid || "").toLowerCase())) continue;
      found.push({ height: h, id, tx_hex: row.tx_hex, coinbase: row.is_coinbase });
    }
  }
  check(found.length > 0, `located ${found.length} exercise tx(s) in recent blocks`);

  for (const f of found) {
    // Decode is not available over RPC without hex decode; inspect JSON fields on list shape
    const shape = {
      height: f.height,
      id: f.id,
      has_tx_hex: Boolean(f.tx_hex),
      tx_hex_len: f.tx_hex ? f.tx_hex.length : 0,
      coinbase: f.coinbase,
    };
    out.txs.push(shape);
    check(Boolean(f.tx_hex) && f.tx_hex.length > 100, `tx ${f.id.slice(0, 12)}… has wire hex (${shape.tx_hex_len} chars)`);
    // Coinbase should not be our user txs
    check(f.coinbase !== true, `tx ${f.id.slice(0, 12)}… is not marked coinbase`);
  }

  // Cross-wallet privacy: dave cannot be derived from carol view key being on-chain in clear
  const tipBlock = await rpc("get_block_txs", { height: tipHeight });
  const blob = JSON.stringify(tipBlock).toLowerCase();
  check(!carolView || !blob.includes(carolView), "carol view_pub not present in tip block JSON");
  check(!daveView || !blob.includes(daveView), "dave view_pub not present in tip block JSON");

  // Transparent balances API must not exist for stealth wallets
  try {
    await rpc("get_balance", { address: "mf" });
    check(false, "get_balance must not be a public method");
  } catch (e) {
    check(true, `no public get_balance (${String(e.message || e).slice(0, 80)})`);
  }

  fs.writeFileSync(process.env.OUT_JSON || "privacy.json", JSON.stringify(out, null, 2));
  const failed = out.checks.filter((c) => !c.ok).length;
  process.exit(failed ? 1 : 0);
} catch (e) {
  console.error("ERROR: " + (e && e.message ? e.message : e));
  process.exit(2);
}
NODE

export RPC TIP="$TIP2" TX_ID="$TX_SEND" FUND_TXS="$(IFS=,; echo "${FUND_TXS[*]}")" \
  CAROL_VIEW="$CAROL_VIEW" DAVE_VIEW="$DAVE_VIEW" OUT_JSON="$WALLET_DIR/privacy.json"
if command -v node >/dev/null 2>&1; then
  set +e
  node "$PRIV_JS"
  PRIV_RC=$?
  set -e
  if [[ $PRIV_RC -eq 0 ]]; then
    ok "privacy wire checks script exit 0"
  else
    fail "privacy wire checks script exit $PRIV_RC"
  fi
  if [[ -f "$WALLET_DIR/privacy.json" ]]; then
    log "privacy_json<<EOF"
    cat "$WALLET_DIR/privacy.json"
    log "EOF"
  fi
else
  warn "node unavailable — skipped deep privacy RPC checks"
fi

# Cross-scan: dave must NOT see carol remaining outputs (different seeds)
# Already true by construction; assert dave owned after receive and carol view != dave

log "--- summary ---"
log "pass=$PASS fail=$FAIL warn=$WARN"
if (( FAIL > 0 )); then
  log "errors:"
  for e in "${ERRORS[@]}"; do log " - $e"; done
  log "RESULT=FAIL"
  exit 1
fi
log "RESULT=PASS"
exit 0
