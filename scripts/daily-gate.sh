#!/bin/zsh
# Zeke daily gate — run by launchd (<prefix>.daily) hourly and on every network change. See docs/SPEC.md §5.
# Once a day, on Wi-Fi/Ethernet >= ZEKE_MIN_MBPS (default 50): `engine.py daily` refreshes security data,
# then runs update-all if daily auto-update is on (the engine decides that from data/settings.json).
ZEKE_HOME="${ZEKE_HOME:-$HOME/.zeke}"
DATA="$ZEKE_HOME/data"
MIN_MBPS="${ZEKE_MIN_MBPS:-50}"
LOG="$ZEKE_HOME/logs/daily-gate.log"
SLOW="$DATA/slow-today"   # "<date> <count>" — speed tests that came back slow today
mkdir -p "$ZEKE_HOME/logs"
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }
today=$(date +%F)

[[ "$(cat "$DATA/last-run" 2>/dev/null)" == "$today" ]] && exit 0

# Back off after slow results: wait 1 h, then 3 h, then give up for the day (each test uses real data).
read sday scount < "$SLOW" 2>/dev/null
[[ "$sday" != "$today" ]] && scount=0
(( scount >= 3 )) && exit 0
wait_min=$(( scount == 0 ? 0 : (scount == 1 ? 60 : 180) ))
(( wait_min > 0 )) && [[ -n $(find "$DATA/last-test" -mmin -$wait_min 2>/dev/null) ]] && exit 0

sleep 20  # let a new connection settle
iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
port=$(networksetup -listallhardwareports | awk -v d="$iface" '/Hardware Port/{p=$0} $2==d{print p}')
[[ -z "$iface" || "$port" == *iPhone* || "$port" == *Bluetooth* ]] && exit 0  # offline or phone hotspot

touch "$DATA/last-test"
bps=$(networkQuality -u -c -M 15 2>/dev/null | plutil -extract dl_throughput raw - 2>/dev/null)
mbps=$(( ${bps%.*:-0} / 1000000 ))
if (( mbps < MIN_MBPS )); then
  echo "$today $(( scount + 1 ))" > "$SLOW"
  log "skip: $iface at ${mbps} Mbps (< $MIN_MBPS), slow result $(( scount + 1 ))/3 today"
  exit 0
fi

log "fast connection: $iface at ${mbps} Mbps, running daily (details in Zeke → Activity)"
/usr/bin/python3 "$ZEKE_HOME/engine.py" daily >> "$LOG" 2>&1
rc=$?
case $rc in
  0)  echo "$today" > "$DATA/last-run"; log "daily finished OK" ;;
  75) log "busy: another scan/update was running; will retry on next check" ;;
  *)  # retry once later today, then give up until tomorrow
      if [[ "$(cat "$DATA/daily-failed" 2>/dev/null)" == "$today" ]]; then
        echo "$today" > "$DATA/last-run"; log "daily failed again (exit $rc); trying again tomorrow"
      else
        echo "$today" > "$DATA/daily-failed"; log "daily failed (exit $rc); will retry once later today"
      fi ;;
esac
exit 0
