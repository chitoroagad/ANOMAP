#!/usr/bin/env bash

SUBNET="192.168.1.109/24"
OUTDIR="./home_nmap_logs"
INTERVAL=60 # seconds between scans

mkdir -p "$OUTDIR"

echo "[*] Starting continuous Nmap monitoring of $SUBNET"
echo "[*] Output directory: $OUTDIR"
echo "[*] Scan interval: ${INTERVAL}s"
echo

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
    BASENAME="$OUTDIR/scan_$TIMESTAMP"

    echo "[*] Running scan on at $TIMESTAMP"
    sudo nmap \
        -sS \
        -sV \
        -O \
        --reason \
        --stats-every 10s \
        -T4 \
        $SUBNET \
        -oA "$BASENAME"

        # -sS \                # SYN port scan (fast, stealthy)
        # -sV \                # Probe open ports to determine service/version info
        # -O \                 # OS detection
        # --reason \           # Explain why ports are in a state
        # --stats-every 10s \  # Periodic RTT/progress stats
        # -T4 \                # Aggressive speed (assumes good quality network)

    echo "Scan complete: $BASENAME"
    echo "Sleeping for ${INTERVAL}s"

    sleep "$INTERVAL"
done
