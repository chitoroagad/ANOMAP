import nmap
import json
import time
import datetime

SUBNET = "172.20.10.11/28"
SCAN_INTERVAL = 25
OUTPUT_JSON = "detailed_scan_history.jsonl"


def append_json_line(data):
    """Append one JSON record per scan to a .jsonl file."""
    with open(OUTPUT_JSON, "a") as f:
        f.write(json.dumps(data) + "\n")


def perform_scan():
    nm = nmap.PortScanner()

    # -Pn: do not assume host discovery, but still get RTT info
    # --stats-every: disabled in python-nmap (CLI only)
    nm.scan(hosts=SUBNET, arguments="-sS")

    timestamp = datetime.datetime.now(datetime.UTC).isoformat()
    scan_result = {"timestamp": timestamp, "hosts": []}

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "state": nm[host].state(),
            "rtt": None,
            "mac": None,
            "vendor": None,
            "ports": [],
        }
        # print("thishost:::::     ", nm[host]['rtt'], "\n\n")
        print("thishost:::::     ", nm[host], "\n\n")

        # RTT (round-trip time)
        try:
            host_data["rtt"] = nm[host]["status"].get("reason_ttl", None)
        except:
            pass

        # MAC + Vendor
        try:
            host_data["mac"] = nm[host]["addresses"].get("mac", None)
            vendor = nm[host].get("vendor", {})
            if vendor:
                host_data["vendor"] = list(vendor.values())[0]
        except:
            pass

        # Port information
        if "tcp" in nm[host]:
            for port in nm[host]["tcp"]:
                p = nm[host]["tcp"][port]

                host_data["ports"].append(
                    {
                        "port": port,
                        "state": p.get("state", None),
                        "name": p.get("name", None),
                        "product": p.get("product", None),
                        "version": p.get("version", None),
                        "extrainfo": p.get("extrainfo", None),
                    }
                )

        scan_result["hosts"].append(host_data)

    return scan_result


def main():
    print(f"Starting detailed monitoring on {SUBNET}")
    print(f"Saving JSON logs to {OUTPUT_JSON}\n")

    while True:
        print(f"Scanning at {datetime.datetime.now(datetime.UTC).isoformat()} ...")
        result = perform_scan()
        append_json_line(result)
        print(f" → Scan complete. Logged {len(result['hosts'])} hosts.\n")

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
