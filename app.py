from flask import Flask, render_template, request, jsonify
import ipaddress
import socket
import subprocess
import concurrent.futures
import re

app = Flask(__name__)

EXCLUDE_IFACE_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "kube", "tailscale", "zt", "wg"
)

PING_CMD = ["ping", "-c", "1", "-W", "1"]  

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def list_local_ipv4s():

    out = run(["ip", "-o", "-4", "addr", "show"]).stdout.strip().splitlines()
    rows = []
    for line in out:
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        if any(iface.startswith(p) for p in EXCLUDE_IFACE_PREFIXES):
            continue
        if parts[2] != "inet":
            continue
        ip_cidr = parts[3]
        try:
            ip_str, cidrlen = ip_cidr.split("/")
            cidrlen = int(cidrlen)
            rows.append((iface, ip_str, cidrlen))
        except Exception:
            continue
    return rows

def candidate_subnets():
    subs = []
    seen = set()
    for iface, ip_str, _cidr in list_local_ipv4s():
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        key = (str(net.network_address), net.prefixlen)
        if key not in seen:
            seen.add(key)
            subs.append({
                "iface": iface,
                "cidr": str(net),
                "gateway_hint": str(net.network_address + 1)
            })
    return subs

LATENCY_RE = re.compile(r"time[=<]([0-9.]+)\s*ms", re.I)

def ping_once(ip):

    try:
        proc = run(PING_CMD + [ip])
        if proc.returncode == 0:
            m = LATENCY_RE.search(proc.stdout)
            if not m:
                m = LATENCY_RE.search(proc.stderr)
            latency = float(m.group(1)) if m else None
            return "up", latency
        else:
            return "down", None
    except Exception:
        return "down", None

def reverse_dns(ip, timeout=0.3):
    sock_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(sock_to)

def classify_status(lat_ms):
    if lat_ms is None:
        return {"label": "Unreachable", "color": "red"}
    if lat_ms < 50:
        return {"label": "Online", "color": "green"}
    if lat_ms <= 150:
        return {"label": "Warning", "color": "yellow"}
    return {"label": "Unreachable", "color": "red"}

def scan_cidr(cidr, limit_hosts=254, max_workers=64):
   
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []

   
    targets = []
    for i, ip in enumerate(net.hosts()):
        if i >= limit_hosts:
            break
        targets.append(str(ip))

    rows = []

    def work(ip):
        st, lat = ping_once(ip)
        host = reverse_dns(ip)
        status_meta = classify_status(lat)
        return {
            "ip": ip,
            "hostname": host,
            "latency": None if lat is None else round(lat, 1),
            "hops": None,   
            "status": status_meta["label"],
            "statusColor": status_meta["color"]
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for item in ex.map(work, targets):
            rows.append(item)
    return rows

@app.route("/")
def index():
   
    return render_template("index.html")

@app.get("/api/subnets")
def api_subnets():
    subs = candidate_subnets()
    print("DEBUG /api/subnets ->", subs, flush=True)
    return jsonify({"subnets": candidate_subnets()})

@app.get("/api/scan")
def api_scan():

    cidr = request.args.get("cidr")
    if not cidr:
        subs = candidate_subnets()
        cidr = subs[0]["cidr"] if subs else "192.168.1.0/24"
        print("DEBUG /api/scan cidr =", cidr, flush=True)
    data = scan_cidr(cidr)
    print("DEBUG /api/scan count =", len(data), flush=True)
    return jsonify({"cidr": cidr, "count": len(data), "devices": data})

if __name__ == "__main__":
    subs = candidate_subnets()
    if not subs:
        print("No subnets found.")
    else:
        cidr = subs[0]["cidr"]
        print(f"Scanning {cidr}...\n")
        results = scan_cidr(cidr)
        print(f"{'IP':<15} {'Hostname':<30} {'Latency(ms)':<12} {'Hops':<5} {'Status':<10}")
        print("-"*80)
        for r in results:
            ip = r["ip"]
            host = r["hostname"] or "-"
            lat = r["latency"] if r["latency"] is not None else "-"
            hops = r["hops"] if r["hops"] is not None else "-"
            status = r["status"]
            print(f"{ip:<15} {host:<30} {lat:<12} {hops:<5} {status:<10}")

'''if __name__ == "__main__":
    subs = candidate_subnets()
    print("Subnets found:", subs)

    if subs:
        cidr = subs[0]["cidr"]
        print(f"Scanning {cidr}...")
        results = scan_cidr(cidr)
        for r in results:
            print(r)
    else:
        print("No subnets found.")
''' '''
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)'''
