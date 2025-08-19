#!/usr/bin/env python3
# discovr.py
import argparse, asyncio, ipaddress, socket, csv, time, sys
from pathlib import Path
from datetime import datetime

DEFAULT_PORTS = [22, 80, 135, 443, 445, 3389]

def guess_os(open_ports):
    p = set(open_ports)
    if 135 in p or 445 in p or 3389 in p: return "Windows (heuristic)"
    if 22 in p: return "Linux/Unix-like (heuristic)"
    if 80 in p or 443 in p: return "Unknown (web)"
    return "Unknown"

async def tcp_probe(host, port, timeout=1.5):
    try:
        await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        return True
    except:
        return False

async def scan_host(host, ports, sem, timeout):
    open_ports = []
    async with sem:
        for port in ports:
            if await tcp_probe(host, port, timeout):
                open_ports.append(port)
    if not open_ports:
        return None
    return {
        "ip": host,
        "hostname": safe_gethost(host),
        "open_ports": ",".join(map(str, open_ports)),
        "os_guess": guess_os(open_ports),
    }

def safe_gethost(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

async def run_scan(cidr, ports, concurrency, timeout, max_hosts=None, deadline=None):
    net = ipaddress.ip_network(cidr, strict=False)
    targets = [str(ip) for ip in net.hosts()]
    if max_hosts: targets = targets[:max_hosts]
    sem = asyncio.Semaphore(concurrency)
    results = []
    start = time.time()
    for ip in targets:
        if deadline and time.time() > deadline:
            break
        res = await scan_host(ip, ports, sem, timeout)
        if res: results.append(res)
    elapsed = time.time() - start
    return results, elapsed, len(targets)

def write_csv(rows, out_csv):
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip","hostname","open_ports","os_guess"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

def write_html(rows, out_html):
    out_html.parent.mkdir(parents=True, exist_ok=True)
    head = """<!doctype html><meta charset="utf-8">
<title>Discovr Report</title>
<style>body{font:14px system-ui, sans-serif;padding:16px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}
th{background:#f5f5f5;cursor:pointer}#q{margin:8px 0;padding:8px;width:100%}</style>
<h2>Discovr Report</h2><input id="q" placeholder="Filter...">
<table id="t"><thead><tr><th>IP</th><th>Hostname</th><th>Open Ports</th><th>OS Guess</th></tr></thead><tbody>"""
    body = "".join(
        f"<tr><td>{r['ip']}</td><td>{r['hostname']}</td><td>{r['open_ports']}</td><td>{r['os_guess']}</td></tr>"
        for r in rows
    )
    foot = """</tbody></table>
<script>
const q=document.getElementById('q');const rows=[...document.querySelectorAll('#t tbody tr')];
q.addEventListener('input',()=>{const s=q.value.toLowerCase();rows.forEach(r=>{r.style.display=
r.textContent.toLowerCase().includes(s)?'':'none';});});
</script>"""
    out_html.write_text(head+body+foot, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Discovr - lightweight asset discovery (CSV only)")
    ap.add_argument("--target", required=True, help="CIDR, e.g. 192.168.1.0/24")
    ap.add_argument("--quick-scan", action="store_true", help="Use quick preset")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    ap.add_argument("--concurrency", type=int, default=256)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--max-hosts", type=int, default=None)
    ap.add_argument("--deadline-sec", type=int, default=150, help="Stop around this many seconds")
    ap.add_argument("--out", default="out/report.csv")
    args = ap.parse_args()

    if args.quick_scan:
        args.concurrency = 256
        args.timeout = 1.5
        if not args.max_hosts: args.max_hosts = None  # allow full /24 by default

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    out_csv = Path(args.out)
    out_html = out_csv.with_suffix(".html")

    print(f"[*] Discovr v0.1 - target={args.target} ports={ports} conc={args.concurrency} timeout={args.timeout}")
    print(f"[*] Starting {datetime.now().isoformat(timespec='seconds')}")

    deadline = time.time() + args.deadline_sec if args.deadline_sec else None
    rows, elapsed, total = asyncio.run(run_scan(args.target, ports, args.concurrency, args.timeout, args.max_hosts, deadline))

    write_csv(rows, out_csv)
    write_html(rows, out_html)

    print(f"[+] Hosts scanned (attempted): {total}")
    print(f"[+] Discovered: {len(rows)}")
    print(f"[*] Exported: {out_csv} and {out_html}")
    print(f"[*] Done in {elapsed:0.2f}s")

if __name__ == "__main__":
    main()
