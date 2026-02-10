#!/usr/bin/env python3
import argparse
import asyncio
import json
import socket
import ssl
import time
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import httpx
from tqdm.asyncio import tqdm

console = Console()

# Aggressive WAF/CDN signatures — expect blocks, challenges and weird behavior
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "server: cloudflare"],
    "Akamai": ["x-akamai", "akamai", "akamai-ghost"],
    "Sucuri": ["x-sucuri", "sucuri", "sucuri/cloudproxy"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-pop", "x-cache"],
    "Fastly": ["x-fastly-request-id", "fastly", "x-iinfo"],
    "Imperva": ["x-cdn", "imperva", "incapsula"],
    "Azure Front Door": ["x-azure-ref"],
    "ModSecurity": ["mod_security", "modsecurity", "blocked by modsecurity"],
    "Barracuda": ["barra", "barracuda"],
    "FortiWeb": ["fortiwaf", "fortinet"],
    "Comodo": ["protected by comodo"],
    "DDoS-GUARD": ["ddos-guard"],
    "PerimeterX": ["x-perimeterx"],
    "Edgecast": ["server: ecd"],
    "StackPath": ["stackpath", "waf"],
}

def detect_waf(headers):
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s in str(headers_lower) for s in sigs):
            return waf
    return "None"

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

async def get_geoip_asn_via_ipinfo(ip, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://ipinfo.io/{ip}/json"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            data = resp.json()
            loc = data.get("loc", "N/A").split(",")
            return {
                "country": data.get("country", "N/A"),
                "region": data.get("region", "N/A"),
                "city": data.get("city", "N/A"),
                "org": data.get("org", "N/A"),
                "asn": data.get("org", "N/A").split(" ")[0] if data.get("org") else "N/A",
            }
    except Exception:
        return {"country": "N/A", "region": "N/A", "city": "N/A", "org": "N/A", "asn": "N/A"}

def get_whois_info(domain):
    try:
        import whois
        w = whois.whois(domain)
        return {
            "registrar": w.registrar or "N/A",
            "creation_date": str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "emails": w.emails or "N/A",
        }
    except:
        return {"registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A", "emails": "N/A"}

def get_tls_cert_info(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                return {
                    "subject": subject.get("commonName", "N/A"),
                    "issuer": issuer.get("commonName", "N/A"),
                    "not_after": cert.get("notAfter", "N/A"),
                }
    except:
        return {"subject": "N/A", "issuer": "N/A", "not_after": "N/A"}

def measure_latency(host, port, timeout=3):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return round((time.time() - start) * 1000, 2)  # ms
    except:
        return "Timeout"

async def scan_port(host, port, timeout=3):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_ports(host, ports, concurrency=100, timeout=3):
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_scan(p):
        async with semaphore:
            return await scan_port(host, p, timeout)

    tasks = [sem_scan(p) for p in ports]
    results = []
    for f in tqdm(asyncio.as_completed(tasks), total=len(ports), desc="Scanning ports", leave=False):
        result = await f
        if result:
            results.append(result)
    return sorted(results)

def parse_port_range(port_range):
    ports = set()
    for part in port_range.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return list(ports)

class ReconSuite:
    def __init__(self, target, ipinfo_token=None, port_range="1-1000", concurrency=100, timeout=10):
        self.target = target
        self.ipinfo_token = ipinfo_token
        self.port_range = port_range
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = {}

    async def run(self):
        # Resolve IP
        ip = socket.gethostbyname(self.target)
        self.results["ip"] = ip

        # Reverse DNS — what name hides behind this IP
        self.results["reverse_dns"] = get_reverse_dns(ip)

        # GeoIP and ASN lookup via ipinfo
        geo = await get_geoip_asn_via_ipinfo(ip, self.ipinfo_token)
        self.results.update(geo)

        # WHOIS
        self.results["whois"] = get_whois_info(self.target)

        # HTTP fingerprint
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"http://{self.target}", follow_redirects=True)
                self.results["http_status"] = resp.status_code
                self.results["http_headers"] = dict(resp.headers)
                self.results["waf"] = detect_waf(resp.headers)
                self.results["server_header"] = resp.headers.get("server", "N/A")
        except:
            self.results["http_status"] = "N/A"
            self.results["http_headers"] = {}
            self.results["waf"] = "N/A"
            self.results["server_header"] = "N/A"

        # TLS fingerprint used for identification
        self.results["tls"] = get_tls_cert_info(self.target)


        #Latency baselines for common ports, defined below for quick checks
        common_ports = [22, 80, 443, 8080]
        latencies = {port: measure_latency(self.target, port) for port in common_ports}
        self.results["latencies"] = latencies

        # Port scanning
        ports_to_scan = parse_port_range(self.port_range)
        open_ports = await scan_ports(self.target, ports_to_scan, concurrency=self.concurrency)
        self.results["open_ports"] = open_ports

    def print_report(self):
        console.print(Panel(f"[bold yellow]Target: {self.target} ({self.results['ip']})[/bold yellow]", expand=False))

        table = Table(title="Reconnaissance Report", show_header=True, header_style="bold magenta")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")

        table.add_row("Reverse DNS", self.results["reverse_dns"])
        table.add_row("Country", self.results["country"])
        table.add_row("Region", self.results["region"])
        table.add_row("City", self.results["city"])
        table.add_row("Organization/ASN", self.results["org"])
        table.add_row("WAF/CDN", self.results["waf"])
        table.add_row("Server Header", self.results["server_header"])
        table.add_row("HTTP Status", str(self.results["http_status"]))
        table.add_row("TLS Subject", self.results["tls"]["subject"])
        table.add_row("TLS Issuer", self.results["tls"]["issuer"])
        table.add_row("Open Ports", ", ".join(map(str, self.results["open_ports"])) or "None")
        table.add_row("Latencies (ms)", str(self.results["latencies"]))

        console.print(table)


        #WHOIS
        whois_data = self.results["whois"]
        wtable = Table(title="WHOIS Information", show_header=True, header_style="bold blue")
        wtable.add_column("Field", style="green", no_wrap=True)
        wtable.add_column("Value", style="yellow")
        wtable.add_row("Registrar", whois_data["registrar"])
        wtable.add_row("Creation Date", whois_data["creation_date"])
        wtable.add_row("Expiration Date", whois_data["expiration_date"])
        wtable.add_row("Emails", str(whois_data["emails"]))
        console.print(wtable)

    def save_report(self):
        with open(f"recon_{self.target.replace('.', '_')}.json", "w") as f:
            json.dump(self.results, f, indent=2)
        console.print(f"Report saved to: recon_{self.target.replace('.', '_')}.json")

async def main():
    parser = argparse.ArgumentParser(description="Advanced reconnaissance suite with GeoIP, ASN, WAF detection, port scanning, and more")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--token", help="ipinfo.io API token for enhanced accuracy (optional)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (e.g., 1-1000, 22,80,443)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Port scanning concurrency level")
    args = parser.parse_args()

    recon = ReconSuite(
        target=args.target,
        ipinfo_token=args.token,
        port_range=args.ports,
        concurrency=args.concurrency
    )
    await recon.run()
    recon.print_report()
    recon.save_report()

if __name__ == "__main__":
    asyncio.run(main())
