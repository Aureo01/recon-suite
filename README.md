# recon-suite

An **all-in-one reconnaissance toolkit** to quickly understand *what you’re dealing with*  
before you even think about exploitation.

IP, ASN, WAF, TLS, ports, latency, WHOIS — all in one clean pass.

Less guessing. More context. 🧠

---

## Why ReconSuite exists

Most recon workflows start like this:
- run 5 tools
- copy/paste results
- forget half of the context
- miss obvious patterns

ReconSuite was built to answer one simple question:

> “What is this target really?”

Before fuzzing.  
Before exploitation.  
Before wasting time.

---

## What it does

Given a domain or IP, ReconSuite collects:

- 🌍 GeoIP & ASN (via ipinfo)
- 🔁 Reverse DNS
- 🧱 WAF / CDN detection (Cloudflare, Akamai, Imperva, etc.)
- 🌐 HTTP fingerprinting
- 🔐 TLS certificate details
- ⏱️ Latency baselines (22 / 80 / 443 / 8080)
- 🔓 Port scanning (async, fast)
- 📄 WHOIS information

All correlated into **one report**.

---

## WAF & CDN detection

ReconSuite actively fingerprints common protections using:
- headers
- server behavior
- known signature patterns

Detects things like:
- Cloudflare
- Akamai
- Fastly
- Imperva / Incapsula
- AWS WAF
- Azure Front Door
- ModSecurity
- FortiWeb
- and more

Because knowing *what’s in front* changes everything.

---

## Port scanning (but sane)

- Async scanning
- Adjustable concurrency
- Custom port ranges

Example:
```bash
-p 1-1000
-p 22,80,443
-p 8000-9000

Fast enough to be useful.
Careful enough to not be stupid.

Usage:

python3 reconsuite.py example.com --token YOUR_IPINFO_TOKEN


