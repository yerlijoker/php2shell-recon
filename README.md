# php2shell-recon

A high-performance bulk target scanner for inspecting PHP configuration and version information
as part of authorized security testing.

## Features

- **High Performance:** `uvloop` event-loop support on Linux/macOS, async DNS caching (`aiodns`), and connection pooling with keep-alive optimization.
- **Stealth & Browser Emulation:** Realistic User-Agent pool, dynamic Client Hints (`Sec-Ch-Ua`), and HTTP header emulation.
- **Proxy Rotation:** Single proxy (`--proxy`) or file-based proxy list rotation (`--proxy-file`) supporting HTTP, HTTPS, and SOCKS5.
- **Advanced PHP Fingerprinting:** Passive header inspection, error status code disclosure analysis (404/405/413/500 address banners), PHP error path leak extraction, and SAPI heuristic classification (mod_php, fpm, litespeed, frankenphp).

## Warning

This tool sends active HTTP requests and configuration probes. Use it only on
systems you own or are explicitly authorized to test. The user is responsible
for any consequences of unauthorized scanning or testing.

The tool does not execute an exploit, but some output suggests follow-up
security-testing steps. `green_targets.txt` and scan results are intended for
local use and are excluded from Git by `.gitignore`.

## Installation

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Create a local `domains.txt` file with one domain or URL per line:

```text
https://authorized-example.example
```

Then run:

```bash
python scan.py --input domains.txt --out results.jsonl --summary summary.csv \
  --random-ua --concurrency 30 --probe-post-max --probe-memory
```

### Key Options

- `--random-ua`: Enable randomized browser User-Agent and realistic headers.
- `--proxy <url>`: Route requests through a single HTTP/SOCKS5 proxy.
- `--proxy-file <path>`: Rotate requests across multiple proxies listed in a text file.
- `--probe-error-page`: Actively probe non-existent PHP endpoints to capture error banners disclosing PHP/server details.
- `--concurrency <N>`: Set max concurrent scanning tasks (default: 30).
- `--rate <N>`: Limit requests per second per host (0 = unlimited).
- `--jsonl-append`: Resume and append to an existing JSONL output file.
- `--include-http`: Allow explicit `http://` targets.

