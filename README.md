# php2shell-recon

A bulk target scanner for inspecting PHP configuration and version information
as part of authorized security testing.

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
  --probe-post-max --probe-memory
```

By default, explicit `http://` targets are skipped. Add `--include-http` to
allow them. Use `--jsonl-append` to resume and append to an existing JSONL
file. `--rate` limits requests per second per host, `--retries` retries failed
network requests, and `--proxy` routes regular HTTP requests through a proxy.

