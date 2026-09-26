> **⚠️ Deprecated.** This project has been superseded by [recon-wolf](https://github.com/netclouts/recon-wolf), which adds DNS bruteforce/permutations, port scanning, JS secret/sourcemap mining, LFI and SQLi candidate scanning, GitHub secret scanning, vhost fuzzing, WAF fingerprinting, and per-target dual-template-root nuclei scanning. Use recon-wolf going forward.

# recon.sh

Subdomain discovery → live host probing → nuclei vulnerability scanning, in one pipeline.

```
subfinder -d <domain> | httpx -sc -title -cl -location -web-server -tech-detect -follow-redirects
    -> extract bare hostnames
    -> nuclei (template-path scans + tag-based scans)
```

## Requirements

- [Go](https://go.dev/dl/) 1.21+
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [nuclei](https://github.com/projectdiscovery/nuclei) (+ nuclei-templates)

## Install

```bash
git clone https://github.com/netclouts/recon-tool.git
cd recon-tool
chmod +x install.sh recon.sh
./install.sh
```

`install.sh` installs subfinder, httpx, and nuclei via `go install`, then syncs
the official nuclei-templates repo (`nuclei -ut`). It checks for Go first and
tells you how to install it if missing — it won't silently install Go itself.

Make sure your Go bin path is on `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

```bash
./recon.sh <input_file> [output_file]
```

- `input_file` — one domain per line (e.g. `target.com`), in the current directory
- `output_file` — optional, defaults to `<input_file_basename>_live.txt`

### Example

```bash
echo "example.com" > targets.txt
./recon.sh targets.txt
```

### Output files

| File | Contents |
|---|---|
| `<input>_live.txt` | Raw subfinder + httpx results |
| `<input>_hosts.txt` | Deduplicated bare hostnames extracted from the above |
| `<input>_nuclei_results/` | One result file per nuclei scan (per template path / tag group) |
| `<input>_nuclei_all.txt` | All nuclei findings combined and deduplicated |

## Customizing nuclei scans

Open `recon.sh` and edit the two arrays directly — each entry is one commented
line, so adding or removing a scan is a one-line change:

- `NUCLEI_TEMPLATE_PATHS` — scans run as `nuclei -t <path>` (exposures, panels,
  misconfig, takeovers, recent CVEs, etc.)
- `NUCLEI_TAG_GROUPS` — scans run as `nuclei -tags <a,b,c>` (apikey/exposure,
  RCE/SQLi/SSRF/LFI CVEs, takeover, default-login, etc.)

To disable an entry without deleting it, comment it out with a leading `#`.

There's also a global severity filter near the top of the nuclei stage:

```bash
NUCLEI_SEVERITY=""   # e.g. "critical,high" to cut noise across all scans
```

## Notes

- Uses `set -uo pipefail` (not `-e`) so one failed scan doesn't kill the whole run.
- If httpx returns zero live hosts, the nuclei stage is skipped automatically.
- Intended for authorized security testing (bug bounty programs, pentests with
  written scope) only. Don't scan targets you don't have permission to test.

## License

@netclouts
