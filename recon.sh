#!/usr/bin/env bash
#
# recon.sh - Subdomain discovery + live host probing + nuclei scanning wrapper
#
# Usage:
#   ./recon.sh <input_file> [output_file]
#
#   <input_file>   File in the current directory containing one domain
#                   per line (e.g. target.com)
#   [output_file]  Optional. Defaults to <input_file_basename>_live.txt
#
# Pipeline:
#   1. For each domain in <input_file>:
#        subfinder -d <domain> | httpx -sc -title -cl -location -web-server -tech-detect -follow-redirects
#      Results are appended to the output file AND printed live to the terminal.
#   2. Bare hostnames (no scheme, no path, no port) are extracted from the
#      httpx output into a second file.
#   3. That hostname file is fed into nuclei across a set of exposure /
#      token / API-key template groups, each writing its own result file.
set -uo pipefail

# ---- Argument handling -----------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <input_file> [output_file]" >&2
    exit 1
fi

INPUT_FILE="$1"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Error: file '$INPUT_FILE' not found in current directory ($(pwd))." >&2
    exit 1
fi

BASENAME="$(basename "$INPUT_FILE")"
BASENAME_NOEXT="${BASENAME%.*}"
OUTPUT_FILE="${2:-${BASENAME_NOEXT}_live.txt}"
HOSTS_FILE="${BASENAME_NOEXT}_hosts.txt"
NUCLEI_OUT_DIR="${BASENAME_NOEXT}_nuclei_results"

# ---- Dependency checks ------------------------------------------------------
for bin in subfinder httpx nuclei; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[!] Error: required tool '$bin' not found in PATH." >&2
        exit 1
    fi
done

# ---- Prep --------------------------------------------------------------------
mapfile -t DOMAINS < <(tr -d '\r' < "$INPUT_FILE" | sed '/^\s*$/d' | sed '/^\s*#/d')

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    echo "[!] No domains found in '$INPUT_FILE'." >&2
    exit 1
fi

: > "$OUTPUT_FILE"   # truncate/create output file
echo "[*] Loaded ${#DOMAINS[@]} domain(s) from: $INPUT_FILE"
echo "[*] Output will be saved to: $OUTPUT_FILE"
echo "-------------------------------------------------------------------"

# ---- Stage 1: subfinder + httpx ----------------------------------------------
for domain in "${DOMAINS[@]}"; do
    echo "[*] Scanning: $domain"
    subfinder -d "$domain" -silent | \
        httpx -sc -title -cl -location -web-server -tech-detect -follow-redirects | \
        tee -a "$OUTPUT_FILE"
    echo "-------------------------------------------------------------------"
done

echo "[+] Stage 1 done. Results saved to: $OUTPUT_FILE"

# ---- Stage 2: extract bare hostnames -----------------------------------------
echo
echo "[*] Extracting bare hostnames -> $HOSTS_FILE"

grep -oE 'https?://[^][:space:]]+' "$OUTPUT_FILE" \
    | sed -E 's#^https?://##' \
    | sed -E 's#[/:].*$##' \
    | tr 'A-Z' 'a-z' \
    | sort -u > "$HOSTS_FILE"

HOST_COUNT=$(wc -l < "$HOSTS_FILE" | tr -d ' ')

if [[ "$HOST_COUNT" -eq 0 ]]; then
    echo "[!] No live hosts extracted from $OUTPUT_FILE. Skipping nuclei stage." >&2
    echo
    echo "===== FINAL RESULTS (httpx) ====="
    cat "$OUTPUT_FILE"
    exit 0
fi

echo "[+] Extracted $HOST_COUNT unique host(s) -> $HOSTS_FILE"
echo "-------------------------------------------------------------------"

# =====================================================================
# SEVERITY FILTER — optional, applies to ALL nuclei scans below
# =====================================================================
NUCLEI_SEVERITY=""

SEVERITY_FLAG=()
if [[ -n "$NUCLEI_SEVERITY" ]]; then
    SEVERITY_FLAG=(-severity "$NUCLEI_SEVERITY")
fi

# ---- Stage 3: nuclei scanning -------------------------------------------------
mkdir -p "$NUCLEI_OUT_DIR"

echo "[*] Running nuclei template-path scans..."

# =====================================================================
# TEMPLATE PATH LIST — edit this to add/remove nuclei template scans
# =====================================================================
NUCLEI_TEMPLATE_PATHS=(
    "http/exposures/tokens/google/google-api-key.yaml"
    "http/exposures/tokens"
    "http/exposures/apis"
    "http/exposures/configs"
    "http/exposures/backups"
    "http/exposures/files"
    "http/exposures/logs"
    "http/exposures/panels"
    "http/exposed-panels"
    "http/misconfiguration"
    "http/misconfiguration/aws"
    "http/default-logins"
    "http/takeovers"
    "http/vulnerabilities"
    "http/cves/2025"
    "http/cves/2026"
    # "http/miscellaneous"
    # "http/fuzzing"
)

for tmpl in "${NUCLEI_TEMPLATE_PATHS[@]}"; do
    safe_name="$(echo "$tmpl" | tr '/' '_')"
    out_file="${NUCLEI_OUT_DIR}/${safe_name}.txt"
    echo "[*] nuclei -l $HOSTS_FILE -t $tmpl${NUCLEI_SEVERITY:+ -severity $NUCLEI_SEVERITY}"
    nuclei -l "$HOSTS_FILE" -t "$tmpl" "${SEVERITY_FLAG[@]}" -o "$out_file" -silent
    echo "    -> $out_file"
done

echo "-------------------------------------------------------------------"
echo "[*] Running nuclei tag-based scans..."

# =====================================================================
# TAG GROUP LIST — edit this to add/remove nuclei -tags scans
# =====================================================================
NUCLEI_TAG_GROUPS=(
    "google,apikey,exposure"
    "token,exposure,config"
    "aws,exposure"
    "secret,exposure"
    "misconfig,exposure"
    "panel,exposure"
    "takeover"
    "default-login"
    "cve,rce"
    "cve,sqli"
    "cve,ssrf"
    "cve,lfi"
    "wordpress,cve"
    # "xss"
    # "fuzz"
)

for tags in "${NUCLEI_TAG_GROUPS[@]}"; do
    safe_name="$(echo "$tags" | tr ',' '_')"
    out_file="${NUCLEI_OUT_DIR}/tags_${safe_name}.txt"
    echo "[*] nuclei -l $HOSTS_FILE -tags $tags${NUCLEI_SEVERITY:+ -severity $NUCLEI_SEVERITY}"
    nuclei -l "$HOSTS_FILE" -tags "$tags" "${SEVERITY_FLAG[@]}" -o "$out_file" -silent
    echo "    -> $out_file"
done

echo "-------------------------------------------------------------------"

# ---- Combine all nuclei findings into one file --------------------------------
COMBINED_FINDINGS="${BASENAME_NOEXT}_nuclei_all.txt"
find "$NUCLEI_OUT_DIR" -type f -name '*.txt' -exec cat {} + 2>/dev/null | sort -u > "$COMBINED_FINDINGS"

echo "[+] Done."
echo "    httpx live hosts:   $OUTPUT_FILE"
echo "    extracted hosts:    $HOSTS_FILE"
echo "    nuclei per-scan out: $NUCLEI_OUT_DIR/"
echo "    nuclei combined out: $COMBINED_FINDINGS"
echo
echo "===== FINAL NUCLEI FINDINGS ====="
cat "$COMBINED_FINDINGS"
