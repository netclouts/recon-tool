#!/usr/bin/env bash
#
# install.sh - Installs dependencies required by recon.sh
set -uo pipefail

echo "===== recon.sh dependency installer ====="

if ! command -v go >/dev/null 2>&1; then
    cat >&2 <<'EOF'
[!] Go is not installed or not in PATH.

    subfinder, httpx, and nuclei are Go binaries and require Go 1.21+.
    Install it first:

      Debian/Ubuntu:  sudo apt install golang-go
      macOS (brew):   brew install go
      Or download:    https://go.dev/dl/

    Then re-run this script.
EOF
    exit 1
fi

GOBIN="$(go env GOPATH)/bin"
echo "[*] Go found: $(go version)"
echo "[*] Go binaries will install to: $GOBIN"

if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "[!] Warning: $GOBIN is not in your PATH."
    echo "    Add this to your shell profile (~/.bashrc, ~/.zshrc, etc):"
    echo "      export PATH=\"\$PATH:$GOBIN\""
fi

install_go_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" >/dev/null 2>&1; then
        echo "[+] $name already installed: $(command -v "$name")"
        return
    fi

    echo "[*] Installing $name..."
    if go install "$pkg"; then
        echo "[+] $name installed."
    else
        echo "[!] Failed to install $name." >&2
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Syncing nuclei-templates..."
    nuclei -ut
else
    echo "[!] Skipping template sync — nuclei not found in PATH after install." >&2
    echo "    Make sure $GOBIN is in your PATH, then run: nuclei -ut"
fi

echo
echo "===== Done ====="
echo "Verify with:"
echo "  subfinder -version"
echo "  httpx -version"
echo "  nuclei -version"
