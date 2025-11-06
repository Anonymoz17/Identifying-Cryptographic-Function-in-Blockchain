#!/usr/bin/env bash
set -euo pipefail

VERSION="10.2.3"
DEST="${HOME}/ghidra-${VERSION}"

USAGE="Usage: install-ghidra.sh [--version x.y.z] [--dest /path/to/install] --accept-license"

ACCEPT=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --accept-license) ACCEPT=1; shift;;
    -h|--help) echo "$USAGE"; exit 0;;
    *) echo "Unknown arg: $1"; echo "$USAGE"; exit 1;;
  esac
done

if [[ "$ACCEPT" -ne 1 ]]; then
  echo "You must accept the Ghidra license to download. Re-run with --accept-license"
  exit 1
fi

# NOTE: Update URL and checksum when bumping versions
URL="https://ghidra-sre.org/ghidra_${VERSION}_PUBLIC.zip"
TMP="/tmp/ghidra_${VERSION}.zip"
EXPECTED_SHA256="<REPLACE_WITH_REAL_SHA256>"  # replace with official checksum

echo "Downloading Ghidra $VERSION to $TMP"
curl -L -o "$TMP" "$URL"

if [[ "$EXPECTED_SHA256" != "<REPLACE_WITH_REAL_SHA256>" ]]; then
  echo "Verifying SHA256 checksum..."
  sha256sum "$TMP" | awk '{print $1}' | grep -i "$EXPECTED_SHA256" || { echo "Checksum mismatch"; exit 2; }
else
  echo "Checksum verification skipped; update script to include the official SHA256 for the selected version"
fi

mkdir -p "$DEST"
unzip -q "$TMP" -d "$DEST"
echo "Ghidra installed to $DEST"
echo "Set GHIDRA_INSTALL_DIR to the directory that contains support/analyzeHeadless"
