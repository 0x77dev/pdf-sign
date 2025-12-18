#!/usr/bin/env bash
# Preparation + runner for tools/autocast.yaml.
#
# Run this script (e.g. from fish) to generate a recording without
# polluting the demo with setup/teardown “time segments”.

set -Eeuo pipefail

_pdf_sign_demo_mktemp_dir() {
  mktemp -d 2>/dev/null || mktemp -d -t pdf-sign-demo
}

_pdf_sign_demo_cleanup() {
  {
    if [[ -n "${_PDF_SIGN_DEMO_DIR:-}" ]]; then
      rm -rf "${_PDF_SIGN_DEMO_DIR}" 2>/dev/null || true
    fi
  } >/dev/null 2>&1 || true
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

YAML="${ROOT_DIR}/scripts/autocast.yaml"
OUT="${1:-${ROOT_DIR}/demo.rec}"

_PDF_SIGN_DEMO_DIR="$(_pdf_sign_demo_mktemp_dir)"

# Isolated keychain.
export GNUPGHOME="${_PDF_SIGN_DEMO_DIR}/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# Make gpg-agent happy / non-interactive.
export GPG_TTY=/dev/null
export LANG=C
export TERM=xterm-256color

# Start agent (best-effort).
gpgconf --launch gpg-agent >/dev/null 2>&1 || true

# Ephemeral demo key in the isolated keybox.
gpg --batch --pinentry-mode loopback --passphrase "" \
  --quick-generate-key "Demo <demo@example.invalid>" default default never \
  >/dev/null 2>&1

# Sample PDF.
curl -fsSL -o "${_PDF_SIGN_DEMO_DIR}/bitcoin.pdf" https://bitcoin.org/bitcoin.pdf >/dev/null 2>&1

trap _pdf_sign_demo_cleanup EXIT

# Run autocast from inside the demo directory so relative filenames match.
cd "${_PDF_SIGN_DEMO_DIR}"

autocast "${YAML}" "${OUT}" -d 88ms --overwrite

