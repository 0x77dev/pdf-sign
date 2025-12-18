#!/usr/bin/env bash
# End-to-end tests for pdf-sign.
# Runs in Nix sandbox (offline) for GPG tests, and optionally with network for Sigstore.
set -euo pipefail

# Verify pdf-sign binary is available
if [[ -z "${PDF_SIGN:-}" ]] || ! command -v "$PDF_SIGN" &>/dev/null; then
  echo "ERROR: PDF_SIGN binary not found or not in PATH" >&2
  exit 1
fi

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"

# Non-interactive agent defaults
export GPG_TTY=/dev/null
export LANG=C

gpgconf --launch gpg-agent

# Generate two test keys for multi-party signing
gpg --batch --pinentry-mode loopback --passphrase "" \
  --quick-generate-key "CI Test <ci@example.invalid>" default default never

gpg --batch --pinentry-mode loopback --passphrase "" \
  --quick-generate-key "CI Test 2 <ci2@example.invalid>" default default never

gpg --batch --armor --export "ci@example.invalid" >cert1.asc
gpg --batch --armor --export "ci2@example.invalid" >cert2.asc

cat >input.pdf <<'EOF'
%PDF-1.1
1 0 obj
<<>>
endobj
trailer
<<>>
%%EOF
EOF

echo "==> Test 1: GPG sign + verify"
signed="$("$PDF_SIGN" sign input.pdf --key cert1.asc)"
"$PDF_SIGN" verify "$signed" --cert cert1.asc | grep -x OK >/dev/null
echo "    [OK] GPG sign + verify passed"

echo "==> Test 2: Multi-party GPG signing (two signers)"
# Sign with second key on top of first signature
multi_signed="$("$PDF_SIGN" sign "$signed" --key cert2.asc)"
# Verify with both certs - should find both signatures
"$PDF_SIGN" verify "$multi_signed" --cert cert1.asc --cert cert2.asc | grep -x OK >/dev/null
echo "    [OK] Multi-party GPG signing passed"

# Sigstore tests require network and OIDC token
if [[ -n "${SIGSTORE_IDENTITY_TOKEN:-}" ]]; then
  if [[ -z "$SIGSTORE_IDENTITY_TOKEN" ]]; then
    echo "ERROR: SIGSTORE_IDENTITY_TOKEN is set but empty" >&2
    exit 1
  fi

  echo "==> Test 3: Sigstore sign + verify"
  sigstore_signed="$("$PDF_SIGN" sign input.pdf --backend sigstore --identity-token "$SIGSTORE_IDENTITY_TOKEN")" || {
    echo "ERROR: Sigstore sign failed (token may be invalid or expired)" >&2
    exit 1
  }
  "$PDF_SIGN" verify "$sigstore_signed" | grep -x OK >/dev/null
  echo "    [OK] Sigstore sign + verify passed"

  echo "==> Test 4: Multi-backend signing (GPG + Sigstore)"
  # Start with GPG-signed PDF, add Sigstore signature
  multi_backend="$("$PDF_SIGN" sign "$signed" --backend sigstore --identity-token "$SIGSTORE_IDENTITY_TOKEN")" || {
    echo "ERROR: Sigstore sign failed (token may be invalid or expired)" >&2
    exit 1
  }
  # Verify should find both GPG and Sigstore signatures
  "$PDF_SIGN" verify "$multi_backend" --cert cert1.asc | grep -x OK >/dev/null
  echo "    [OK] Multi-backend signing passed"
else
  echo "==> Skipping Sigstore tests (SIGSTORE_IDENTITY_TOKEN not set)"
fi

echo ""
echo "[SUCCESS] All e2e tests passed"

if [[ -n "${out:-}" ]]; then
  touch "$out"
fi
