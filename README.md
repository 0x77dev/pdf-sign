# pdf-sign

A lightweight, modern PDF signing utility written in Rust. It creates an Adobe-compatible detached OpenPGP (GPG) signature and appends it to the PDF, making it easy to sign and verify documents without dragging in heavyweight PDF signing stacks.

It’s designed to be a practical alternative to “traditional” PDF signing workflows: minimal setup, scriptable CLI, and it delegates cryptography to your existing `gpg-agent` (including smartcards/YubiKey).

The signed output stays minimal: the original PDF content is preserved and the signature is appended, keeping the file compliant so it still opens normally in standard PDF viewers.

## Features

* **Simple CLI**: `sign` and `verify` commands that compose well in pipelines.
* **Works with your existing GPG setup**: Uses `gpg-agent` and your keyring (respects `GNUPGHOME`).
* **Hardware-friendly**: Private keys can stay on a smartcard/YubiKey.
* **Lightweight distribution**: Single-file script you can run directly (see Quickstart).

## Security model

* **No private keys in the tool**: All signing operations are performed by `gpg-agent`.
* **Reduced key exposure**: Private keys never need to be loaded into this process.
* **Explicit verification**: Verifies the appended signature against a provided certificate.

## Quickstart

### Zero-Install Execution

Download the script and execute it. The `nix-shell` shebang will provision dependencies automatically.

```bash
curl -fsSL https://raw.githubusercontent.com/0x77dev/pdf-sign/main/pdf-sign.rs -o pdf-sign.rs
chmod +x pdf-sign.rs
./pdf-sign.rs sign document.pdf --key 0xDEADBEEF
```

### Local Execution

If you already have `pdf-sign.rs` locally, ensure it's executable. The shebang handles the rest.

```bash
chmod +x pdf-sign.rs
./pdf-sign.rs sign input.pdf --key 0xDEADBEEF
```

## Methodology

`pdf-sign` focuses on doing the minimum work needed to connect PDF bytes to `gpg-agent` safely:

1. **PDF Parsing**: Locates the `%%EOF` marker to identify the exact byte range for signing.
2. **Agent Delegation**: Talks to `gpg-agent` (Assuan protocol via `sequoia-gpg-agent`) to perform signing.
3. **Key Isolation**: Your private key stays in `gpg-agent` or on hardware; the tool only handles public material.
4. **Compatibility**: Produces an ASCII-armored detached signature packet and appends it to the PDF for verification.

## Requirements

* **Nix Package Manager**: Used for reproducible, hermetic runtime environment bootstrapping.
* **GnuPG**: A running `gpg-agent`.
* **Public Certificate**: The public key must be importable or available (file or keyring).
* **Private Key**: Managed by `gpg-agent` (Softkey or Smartcard/YubiKey).

## Commands

### Sign

Signs a PDF. Requires a key specification (File, Key ID, Fingerprint, or Email).

```bash
./pdf-sign.rs sign contract.pdf --key 0xF1171FAAAA237211
```

* **--output, -o**: Specify output path (Default: `input_signed.pdf`).
* **--key**: Key identifier. If a file path is not found, it queries `gpg --export`.

### Verify

Verifies the appended signature against a provided public certificate.

```bash
./pdf-sign.rs verify contract_signed.pdf --cert signing-key.asc
```

## Environment

* `GNUPGHOME`: Respected for keyring lookups.
* `stderr`: Used for all progress, status, and error reporting.
* `stdout`: Outputs the resulting file path (signing) or "OK" (verification) for pipeline composition.
