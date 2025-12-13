# pdf-sign

A minimalist, agent-centric PDF signing utility written in Rust utilizing. It generates Adobe-compliant detached PGP signatures appended to PDF documents while strictly delegating all cryptographic operations to the GPG Agent.

## Quickstart

### Zero-Install Execution

Leverage `nix-shell` to pull dependencies, compile, and execute the artifact ephemerally directly from the source URL.

```bash
nix-shell \
  https://raw.githubusercontent.com/0x77dev/pdf-sign/main/pdf-sign.rs \
  -- sign document.pdf --key 0xDEADBEEF
```

### Local Execution

Ensure the script is executable. The shebang handles the rest.

```bash
curl -fsSL https://raw.githubusercontent.com/0x77dev/pdf-sign/main/pdf-sign.rs -o pdf-sign.rs
chmod +x pdf-sign.rs
./pdf-sign.rs sign input.pdf --key 0xDEADBEEF
```

## Methodology

This tool adheres to a "No-Key-In-Memory" architecture. It acts as a bridge between the PDF file structure and the GPG Agent socket.

1. **PDF Parsing**: Locates the `%%EOF` marker to identify the exact byte range for signing.
2. **Agent Delegation**: Connects directly to the `gpg-agent` Unix socket using the Assuan protocol via `sequoia-gpg-agent`.
3. **Hardware Isolation**: Private keys never leave the secure element (YubiKey/Smartcard) or the agent's protected memory. The tool only handles the public certificate stub.
4. **Standardization**: Produces an ASCII-armored detached signature packet and appends it to the PDF, ensuring compatibility with standard verification tools.

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
