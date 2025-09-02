
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Initial release scaffolding.

---

## [1.0.0] - 2025-09-01

### Added
- `SecureCrypto.dll` (C# cryptography library).
- `securecrypto.py` Python wrapper with helpers for:
  - AES encryption/decryption (strings, bytes, files).
  - RSA hybrid encryption/decryption.
  - Digital signatures (strings, files, `.sig` helpers).
  - Hashing (SHA256, SHA512).
  - HMAC (HMAC-SHA256, HMAC-SHA512).
  - Keypair generation and import/export.
  - Utility: `encode_bytes`, constants for algorithms.
- `examples/` folder with AES, RSA Hybrid, and Signing demos.
- `IMPLEMENTATION_IDEAS.md` for real-world usage inspiration.
- `CONTRIBUTING.md` guide for contributors.
- `LICENSE` (MIT).
- `securecrypto_cheatsheet.pdf` quick reference.
- `README.md` with badges, install/use instructions, and links.

