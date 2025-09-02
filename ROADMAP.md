
# Roadmap

This roadmap outlines potential improvements and milestones for **SecureCrypto-PythonBridge**.
Use it as a living plan—check items off as they ship and open issues/PRs to discuss changes.

---

## ✅ Recently Shipped
- [x] Python wrapper with AES/RSA/Hash/HMAC/Sign/Verify helpers
- [x] Examples folder (AES, Hybrid RSA, Sign/Verify)
- [x] Cheatsheet (PDF), Implementation Ideas doc
- [x] README with badges + Windows CI workflow
- [x] CONTRIBUTING, LICENSE (MIT), CHANGELOG, Release template
- [x] Signature I/O helpers and extra encoding utilities

---

## 🐣 v1.1 — Developer Ergonomics
- [ ] Publish to **PyPI** (`pip install securecrypto-bridge`) with wheel
- [ ] Add structured exceptions and error messages (e.g., `KeyLoadError`, `DecryptError`)
- [ ] Add richer type hints + docstrings for every function
- [ ] Add `encrypt_and_sign` / `verify_and_decrypt` convenience pairs
- [ ] CLI tool (`python -m securecrypto ...`) for quick terminal usage
- [ ] More examples: API HMAC signing; encrypted notes demo
- [ ] Benchmarks: AES/Hybrid performance on typical files

---

## 🧪 v1.2 — Testing & CI
- [ ] Unit tests for wrapper behavior (pytest)
- [ ] Fixtures for temporary keys/files
- [ ] Extended CI steps: run tests, coverage report artifact
- [ ] Linting + formatting (ruff/black) and pre-commit hooks

---

## 🖥️ v1.3 — Cross‑Platform
- [ ] Linux/macOS CI jobs with .NET runtime configuration (Mono/.NET)
- [ ] Docs for installing dependencies on Linux/macOS
- [ ] Validate DLL interop or offer **.NET 6/7** cross-platform build

---

## 🔐 v1.4 — Security Hardening
- [ ] Optional key storage integrations: DPAPI (Windows), Keychain (macOS), libsecret (Linux)
- [ ] Encrypted private key export (password-protected PEM/XML)
- [ ] Add key rotation patterns and helpers
- [ ] Timing-safe compare for HMAC verification (constant-time)

---

## 📦 v1.5 — Packaging & Distribution
- [ ] Pre-built releases with signed assets
- [ ] Versioned `SecureCrypto.dll` with **strong name** or code signing
- [ ] `pipx` install instructions for CLI
- [ ] Docker dev container for examples/tests

---

## 📚 v1.6 — Docs & Site
- [ ] Full API Reference (mkdocs + mkdocstrings)
- [ ] Tutorials: file encryption workflow, signed update pipeline
- [ ] Architecture diagram: AES + RSA hybrid format details
- [ ] Security FAQ and best practices

---

## 🚀 v2.0 — Advanced Features (Exploration)
- [ ] Streaming/chunked file encryption for very large files
- [ ] Parallel encryption paths for performance
- [ ] Optional authenticated encryption (AES-GCM) path
- [ ] Pluggable KDF (Argon2id option in addition to PBKDF2)
- [ ] Backward-compatible on-disk formats with version bytes
- [ ] Minimal REST service example for server-side operations

---

## 🗺️ Nice-to-Have / Backlog
- [ ] GUI demo (Tkinter/PySide) for encrypt/sign workflows
- [ ] Example integration with FastAPI/Flask
- [ ] Key discovery and trust model patterns (pubkey fingerprints)
- [ ] Example: S3 encrypted backups with lifecycle policies
- [ ] Localization-ready strings for CLI outputs

---

## 📌 Notes
- Adopt **Semantic Versioning**; reflect breaking changes with major bumps.
- Keep **CHANGELOG** updated; tag releases following `vX.Y.Z`.
- Prioritize API stability and security best practices.
