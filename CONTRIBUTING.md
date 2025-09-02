
# Contributing to SecureCrypto-PythonBridge

First off, thank you for considering contributing! 🚀

This project provides a .NET cryptography DLL (`SecureCrypto.dll`) and a Python wrapper (`securecrypto.py`).
Contributions are welcome in the form of bug reports, documentation, examples, or feature improvements.

---

## 📋 How to Contribute

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/SecureCrypto-PythonBridge.git
   cd SecureCrypto-PythonBridge
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feature/my-improvement
   ```
4. **Make your changes**:
   - Add new examples under the `examples/` folder.
   - Update documentation (`README.md`, `IMPLEMENTATION_IDEAS.md`).
   - Improve `securecrypto.py` with additional helpers or error handling.
5. **Run tests / self-test**:
   ```bash
   python securecrypto.py
   ```
   The built-in self-test should pass without errors.
6. **Commit and push**:
   ```bash
   git commit -am "Add: my improvement description"
   git push origin feature/my-improvement
   ```
7. **Open a Pull Request** on GitHub.

---

## 🧩 Contribution Ideas

- Add more example scripts (API signing, encrypted note app, file integrity checker).
- Expand documentation with tutorials and diagrams.
- Improve cross-platform instructions (Linux/macOS usage with Mono/.NET).
- Wrap additional .NET crypto utilities if needed.

---

## ⚠️ Security Considerations

- Do not commit or share private keys in the repo.
- Use only test/demo keys in examples.
- Keep in mind this project is for educational and development purposes — not production-ready security audits.

---

Thank you for helping improve SecureCrypto-PythonBridge! 🙌
