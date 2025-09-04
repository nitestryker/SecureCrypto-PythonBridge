# SecureCrypto-PythonBridge

[![PyPI](https://img.shields.io/pypi/v/securecrypto-bridge)](https://pypi.org/project/securecrypto-bridge/)
![Python Versions](https://img.shields.io/pypi/pyversions/securecrypto-bridge)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![CI - Python self-test](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/test.yml/badge.svg)](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/test.yml)


<div align="center">

🔐 **Production-ready cryptographic toolkit that just works**  
*Seamlessly bridge .NET cryptography power with Python simplicity*

</div>

---

## ⚡ Why SecureCrypto?

Building secure applications shouldn't require a PhD in cryptography. SecureCrypto delivers enterprise-grade encryption, signing, and key management through a clean Python API that wraps a battle-tested .NET cryptography library.

```python
import securecrypto_bridge as sc

# It's this simple
encrypted = sc.encrypt("Secret data", "your-password")
decrypted = sc.decrypt(encrypted, "your-password")
```

## ✨ What's Inside

<table>
<tr>
<td width="50%">

**🔒 Encryption Arsenal**
- AES symmetric encryption with PBKDF2 key derivation
- RSA hybrid encryption for secure key exchange
- File encryption with `.enc` format (salt + IV included)

**🔑 Digital Security**
- RSA digital signatures for authenticity
- HMAC generation & verification
- SHA256/SHA512 hashing algorithms

</td>
<td width="50%">

**🛠️ Developer Experience**
- Clean Pythonic API design
- Comprehensive CLI tools
- Ready-to-use examples
- Zero-config setup

**📁 File Operations**
- Encrypt/decrypt files of any size
- Digital signature workflows (`.sig` files)
- Batch processing capabilities

</td>
</tr>
</table>

> ⚠️ **Platform Support**: Currently Windows-only (leverages .NET Framework via pythonnet). Cross-platform support is on our roadmap.

## 🚀 Quick Setup

```bash
# Install from PyPI
pip install securecrypto-bridge

# Or install from source for development
pip install -e .
```

**That's it!** The library automatically handles .NET DLL loading and initialization.

## 💡 Get Started in 30 Seconds

```python
import securecrypto as sc

# Initialize the library
sc.init()

# 🔐 Password-based encryption
secret_data = "My confidential information"
encrypted = sc.encrypt(secret_data, "strong-password-123")
decrypted = sc.decrypt(encrypted, "strong-password-123")

# 🔍 Cryptographic hashing
file_hash = sc.hash_string("important-data", sc.ALGORITHMS[0])

# 🔑 Public-key cryptography
public_key, private_key = sc.generate_keypair()
ciphertext = sc.hybrid_encrypt("Top secret message", public_key)
plaintext = sc.hybrid_decrypt(ciphertext, private_key)

# ✍️ Digital signatures
signature = sc.sign_string("document-content", private_key)
is_valid = sc.verify_string("document-content", signature, public_key)
print(f"Signature valid: {is_valid}")
```

## 🖥️ Command Line Power Tools

<details>
<summary><b>🔓 Click to expand CLI examples</b></summary>

### File Encryption & Decryption
```bash
# Encrypt a file
python -m securecrypto encrypt -p "mypassword" -i document.pdf -o document.enc

# Decrypt it back
python -m securecrypto decrypt -p "mypassword" -i document.enc -o document-restored.pdf
```

### Digital Signatures
```bash
# Sign a document
python -m securecrypto sign -k private.pem -i contract.pdf -o contract.sig

# Verify the signature
python -m securecrypto verify -k public.pem -i contract.pdf -s contract.sig
```

### Hashing & HMAC
```bash
# Generate file hash
python -m securecrypto hash -i largefile.zip -a sha256

# Create HMAC with shared secret
python -m securecrypto hmac -p "shared-secret" -i data.json -a sha512
```

### Get Help Anytime
```bash
python -m securecrypto --help
```

**CLI Reference:**

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `encrypt` | Password-based file encryption | `-p` (password), `-i` (input), `-o` (output) |
| `decrypt` | Decrypt encrypted files | `-p` (password), `-i` (input), `-o` (output) |
| `sign` | Create digital signatures | `-k` (private key), `-i` (file), `-o` (signature) |
| `verify` | Verify signatures | `-k` (public key), `-i` (file), `-s` (signature) |
| `hash` | Generate file hashes | `-i` (input), `-a` (algorithm) |
| `hmac` | Generate HMAC | `-p` (password), `-i` (input), `-a` (algorithm) |

</details>

## 📚 Learn More

- **[📄 Cheatsheet (PDF)](securecrypto_cheatsheet.pdf)** — One-page quick reference for all functions
- **[💡 Implementation Ideas](IMPLEMENTATION_IDEAS.md)** — Real-world integration patterns and use cases

## 🏗️ Architecture

### C# Core Engine
The heart of SecureCrypto is a robust .NET class library that implements industry-standard cryptographic algorithms with proper security practices.

**Build Requirements:**
- .NET Framework 4.8 (Windows)
- Visual Studio 2022 or compatible IDE
- Python bridge requires `pythonnet`

**Project Structure:**
```
SecureCrypto/
├── SecureCrypto.sln          # Visual Studio solution
├── SecureCrypto/
│   ├── SecureCrypto.csproj   # C# project configuration  
│   └── CryptoLib.cs          # Core cryptographic implementation
```

**Building from Source:**
1. Open `SecureCrypto.sln` in Visual Studio
2. Build in **Release** mode
3. The compiled DLL will be ready for Python integration

## 🎯 Example Playground

Explore real-world scenarios with our example collection in the [`examples/`](examples) directory:

- **[`aes_example.py`](examples/aes_example.py)** — Master symmetric encryption patterns
- **[`rsa_hybrid_example.py`](examples/rsa_hybrid_example.py)** — Learn hybrid encryption workflows  
- **[`sign_verify_example.py`](examples/sign_verify_example.py)** — Implement digital signature verification

```bash
# Try them out
python examples/aes_example.py
python examples/rsa_hybrid_example.py  
python examples/sign_verify_example.py
```

## 🛡️ Security Best Practices

- **🔐 Private Key Management**: Store private keys securely. Never commit them to version control
- **💪 Strong Passwords**: Use complex passwords for AES key derivation (12+ characters recommended)
- **🔍 Modern Algorithms**: Prefer SHA256/SHA512 over legacy hash functions
- **🤝 Authentication Methods**: 
  - Use HMAC for shared-secret scenarios
  - Use RSA signatures for public/private key workflows
- **🔄 Regular Updates**: Keep the library updated for the latest security patches

## 📄 License

This project is released under the MIT License. You're free to use it in your applications, but please ensure compliance with your local security regulations and industry standards.

---

<div align="center">

**Built with ❤️ for developers who value security and simplicity**

[Report Issues](../../issues) • [Contribute](../../pulls) • [Documentation](../../wiki)

</div>