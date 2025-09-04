# SecureCrypto-PythonBridge
## Badges (add under title)
[![PyPI](https://img.shields.io/pypi/v/securecrypto-bridge)](https://pypi.org/project/securecrypto-bridge/)
![Python Versions](https://img.shields.io/pypi/pyversions/securecrypto-bridge)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![CI - Python self-test](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/test.yml/badge.svg)](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/test.yml)
[![Nightly - Assign Milestones](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/assign-milestones.yml/badge.svg)](https://github.com/nitestryker/SecureCrypto-PythonBridge/actions/workflows/assign-milestones.yml)


🔐 A ready-to-use .NET cryptography library (**SecureCrypto.dll**) with a Python wrapper (**securecrypto.py**) for easy encryption, decryption, hashing, signing, and key management in your own applications.

---

## ✨ Features
- AES (symmetric encryption with password-derived keys)
- RSA hybrid encryption (AES + RSA for secure key exchange)
- Digital signatures (sign/verify strings and files)
- File encryption/decryption (`.enc` format with salt + IV)
- Hashing (SHA256, SHA512)
- HMAC generation & verification (HMAC-SHA256, HMAC-SHA512)
- Keypair generation, import/export
- Signature file helpers (`.sig` workflow)
- Clean Pythonic API wrapping the .NET DLL

---

> ⚠️ Platform: Windows only (uses a .NET DLL via pythonnet). Linux/macOS planned in the roadmap.

## Installation
```bash
pip install securecrypto-bridge
```

From source (dev):
```bash
pip install -e .
```

## Quick Start
```python
import securecrypto_bridge as sc

c = sc.encrypt("Hello", "pw")
print(sc.decrypt(c, "pw"))
print(sc.hash_string("abc"))
```


## 🚀 Quick Usage

```python
import securecrypto as sc

sc.init()  # loads SecureCrypto.dll

# AES encrypt/decrypt
c = sc.encrypt("Hello", "mypassword")
print("Ciphertext:", c)
print("Plaintext:", sc.decrypt(c, "mypassword"))

# Hashing
print(sc.hash_string("abc", sc.ALGORITHMS[0]))

# Hybrid RSA + AES
pub, priv = sc.generate_keypair()
ct = sc.hybrid_encrypt("Top Secret", pub)
print(sc.hybrid_decrypt(ct, priv))

# Signing & verifying
sig = sc.sign_string("hello", priv)
print("Signature valid?", sc.verify_string("hello", sig, pub))
```

<details>
  <summary>📦 Command Line Interface (CLI)</summary>

Use `python -m securecrypto` from your terminal for quick operations.

### 🔐 Encryption

```bash
python -m securecrypto encrypt -p "mypassword" -i plaintext.txt -o secret.enc
```

### 🔓 Decryption

```bash
python -m securecrypto decrypt -p "mypassword" -i secret.enc -o decrypted.txt
```

### ✍️ Sign a file

```bash
python -m securecrypto sign -k private.pem -i myfile.txt -o myfile.sig
```

### ✅ Verify a signature

```bash
python -m securecrypto verify -k public.pem -i myfile.txt -s myfile.sig
```

### 🔁 Hash a file

```bash
python -m securecrypto hash -i myfile.txt -a sha256
```

### 🧪 HMAC a file

```bash
python -m securecrypto hmac -p "sharedsecret" -i myfile.txt -a sha512
```

---

### 🆘 Help Menu

```bash
python -m securecrypto --help
```

**Flags Overview:**

| Flag/Option         | Description                               |
|---------------------|-------------------------------------------|
| `-i, --input`        | Path to input file                        |
| `-o, --output`       | Path to output file                       |
| `-p, --password`     | Password for AES or HMAC                  |
| `-k, --key`          | Path to RSA key (public or private)       |
| `-s, --signature`    | Path to signature file                    |
| `-a, --algorithm`    | Algorithm to use (`sha256`, `sha512`, etc)|
| `--help`             | Show help text                            |

</details>

---

## 📘 Documentation

- [Cheatsheet (PDF)](securecrypto_cheatsheet.pdf) — one-page quick reference  
- [Implementation Ideas](IMPLEMENTATION_IDEAS.md) — how to use this library in real projects  

---
## SecureCrypto C# Source

This folder contains the full C# source code for building the `SecureCrypto.dll` used in the Python bridge.

## 🔧 Requirements

- .NET Framework 4.8 (Windows)
- Visual Studio 2022 (or compatible)
- Python consumers must install `pythonnet`

## 📦 Project Contents

- `SecureCrypto.sln` – Solution file
- `SecureCrypto/` – C# class library
  - `SecureCrypto.csproj` – Project file
  - `CryptoLib.cs` – Core cryptographic logic

## 🛠 How to Build

1. Open the `SecureCrypto.sln` in Visual Studio.
2. Build the solution in **Release** mode.
3. The DLL will be located at:



---

## 📂 Examples

You can find runnable demo scripts in the [`examples/`](examples) folder:

- `aes_example.py` — AES string encryption & decryption
- `rsa_hybrid_example.py` — Hybrid RSA + AES encrypt/decrypt
- `sign_verify_example.py` — Signing and verifying strings & files

Run them with:

```bash
python examples/aes_example.py
python examples/rsa_hybrid_example.py
python examples/sign_verify_example.py
```

## ⚠️ Security Notes
- Keep private keys safe. Never share them.
- Use strong passwords for AES key derivation.
- Use SHA256/SHA512 over older hash algorithms.
- HMAC is for shared-secret verification; RSA signatures are for public/private workflows.

---

## 📄 License
This project is provided as-is for educational and development use. You are responsible for ensuring compliance with applicable laws and security standards when integrating into your applications.
