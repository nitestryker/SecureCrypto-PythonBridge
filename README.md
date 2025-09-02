# SecureCrypto-PythonBridge

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)


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

## 📦 Installation

1. Install [pythonnet](https://github.com/pythonnet/pythonnet):

```bash
pip install pythonnet
```

2. Clone this repository and place `SecureCrypto.dll` and `securecrypto.py` next to your project files.

---

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

---

## 📘 Documentation

- [Cheatsheet (PDF)](securecrypto_cheatsheet.pdf) — one-page quick reference  
- [Implementation Ideas](IMPLEMENTATION_IDEAS.md) — how to use this library in real projects  

---


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
