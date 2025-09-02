# securecrypto.py
# Thin Python wrapper around SecureCrypto.dll (C#) for simple, pythonic calls.
# Assumes SecureCrypto.dll is next to this file or provide a path to init().
#
# Exposes:
# - init(dll_path=None)
# - encrypt(text, password, encoding='base64') / decrypt(base64_cipher, password)
# - encrypt_hex(text, password)
# - encrypt_bytes(data: bytes, password) -> bytes / decrypt_bytes(data: bytes, password) -> bytes
# - encrypt_file(in_path, out_path, password) / decrypt_file(in_path, out_path, password)
# - generate_keypair() -> (public_key_xml, private_key_xml)
# - hybrid_encrypt(text, public_key_xml) / hybrid_decrypt(b64, private_key_xml)
# - sign_string(text, private_key_xml) / verify_string(text, b64_signature, public_key_xml)
# - sign_file(path, private_key_xml) / verify_file(path, b64_signature, public_key_xml)
# - sign_file_to(path, private_key_xml, sig_path=None) -> str
# - verify_file_from(path, sig_path, public_key_xml) -> bool
# - hash_string(text, algorithm='SHA256') / hash_file(path, algorithm='SHA256')
# - hmac(message, key, algorithm='HMACSHA256') / hmac_verify(message, expected_hex, key, algorithm='HMACSHA256')
# - export_key_to_file(key_xml, path) / import_key_from_file(path)
# - encode_bytes(data, format='base64')
#
# Works with pythonnet >= 3.x.

import os
from pathlib import Path

_loaded = False
CryptoHelper = None
OutputEncoding = None

def init(dll_path: str | os.PathLike | None = None) -> None:
    """Load SecureCrypto.dll via pythonnet. If dll_path is None, search next to this file."""
    global _loaded, CryptoHelper, OutputEncoding
    if _loaded:
        return

    try:
        import clr  # type: ignore
    except ImportError as e:
        raise RuntimeError("pythonnet is required. Install with: pip install pythonnet") from e

    # Resolve path
    if dll_path is None:
        here = Path(__file__).resolve().parent
        candidate = here / "SecureCrypto.dll"
    else:
        candidate = Path(dll_path).resolve()

    if not candidate.exists():
        # Fallback: try to let CLR probe by name if DLL is in CWD
        try:
            clr.AddReference("SecureCrypto")
        except Exception as e:
            raise FileNotFoundError(
                f"Could not find SecureCrypto.dll at {candidate} and AddReference by name failed."
            ) from e
    else:
        # pythonnet 3.x accepts full path
        clr.AddReference(str(candidate))

    # Import after reference
    from SecureCrypto import CryptoHelper as _CH, OutputEncoding as _OE  # type: ignore
    CryptoHelper = _CH
    OutputEncoding = _OE
    _loaded = True


# --------- Extra helpers & constants ---------
ALGORITHMS = ("SHA256", "SHA512")
HMAC_ALGORITHMS = ("HMACSHA256", "HMACSHA512")
HMAC_ALGORITHMS_MAP = {
    "sha256": "HMACSHA256",
    "sha512": "HMACSHA512",
}

def encode_bytes(data: bytes, format: str = 'base64'):
    """Encode raw bytes to base64/hex/bytes via the DLL's EncodeBytes utility."""
    init()
    fmt = format.lower()
    if fmt == 'base64':
        return CryptoHelper.EncodeBytes(bytearray(data), OutputEncoding.Base64)
    elif fmt == 'hex':
        return CryptoHelper.EncodeBytes(bytearray(data), OutputEncoding.Hex)
    elif fmt == 'raw':
        val = CryptoHelper.EncodeBytes(bytearray(data), OutputEncoding.Raw)
        return bytes(val)
    else:
        raise ValueError("format must be 'base64', 'hex', or 'raw'")


# --------- Symmetric (password) helpers ---------
def encrypt(text: str, password: str, encoding: str = 'base64'):
    """Encrypt string; encoding in {'base64','hex','raw'}.
    Returns base64/hex string or bytes for 'raw'."""
    init()
    enc = encoding.lower()
    if enc == 'base64':
        return CryptoHelper.Encrypt(text, password)
    elif enc == 'hex':
        return CryptoHelper.EncryptWithEncoding(text, password, OutputEncoding.Hex)
    elif enc == 'raw':
        return CryptoHelper.EncryptWithEncoding(text, password, OutputEncoding.Raw)
    else:
        raise ValueError("encoding must be 'base64', 'hex', or 'raw'")

def encrypt_hex(text: str, password: str) -> str:
    init()
    return CryptoHelper.EncryptWithEncoding(text, password, OutputEncoding.Hex)

def decrypt(base64_cipher: str, password: str) -> str:
    """Decrypt a Base64 ciphertext produced by encrypt(..., 'base64')."""
    init()
    return CryptoHelper.Decrypt(base64_cipher, password)

def encrypt_bytes(data: bytes, password: str) -> bytes:
    init()
    return bytes(CryptoHelper.EncryptBytes(bytearray(data), password))

def decrypt_bytes(data: bytes, password: str) -> bytes:
    init()
    return bytes(CryptoHelper.DecryptBytes(bytearray(data), password))

def encrypt_file(in_path: str | os.PathLike, out_path: str | os.PathLike, password: str) -> None:
    init()
    CryptoHelper.EncryptFile(str(in_path), str(out_path), password)

def decrypt_file(in_path: str | os.PathLike, out_path: str | os.PathLike, password: str) -> None:
    init()
    CryptoHelper.DecryptFile(str(in_path), str(out_path), password)


# --------- Asymmetric / Hybrid ---------
def generate_keypair() -> tuple[str, str]:
    """Return (public_key_xml, private_key_xml)."""
    init()
    # pythonnet 3.x returns a tuple for out params
    pub, priv = CryptoHelper.GenerateKeyPair()
    return pub, priv

def hybrid_encrypt(text: str, public_key_xml: str) -> str:
    init()
    return CryptoHelper.HybridEncrypt(text, public_key_xml)

def hybrid_decrypt(b64: str, private_key_xml: str) -> str:
    init()
    return CryptoHelper.HybridDecrypt(b64, private_key_xml)


# --------- Signing ---------
def sign_string(text: str, private_key_xml: str) -> str:
    init()
    return CryptoHelper.SignString(text, private_key_xml)

def verify_string(text: str, b64_signature: str, public_key_xml: str) -> bool:
    init()
    return CryptoHelper.VerifyString(text, b64_signature, public_key_xml)

def sign_file(path: str | os.PathLike, private_key_xml: str) -> str:
    init()
    return CryptoHelper.SignFile(str(path), private_key_xml)

def verify_file(path: str | os.PathLike, b64_signature: str, public_key_xml: str) -> bool:
    init()
    return CryptoHelper.VerifyFile(str(path), b64_signature, public_key_xml)

def sign_file_to(path: str | os.PathLike, private_key_xml: str, sig_path: str | os.PathLike | None = None) -> str:
    """
    Sign a file and write the signature to a .sig file (next to the file if sig_path is None).
    Returns the signature file path.
    """
    init()
    path_str = str(path)
    sig_b64 = CryptoHelper.SignFile(path_str, private_key_xml)
    if sig_path is None:
        sig_path = path_str + ".sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(sig_b64)
    return str(sig_path)

def verify_file_from(path: str | os.PathLike, sig_path: str | os.PathLike, public_key_xml: str) -> bool:
    """
    Verify a file against a signature stored in a .sig file.
    Returns True if valid, False otherwise.
    """
    init()
    with open(sig_path, "r", encoding="utf-8") as f:
        sig_b64 = f.read().strip()
    return CryptoHelper.VerifyFile(str(path), sig_b64, public_key_xml)


# --------- Hash / HMAC ---------
def hash_string(text: str, algorithm: str = 'SHA256') -> str:
    init()
    return CryptoHelper.HashString(text, algorithm)

def hash_file(path: str | os.PathLike, algorithm: str = 'SHA256') -> str:
    init()
    return CryptoHelper.HashFile(str(path), algorithm)

def hmac(message: str, key: str, algorithm: str = 'HMACSHA256') -> str:
    init()
    return CryptoHelper.GenerateHMAC(message, key, algorithm)

def hmac_verify(message: str, expected_hex: str, key: str, algorithm: str = 'HMACSHA256') -> bool:
    init()
    return CryptoHelper.VerifyHMAC(message, expected_hex, key, algorithm)


# --------- Key I/O ---------
def export_key_to_file(key_xml: str, path: str | os.PathLike) -> None:
    init()
    CryptoHelper.ExportKeyToFile(key_xml, str(path))

def import_key_from_file(path: str | os.PathLike) -> str:
    init()
    return CryptoHelper.ImportKeyFromFile(str(path))


# --------- Signature file I/O helpers ---------
def save_signature(path: str | os.PathLike, signature_b64: str, sig_path: str | os.PathLike | None = None) -> str:
    """Save a Base64 signature string to a .sig file next to 'path' unless sig_path is provided.
    Returns the signature file path.
    """
    path_str = str(path)
    if sig_path is None:
        sig_path = path_str + ".sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(signature_b64)
    return str(sig_path)

def load_signature(sig_path: str | os.PathLike) -> str:
    """Load a Base64 signature from a .sig file (returns stripped string)."""
    with open(sig_path, "r", encoding="utf-8") as f:
        return f.read().strip()


# --------- Tiny self-test when run directly ---------
if __name__ == '__main__':
    print("[securecrypto] Self-test starting...")
    init()  # ensure DLL loaded

    # Constants
    print("ALGORITHMS:", ALGORITHMS)
    print("HMAC_ALGORITHMS:", HMAC_ALGORITHMS)
    print("HMAC_ALGORITHMS_MAP:", HMAC_ALGORITHMS_MAP)

    # Symmetric encrypt/decrypt
    ct_b64 = encrypt("Hello", "pw")
    assert decrypt(ct_b64, "pw") == "Hello"
    print("AES string round-trip OK")

    # Bytes + encode_bytes
    blob = b"\x01\x02\xff"
    enc_b64 = encode_bytes(blob, "base64")
    enc_hex = encode_bytes(blob, "hex")
    enc_raw = encode_bytes(blob, "raw")
    assert isinstance(enc_b64, str) and isinstance(enc_hex, str) and isinstance(enc_raw, (bytes, bytearray))
    print("encode_bytes OK:", enc_b64, enc_hex, bytes(enc_raw))

    # Hybrid + signing
    pub, priv = generate_keypair()
    hct = hybrid_encrypt("Top Secret", pub)
    assert hybrid_decrypt(hct, priv) == "Top Secret"
    print("Hybrid RSA+AES round-trip OK")

    sig = sign_string("hello", priv)
    assert verify_string("hello", sig, pub) is True
    print("Sign/Verify string OK")

    # File sign/verify
    tmp = Path("sc_demo.txt")
    tmp.write_text("demo content")
    sig_file = sign_file_to(tmp, priv)           # write .sig
    assert verify_file_from(tmp, sig_file, pub)  # verify via .sig file
    sig_loaded = load_signature(sig_file)
    assert verify_file(tmp, sig_loaded, pub)     # verify via loaded string
    print("Sign/Verify file OK (via .sig and loaded string)")

    # Hash/HMAC
    assert hash_string("abc", ALGORITHMS[0]) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    hm = hmac("msg", "key", HMAC_ALGORITHMS[0])
    assert hmac_verify("msg", hm, "key", HMAC_ALGORITHMS_MAP["sha256"]) is True
    print("Hash/HMAC OK")

    print("[securecrypto] Self-test PASSED ✅")
