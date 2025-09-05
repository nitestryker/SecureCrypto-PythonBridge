# securecrypto.py
# Thin Python wrapper around SecureCrypto.dll (C#) for simple, pythonic calls.
# Assumes SecureCrypto.dll is bundled inside the installed package or next to this file.
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
# - encrypt_and_sign() / verify_and_decrypt() and related helpers
#
# Works with pythonnet >= 3.x.

import os
import sys
from pathlib import Path
import importlib.resources as ir  # NEW: for loading DLL when installed as a package


# --------- Custom Exception Classes ---------
class SecureCryptoError(Exception):
    """Base exception class for all SecureCrypto errors."""
    pass


class DllLoadError(SecureCryptoError):
    """Raised when SecureCrypto.dll cannot be loaded or found."""
    pass


class KeyError(SecureCryptoError):
    """Base class for key-related errors."""
    pass


class KeyLoadError(KeyError):
    """Raised when a key cannot be loaded from file or parsed."""
    pass


class KeyGenerationError(KeyError):
    """Raised when key generation fails."""
    pass


class KeyFormatError(KeyError):
    """Raised when a key is in an invalid format."""
    pass


class EncryptionError(SecureCryptoError):
    """Base class for encryption-related errors."""
    pass


class DecryptionError(SecureCryptoError):
    """Base class for decryption-related errors."""
    pass


class DecryptError(DecryptionError):
    """Raised when decryption fails (wrong password, corrupted data, etc.)."""
    pass


class SigningError(SecureCryptoError):
    """Raised when digital signing operations fail."""
    pass


class VerificationError(SecureCryptoError):
    """Raised when signature verification fails or is invalid."""
    pass


class HashingError(SecureCryptoError):
    """Raised when hashing operations fail."""
    pass


class HmacError(SecureCryptoError):
    """Raised when HMAC operations fail."""
    pass


class FileOperationError(SecureCryptoError):
    """Raised when file operations (encrypt/decrypt/sign files) fail."""
    pass


class EncodingError(SecureCryptoError):
    """Raised when encoding/format conversion operations fail."""
    pass


_loaded = False
CryptoHelper = None
OutputEncoding = None

def _find_packaged_dll() -> Path | None:
    """
    Try to locate SecureCrypto.dll inside the installed package using importlib.resources.
    Returns a Path if found, else None.
    """
    try:
        # __package__ resolves to this module's package when installed/imported
        pkg = __package__ or __name__.rpartition(".")[0]
        # If this module is at top-level (no package), __package__ may be empty.
        if not pkg:
            return None
        candidate = ir.files(pkg).joinpath("SecureCrypto.dll")
        if candidate.is_file():
            return Path(candidate)
    except Exception:
        pass
    return None

def init(dll_path: str | os.PathLike | None = None) -> None:
    """Load SecureCrypto.dll via pythonnet. If dll_path is None, search the installed package first, then next to this file, then by name."""
    global _loaded, CryptoHelper, OutputEncoding
    if _loaded:
        return

    try:
        import clr  # type: ignore
    except ImportError as e:
        raise DllLoadError("pythonnet is required. Install with: pip install pythonnet") from e

    # Resolve DLL location in this order:
    # 1) Explicit dll_path (caller provided)
    # 2) Packaged resource (importlib.resources) when installed
    # 3) Next to this file (editable/development installs)
    # 4) Let CLR probe by assembly name "SecureCrypto"
    candidate: Path | None = None

    if dll_path is not None:
        candidate = Path(dll_path).resolve()
    else:
        candidate = _find_packaged_dll()
        if candidate is None:
            # Robust handling when __file__ is not defined (e.g., exec/open in CI)
            try:
                here = Path(__file__).resolve().parent  # type: ignore[name-defined]
            except NameError:
                here = Path.cwd()
            local = here / "SecureCrypto.dll"
            if local.exists():
                candidate = local

    if candidate is not None and candidate.exists():
        # Ensure the directory is on sys.path so dependent probing works if needed
        sys.path.append(str(candidate.parent))
        # pythonnet 3.x: AddReference can take an absolute path
        try:
            clr.AddReference(str(candidate))
        except Exception as e:
            raise DllLoadError(f"Failed to load SecureCrypto.dll from {candidate}: {e}") from e
    else:
        # Fallback to assembly name if DLL is discoverable by CLR (e.g., in CWD)
        try:
            clr.AddReference("SecureCrypto")
        except Exception as e:
            where = candidate if candidate is not None else Path("<not found>")
            raise DllLoadError(
                f"Could not locate SecureCrypto.dll (looked at {where}). "
                f"Ensure the DLL is packaged with this module or provide dll_path to init()."
            ) from e

    # Import after reference
    try:
        from SecureCrypto import CryptoHelper as _CH, OutputEncoding as _OE  # type: ignore
        CryptoHelper = _CH
        OutputEncoding = _OE
        _loaded = True
    except Exception as e:
        raise DllLoadError(f"Failed to import from SecureCrypto.dll: {e}") from e


# --------- Extra helpers & constants ---------
ALGORITHMS = ("SHA256", "SHA512")
HMAC_ALGORITHMS = ("HMACSHA256", "HMACSHA512")
HMAC_ALGORITHMS_MAP = {
    "sha256": "HMACSHA256",
    "sha512": "HMACSHA512",
}

def encode_bytes(data: bytes, format: str = 'base64'):
    """Encode raw bytes to base64/hex/bytes via the DLL's EncodeBytes utility."""
    try:
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
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise EncodingError(f"Failed to encode bytes with format '{format}': {e}") from e


# --------- Symmetric (password) helpers ---------
def encrypt(text: str, password: str, encoding: str = 'base64'):
    """Encrypt string; encoding in {'base64','hex','raw'}.
    Returns base64/hex string or bytes for 'raw'."""
    try:
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
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt text: {e}") from e

def encrypt_hex(text: str, password: str) -> str:
    try:
        init()
        return CryptoHelper.EncryptWithEncoding(text, password, OutputEncoding.Hex)
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt text to hex: {e}") from e

def decrypt(base64_cipher: str, password: str) -> str:
    """Decrypt a Base64 ciphertext produced by encrypt(..., 'base64')."""
    try:
        init()
        return CryptoHelper.Decrypt(base64_cipher, password)
    except Exception as e:
        raise DecryptError(f"Failed to decrypt ciphertext (wrong password or corrupted data): {e}") from e

def encrypt_bytes(data: bytes, password: str) -> bytes:
    try:
        init()
        return bytes(CryptoHelper.EncryptBytes(bytearray(data), password))
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt bytes: {e}") from e

def decrypt_bytes(data: bytes, password: str) -> bytes:
    try:
        init()
        return bytes(CryptoHelper.DecryptBytes(bytearray(data), password))
    except Exception as e:
        raise DecryptError(f"Failed to decrypt bytes (wrong password or corrupted data): {e}") from e

def encrypt_file(in_path: str | os.PathLike, out_path: str | os.PathLike, password: str) -> None:
    try:
        init()
        CryptoHelper.EncryptFile(str(in_path), str(out_path), password)
    except Exception as e:
        raise FileOperationError(f"Failed to encrypt file '{in_path}' to '{out_path}': {e}") from e

def decrypt_file(in_path: str | os.PathLike, out_path: str | os.PathLike, password: str) -> None:
    try:
        init()
        CryptoHelper.DecryptFile(str(in_path), str(out_path), password)
    except Exception as e:
        raise FileOperationError(f"Failed to decrypt file '{in_path}' to '{out_path}' (wrong password or corrupted file): {e}") from e


# --------- Asymmetric / Hybrid ---------
def generate_keypair() -> tuple[str, str]:
    """Return (public_key_xml, private_key_xml)."""
    try:
        init()
        # pythonnet 3.x returns a tuple for out params
        pub, priv = CryptoHelper.GenerateKeyPair()
        return pub, priv
    except Exception as e:
        raise KeyGenerationError(f"Failed to generate RSA keypair: {e}") from e

def hybrid_encrypt(text: str, public_key_xml: str) -> str:
    try:
        init()
        return CryptoHelper.HybridEncrypt(text, public_key_xml)
    except Exception as e:
        raise EncryptionError(f"Failed to hybrid encrypt text: {e}") from e

def hybrid_decrypt(b64: str, private_key_xml: str) -> str:
    try:
        init()
        return CryptoHelper.HybridDecrypt(b64, private_key_xml)
    except Exception as e:
        raise DecryptError(f"Failed to hybrid decrypt text (invalid key or corrupted data): {e}") from e


# --------- Signing ---------
def sign_string(text: str, private_key_xml: str) -> str:
    try:
        init()
        return CryptoHelper.SignString(text, private_key_xml)
    except Exception as e:
        raise SigningError(f"Failed to sign string: {e}") from e

def verify_string(text: str, b64_signature: str, public_key_xml: str) -> bool:
    try:
        init()
        return CryptoHelper.VerifyString(text, b64_signature, public_key_xml)
    except Exception as e:
        raise VerificationError(f"Failed to verify string signature: {e}") from e

def sign_file(path: str | os.PathLike, private_key_xml: str) -> str:
    try:
        init()
        return CryptoHelper.SignFile(str(path), private_key_xml)
    except Exception as e:
        raise SigningError(f"Failed to sign file '{path}': {e}") from e

def verify_file(path: str | os.PathLike, b64_signature: str, public_key_xml: str) -> bool:
    try:
        init()
        return CryptoHelper.VerifyFile(str(path), b64_signature, public_key_xml)
    except Exception as e:
        raise VerificationError(f"Failed to verify file '{path}' signature: {e}") from e

def sign_file_to(path: str | os.PathLike, private_key_xml: str, sig_path: str | os.PathLike | None = None) -> str:
    """
    Sign a file and write the signature to a .sig file (next to the file if sig_path is None).
    Returns the signature file path.
    """
    try:
        init()
        path_str = str(path)
        sig_b64 = CryptoHelper.SignFile(path_str, private_key_xml)
        if sig_path is None:
            sig_path = path_str + ".sig"
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(sig_b64)
        return str(sig_path)
    except Exception as e:
        raise SigningError(f"Failed to sign file '{path}' to '{sig_path}': {e}") from e

def verify_file_from(path: str | os.PathLike, sig_path: str | os.PathLike, public_key_xml: str) -> bool:
    """
    Verify a file against a signature stored in a .sig file.
    Returns True if valid, False otherwise.
    """
    try:
        init()
        with open(sig_path, "r", encoding="utf-8") as f:
            sig_b64 = f.read().strip()
        return CryptoHelper.VerifyFile(str(path), sig_b64, public_key_xml)
    except FileNotFoundError as e:
        raise FileOperationError(f"Signature file '{sig_path}' not found: {e}") from e
    except Exception as e:
        raise VerificationError(f"Failed to verify file '{path}' from signature '{sig_path}': {e}") from e


# --------- Hash / HMAC ---------
def hash_string(text: str, algorithm: str = 'SHA256') -> str:
    try:
        init()
        return CryptoHelper.HashString(text, algorithm)
    except Exception as e:
        raise HashingError(f"Failed to hash string with algorithm '{algorithm}': {e}") from e

def hash_file(path: str | os.PathLike, algorithm: str = 'SHA256') -> str:
    try:
        init()
        return CryptoHelper.HashFile(str(path), algorithm)
    except Exception as e:
        raise HashingError(f"Failed to hash file '{path}' with algorithm '{algorithm}': {e}") from e

def hmac(message: str, key: str, algorithm: str = 'HMACSHA256') -> str:
    try:
        init()
        return CryptoHelper.GenerateHMAC(message, key, algorithm)
    except Exception as e:
        raise HmacError(f"Failed to generate HMAC with algorithm '{algorithm}': {e}") from e

def hmac_verify(message: str, expected_hex: str, key: str, algorithm: str = 'HMACSHA256') -> bool:
    try:
        init()
        return CryptoHelper.VerifyHMAC(message, expected_hex, key, algorithm)
    except Exception as e:
        raise HmacError(f"Failed to verify HMAC with algorithm '{algorithm}': {e}") from e


# --------- Key I/O ---------
def export_key_to_file(key_xml: str, path: str | os.PathLike) -> None:
    try:
        init()
        CryptoHelper.ExportKeyToFile(key_xml, str(path))
    except Exception as e:
        raise KeyError(f"Failed to export key to file '{path}': {e}") from e

def import_key_from_file(path: str | os.PathLike) -> str:
    try:
        init()
        return CryptoHelper.ImportKeyFromFile(str(path))
    except FileNotFoundError as e:
        raise KeyLoadError(f"Key file '{path}' not found: {e}") from e
    except Exception as e:
        raise KeyLoadError(f"Failed to load key from file '{path}': {e}") from e


# --------- Signature file I/O helpers ---------
def save_signature(path: str | os.PathLike, signature_b64: str, sig_path: str | os.PathLike | None = None) -> str:
    """Save a Base64 signature string to a .sig file next to 'path' unless sig_path is provided.
    Returns the signature file path.
    """
    try:
        path_str = str(path)
        if sig_path is None:
            sig_path = path_str + ".sig"
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(signature_b64)
        return str(sig_path)
    except Exception as e:
        raise FileOperationError(f"Failed to save signature to '{sig_path}': {e}") from e

def load_signature(sig_path: str | os.PathLike) -> str:
    """Load a Base64 signature from a .sig file (returns stripped string)."""
    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError as e:
        raise FileOperationError(f"Signature file '{sig_path}' not found: {e}") from e
    except Exception as e:
        raise FileOperationError(f"Failed to load signature from '{sig_path}': {e}") from e


# --------- Combined Encrypt and Sign / Verify and Decrypt Helpers ---------
def encrypt_and_sign(text: str, password: str, private_key_xml: str, encoding: str = 'base64') -> tuple[str, str]:
    """
    Encrypt text with password and sign the original text with private key.
    Returns (encrypted_text, signature).
    
    This provides both confidentiality (encryption) and authenticity (signing).
    The signature is computed on the original plaintext, not the ciphertext.
    
    Args:
        text: Plaintext to encrypt and sign
        password: Password for symmetric encryption
        private_key_xml: Private key for signing
        encoding: Output encoding for encrypted text ('base64' or 'hex')
    
    Returns:
        Tuple of (encrypted_text, signature_b64)
    """
    try:
        # First sign the original text (for authenticity)
        signature = sign_string(text, private_key_xml)
        
        # Then encrypt the text (for confidentiality)
        encrypted = encrypt(text, password, encoding)
        
        return encrypted, signature
    except (SigningError, EncryptionError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to encrypt and sign text: {e}") from e


def verify_and_decrypt(encrypted_text: str, signature: str, password: str, public_key_xml: str) -> str:
    """
    Decrypt text with password and verify signature with public key.
    Returns the decrypted plaintext if both operations succeed.
    
    This verifies both confidentiality (decryption) and authenticity (signature verification).
    
    Args:
        encrypted_text: Encrypted text (base64 or hex)
        signature: Digital signature (base64)
        password: Password for symmetric decryption
        public_key_xml: Public key for signature verification
    
    Returns:
        Decrypted plaintext if both decryption and verification succeed
        
    Raises:
        DecryptError: If decryption fails
        VerificationError: If signature verification fails
    """
    try:
        # First decrypt the text
        plaintext = decrypt(encrypted_text, password)
        
        # Then verify the signature against the decrypted text
        is_valid = verify_string(plaintext, signature, public_key_xml)
        
        if not is_valid:
            raise VerificationError("Signature verification failed - message may have been tampered with")
        
        return plaintext
    except (DecryptError, VerificationError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to verify and decrypt text: {e}") from e


def hybrid_encrypt_and_sign(text: str, public_key_xml: str, private_key_xml: str) -> tuple[str, str]:
    """
    Hybrid encrypt text with public key and sign with private key.
    Returns (encrypted_text, signature).
    
    Uses RSA+AES hybrid encryption for confidentiality and RSA signing for authenticity.
    Ideal when you have separate key pairs for encryption and signing.
    
    Args:
        text: Plaintext to encrypt and sign
        public_key_xml: Public key for hybrid encryption
        private_key_xml: Private key for signing (can be different keypair)
    
    Returns:
        Tuple of (hybrid_encrypted_text, signature_b64)
    """
    try:
        # First sign the original text
        signature = sign_string(text, private_key_xml)
        
        # Then hybrid encrypt the text
        encrypted = hybrid_encrypt(text, public_key_xml)
        
        return encrypted, signature
    except (SigningError, EncryptionError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to hybrid encrypt and sign text: {e}") from e


def verify_and_hybrid_decrypt(encrypted_text: str, signature: str, private_key_xml: str, public_key_xml: str) -> str:
    """
    Verify signature and hybrid decrypt text.
    Returns the decrypted plaintext if both operations succeed.
    
    Args:
        encrypted_text: Hybrid encrypted text (base64)
        signature: Digital signature (base64)
        private_key_xml: Private key for hybrid decryption
        public_key_xml: Public key for signature verification (can be different keypair)
    
    Returns:
        Decrypted plaintext if both decryption and verification succeed
        
    Raises:
        DecryptError: If hybrid decryption fails
        VerificationError: If signature verification fails
    """
    try:
        # First hybrid decrypt the text
        plaintext = hybrid_decrypt(encrypted_text, private_key_xml)
        
        # Then verify the signature against the decrypted text
        is_valid = verify_string(plaintext, signature, public_key_xml)
        
        if not is_valid:
            raise VerificationError("Signature verification failed - message may have been tampered with")
        
        return plaintext
    except (DecryptError, VerificationError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to verify and hybrid decrypt text: {e}") from e


def encrypt_and_sign_file(in_path: str | os.PathLike, out_path: str | os.PathLike, 
                         password: str, private_key_xml: str, sig_path: str | os.PathLike | None = None) -> str:
    """
    Encrypt a file and create a digital signature for the original file.
    Returns the signature file path.
    
    Args:
        in_path: Input file to encrypt and sign
        out_path: Output path for encrypted file
        password: Password for file encryption
        private_key_xml: Private key for file signing
        sig_path: Optional signature file path (default: <in_path>.sig)
    
    Returns:
        Path to the signature file
    """
    try:
        # First sign the original file (before encryption)
        sig_file = sign_file_to(in_path, private_key_xml, sig_path)
        
        # Then encrypt the file
        encrypt_file(in_path, out_path, password)
        
        return sig_file
    except (SigningError, FileOperationError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to encrypt and sign file '{in_path}': {e}") from e


def verify_and_decrypt_file(encrypted_path: str | os.PathLike, out_path: str | os.PathLike,
                           sig_path: str | os.PathLike, password: str, public_key_xml: str) -> None:
    """
    Decrypt a file and verify its signature against the original content.
    
    Args:
        encrypted_path: Path to encrypted file
        out_path: Output path for decrypted file
        sig_path: Path to signature file
        password: Password for file decryption
        public_key_xml: Public key for signature verification
        
    Raises:
        DecryptError: If file decryption fails
        VerificationError: If signature verification fails
        FileOperationError: If file operations fail
    """
    try:
        # First decrypt the file
        decrypt_file(encrypted_path, out_path, password)
        
        # Then verify the signature against the decrypted file
        is_valid = verify_file_from(out_path, sig_path, public_key_xml)
        
        if not is_valid:
            # Clean up the decrypted file if verification fails
            try:
                os.unlink(out_path)
            except:
                pass  # Ignore cleanup errors
            raise VerificationError(f"File signature verification failed - file '{encrypted_path}' may have been tampered with")
        
    except (DecryptError, VerificationError, FileOperationError):
        raise  # Re-raise specific errors as-is
    except Exception as e:
        raise SecureCryptoError(f"Failed to verify and decrypt file '{encrypted_path}': {e}") from e


# --------- CLI Interface ---------
def _setup_cli_parser():
    """Set up the argument parser for the CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog='securecrypto',
        description='SecureCrypto CLI - Encryption, signing, and hashing utilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt/decrypt text
  python -m securecrypto encrypt "Hello World" --password mypass
  python -m securecrypto decrypt <base64_cipher> --password mypass
  
  # File operations
  python -m securecrypto encrypt-file input.txt output.enc --password mypass
  python -m securecrypto decrypt-file output.enc decrypted.txt --password mypass
  
  # Generate keypair
  python -m securecrypto keygen --public pub.xml --private priv.xml
  
  # Hybrid encryption (RSA + AES)
  python -m securecrypto hybrid-encrypt "Secret message" --public-key pub.xml
  python -m securecrypto hybrid-decrypt <base64_cipher> --private-key priv.xml
  
  # Signing and verification
  python -m securecrypto sign "Document text" --private-key priv.xml
  python -m securecrypto verify "Document text" <signature> --public-key pub.xml
  python -m securecrypto sign-file document.pdf --private-key priv.xml
  python -m securecrypto verify-file document.pdf document.pdf.sig --public-key pub.xml
  
  # Combined operations
  python -m securecrypto encrypt-and-sign "Secret" --password mypass --private-key priv.xml
  python -m securecrypto verify-and-decrypt <encrypted> <sig> --password mypass --public-key pub.xml
  
  # Hashing
  python -m securecrypto hash "text to hash" --algorithm SHA256
  python -m securecrypto hash-file document.pdf --algorithm SHA512
  python -m securecrypto hmac "message" --key "secret" --algorithm HMACSHA256
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt text')
    encrypt_parser.add_argument('text', help='Text to encrypt')
    encrypt_parser.add_argument('--password', '-p', help='Password for encryption')
    encrypt_parser.add_argument('--encoding', '-e', choices=['base64', 'hex'], default='base64',
                               help='Output encoding (default: base64)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt text')
    decrypt_parser.add_argument('ciphertext', help='Encrypted text (base64)')
    decrypt_parser.add_argument('--password', '-p', help='Password for decryption')
    
    # Encrypt file command
    encrypt_file_parser = subparsers.add_parser('encrypt-file', help='Encrypt a file')
    encrypt_file_parser.add_argument('input', help='Input file path')
    encrypt_file_parser.add_argument('output', help='Output file path')
    encrypt_file_parser.add_argument('--password', '-p', help='Password for encryption')
    
    # Decrypt file command
    decrypt_file_parser = subparsers.add_parser('decrypt-file', help='Decrypt a file')
    decrypt_file_parser.add_argument('input', help='Input file path')
    decrypt_file_parser.add_argument('output', help='Output file path')
    decrypt_file_parser.add_argument('--password', '-p', help='Password for decryption')
    
    # Generate keypair command
    keygen_parser = subparsers.add_parser('keygen', help='Generate RSA keypair')
    keygen_parser.add_argument('--public', '-pub', help='Public key output file (default: stdout)')
    keygen_parser.add_argument('--private', '-priv', help='Private key output file (default: stdout)')
    
    # Hybrid encrypt command
    hybrid_enc_parser = subparsers.add_parser('hybrid-encrypt', help='Hybrid encrypt (RSA + AES)')
    hybrid_enc_parser.add_argument('text', help='Text to encrypt')
    hybrid_enc_parser.add_argument('--public-key', '-pub', required=True, help='Public key file or XML string')
    
    # Hybrid decrypt command
    hybrid_dec_parser = subparsers.add_parser('hybrid-decrypt', help='Hybrid decrypt (RSA + AES)')
    hybrid_dec_parser.add_argument('ciphertext', help='Encrypted text (base64)')
    hybrid_dec_parser.add_argument('--private-key', '-priv', required=True, help='Private key file or XML string')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign text')
    sign_parser.add_argument('text', help='Text to sign')
    sign_parser.add_argument('--private-key', '-priv', required=True, help='Private key file or XML string')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify text signature')
    verify_parser.add_argument('text', help='Original text')
    verify_parser.add_argument('signature', help='Signature (base64)')
    verify_parser.add_argument('--public-key', '-pub', required=True, help='Public key file or XML string')
    
    # Sign file command
    sign_file_parser = subparsers.add_parser('sign-file', help='Sign a file')
    sign_file_parser.add_argument('file', help='File to sign')
    sign_file_parser.add_argument('--private-key', '-priv', required=True, help='Private key file or XML string')
    sign_file_parser.add_argument('--output', '-o', help='Signature output file (default: <file>.sig)')
    
    # Verify file command
    verify_file_parser = subparsers.add_parser('verify-file', help='Verify file signature')
    verify_file_parser.add_argument('file', help='File to verify')
    verify_file_parser.add_argument('signature', help='Signature file')
    verify_file_parser.add_argument('--public-key', '-pub', required=True, help='Public key file or XML string')
    
    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Hash text')
    hash_parser.add_argument('text', help='Text to hash')
    hash_parser.add_argument('--algorithm', '-a', choices=['SHA256', 'SHA512'], default='SHA256',
                           help='Hash algorithm (default: SHA256)')
    
    # Hash file command
    hash_file_parser = subparsers.add_parser('hash-file', help='Hash a file')
    hash_file_parser.add_argument('file', help='File to hash')
    hash_file_parser.add_argument('--algorithm', '-a', choices=['SHA256', 'SHA512'], default='SHA256',
                                help='Hash algorithm (default: SHA256)')
    
    # HMAC command
    hmac_parser = subparsers.add_parser('hmac', help='Generate HMAC')
    hmac_parser.add_argument('message', help='Message to authenticate')
    hmac_parser.add_argument('--key', '-k', required=True, help='HMAC key')
    hmac_parser.add_argument('--algorithm', '-a', choices=['HMACSHA256', 'HMACSHA512'], 
                           default='HMACSHA256', help='HMAC algorithm (default: HMACSHA256)')
    
    # HMAC verify command
    hmac_verify_parser = subparsers.add_parser('hmac-verify', help='Verify HMAC')
    hmac_verify_parser.add_argument('message', help='Original message')
    hmac_verify_parser.add_argument('expected', help='Expected HMAC (hex)')
    hmac_verify_parser.add_argument('--key', '-k', required=True, help='HMAC key')
    hmac_verify_parser.add_argument('--algorithm', '-a', choices=['HMACSHA256', 'HMACSHA512'],
                                  default='HMACSHA256', help='HMAC algorithm (default: HMACSHA256)')
    
    # Encrypt and sign command
    enc_sign_parser = subparsers.add_parser('encrypt-and-sign', help='Encrypt text and create signature')
    enc_sign_parser.add_argument('text', help='Text to encrypt and sign')
    enc_sign_parser.add_argument('--password', '-p', help='Password for encryption')
    enc_sign_parser.add_argument('--private-key', '-priv', required=True, help='Private key for signing')
    enc_sign_parser.add_argument('--encoding', '-e', choices=['base64', 'hex'], default='base64',
                               help='Output encoding (default: base64)')
    
    # Verify and decrypt command
    ver_dec_parser = subparsers.add_parser('verify-and-decrypt', help='Verify signature and decrypt text')
    ver_dec_parser.add_argument('encrypted_text', help='Encrypted text')
    ver_dec_parser.add_argument('signature', help='Digital signature')
    ver_dec_parser.add_argument('--password', '-p', help='Password for decryption')
    ver_dec_parser.add_argument('--public-key', '-pub', required=True, help='Public key for verification')
    
    # Hybrid encrypt and sign command
    hyb_enc_sign_parser = subparsers.add_parser('hybrid-encrypt-and-sign', help='Hybrid encrypt and sign text')
    hyb_enc_sign_parser.add_argument('text', help='Text to encrypt and sign')
    hyb_enc_sign_parser.add_argument('--public-key', '-pub', required=True, help='Public key for encryption')
    hyb_enc_sign_parser.add_argument('--private-key', '-priv', required=True, help='Private key for signing')
    
    # Verify and hybrid decrypt command
    ver_hyb_dec_parser = subparsers.add_parser('verify-and-hybrid-decrypt', help='Verify signature and hybrid decrypt')
    ver_hyb_dec_parser.add_argument('encrypted_text', help='Hybrid encrypted text')
    ver_hyb_dec_parser.add_argument('signature', help='Digital signature')
    ver_hyb_dec_parser.add_argument('--private-key', '-priv', required=True, help='Private key for decryption')
    ver_hyb_dec_parser.add_argument('--public-key', '-pub', required=True, help='Public key for verification')
    
    # Encrypt and sign file command
    enc_sign_file_parser = subparsers.add_parser('encrypt-and-sign-file', help='Encrypt file and create signature')
    enc_sign_file_parser.add_argument('input', help='Input file to encrypt and sign')
    enc_sign_file_parser.add_argument('output', help='Output encrypted file')
    enc_sign_file_parser.add_argument('--password', '-p', help='Password for encryption')
    enc_sign_file_parser.add_argument('--private-key', '-priv', required=True, help='Private key for signing')
    enc_sign_file_parser.add_argument('--sig-output', '-s', help='Signature output file (default: <input>.sig)')
    
    # Verify and decrypt file command
    ver_dec_file_parser = subparsers.add_parser('verify-and-decrypt-file', help='Verify signature and decrypt file')
    ver_dec_file_parser.add_argument('encrypted_file', help='Encrypted file to decrypt')
    ver_dec_file_parser.add_argument('output', help='Output decrypted file')
    ver_dec_file_parser.add_argument('signature_file', help='Signature file for verification')
    ver_dec_file_parser.add_argument('--password', '-p', help='Password for decryption')
    ver_dec_file_parser.add_argument('--public-key', '-pub', required=True, help='Public key for verification')
    
    return parser


def _get_password(prompt: str = "Password: ") -> str:
    """Securely get password from user."""
    import getpass
    try:
        return getpass.getpass(prompt)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)


def _read_key_or_file(key_arg: str) -> str:
    """Read key from file if it's a path, otherwise return as-is."""
    if os.path.exists(key_arg):
        try:
            return import_key_from_file(key_arg)
        except KeyLoadError:
            raise  # Re-raise KeyLoadError as-is
        except Exception as e:
            raise KeyLoadError(f"Failed to read key from file '{key_arg}': {e}") from e
    return key_arg


def run_cli():
    """Main CLI entry point."""
    parser = _setup_cli_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Initialize the securecrypto module
        init()
        
        # Handle each command
        if args.command == 'encrypt':
            password = args.password or _get_password()
            result = encrypt(args.text, password, args.encoding)
            print(result)
            
        elif args.command == 'decrypt':
            password = args.password or _get_password()
            result = decrypt(args.ciphertext, password)
            print(result)
            
        elif args.command == 'encrypt-file':
            password = args.password or _get_password()
            encrypt_file(args.input, args.output, password)
            print(f"File encrypted: {args.input} -> {args.output}")
            
        elif args.command == 'decrypt-file':
            password = args.password or _get_password()
            decrypt_file(args.input, args.output, password)
            print(f"File decrypted: {args.input} -> {args.output}")
            
        elif args.command == 'keygen':
            public_key, private_key = generate_keypair()
            
            if args.public:
                export_key_to_file(public_key, args.public)
                print(f"Public key saved to: {args.public}")
            else:
                print("=== PUBLIC KEY ===")
                print(public_key)
                
            if args.private:
                export_key_to_file(private_key, args.private)
                print(f"Private key saved to: {args.private}")
            else:
                print("=== PRIVATE KEY ===")
                print(private_key)
                
        elif args.command == 'hybrid-encrypt':
            public_key = _read_key_or_file(args.public_key)
            result = hybrid_encrypt(args.text, public_key)
            print(result)
            
        elif args.command == 'hybrid-decrypt':
            private_key = _read_key_or_file(args.private_key)
            result = hybrid_decrypt(args.ciphertext, private_key)
            print(result)
            
        elif args.command == 'sign':
            private_key = _read_key_or_file(args.private_key)
            result = sign_string(args.text, private_key)
            print(result)
            
        elif args.command == 'verify':
            public_key = _read_key_or_file(args.public_key)
            result = verify_string(args.text, args.signature, public_key)
            print("Valid" if result else "Invalid")
            sys.exit(0 if result else 1)
            
        elif args.command == 'sign-file':
            private_key = _read_key_or_file(args.private_key)
            sig_path = sign_file_to(args.file, private_key, args.output)
            print(f"File signed: {sig_path}")
            
        elif args.command == 'verify-file':
            public_key = _read_key_or_file(args.public_key)
            result = verify_file_from(args.file, args.signature, public_key)
            print("Valid" if result else "Invalid")
            sys.exit(0 if result else 1)
            
        elif args.command == 'hash':
            result = hash_string(args.text, args.algorithm)
            print(result)
            
        elif args.command == 'hash-file':
            result = hash_file(args.file, args.algorithm)
            print(result)
            
        elif args.command == 'hmac':
            result = hmac(args.message, args.key, args.algorithm)
            print(result)
            
        elif args.command == 'hmac-verify':
            result = hmac_verify(args.message, args.expected, args.key, args.algorithm)
            print("Valid" if result else "Invalid")
            sys.exit(0 if result else 1)
            
        elif args.command == 'encrypt-and-sign':
            password = args.password or _get_password()
            private_key = _read_key_or_file(args.private_key)
            encrypted, signature = encrypt_and_sign(args.text, password, private_key, args.encoding)
            print("Encrypted:", encrypted)
            print("Signature:", signature)
            
        elif args.command == 'verify-and-decrypt':
            password = args.password or _get_password()
            public_key = _read_key_or_file(args.public_key)
            result = verify_and_decrypt(args.encrypted_text, args.signature, password, public_key)
            print(result)
            
        elif args.command == 'hybrid-encrypt-and-sign':
            public_key = _read_key_or_file(args.public_key)
            private_key = _read_key_or_file(args.private_key)
            encrypted, signature = hybrid_encrypt_and_sign(args.text, public_key, private_key)
            print("Encrypted:", encrypted)
            print("Signature:", signature)
            
        elif args.command == 'verify-and-hybrid-decrypt':
            private_key = _read_key_or_file(args.private_key)
            public_key = _read_key_or_file(args.public_key)
            result = verify_and_hybrid_decrypt(args.encrypted_text, args.signature, private_key, public_key)
            print(result)
            
        elif args.command == 'encrypt-and-sign-file':
            password = args.password or _get_password()
            private_key = _read_key_or_file(args.private_key)
            sig_path = encrypt_and_sign_file(args.input, args.output, password, private_key, args.sig_output)
            print(f"File encrypted: {args.input} -> {args.output}")
            print(f"Signature created: {sig_path}")
            
        elif args.command == 'verify-and-decrypt-file':
            password = args.password or _get_password()
            public_key = _read_key_or_file(args.public_key)
            verify_and_decrypt_file(args.encrypted_file, args.output, args.signature_file, password, public_key)
            print(f"File decrypted and verified: {args.encrypted_file} -> {args.output}")
            
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except (DllLoadError, KeyLoadError, DecryptError, VerificationError, 
            EncryptionError, SigningError, HashingError, HmacError, 
            FileOperationError, EncodingError, SecureCryptoError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


# --------- Self-test when run directly ---------
if __name__ == '__main__':
    # Check if CLI arguments are provided
    if len(sys.argv) > 1:
        run_cli()
    else:
        # Run self-test
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

        # Test combined encrypt and sign / verify and decrypt
        encrypted_text, signature = encrypt_and_sign("Secret message", "password123", priv)
        decrypted_text = verify_and_decrypt(encrypted_text, signature, "password123", pub)
        assert decrypted_text == "Secret message"
        print("Encrypt+Sign / Verify+Decrypt round-trip OK")

        # Test hybrid encrypt and sign / verify and decrypt
        hyb_encrypted, hyb_signature = hybrid_encrypt_and_sign("Top Secret Data", pub, priv)
        hyb_decrypted = verify_and_hybrid_decrypt(hyb_encrypted, hyb_signature, priv, pub)
        assert hyb_decrypted == "Top Secret Data"
        print("Hybrid Encrypt+Sign / Verify+Decrypt round-trip OK")

        # Test file encrypt and sign / verify and decrypt
        test_file = Path("test_combined.txt")
        test_file.write_text("Test file content for combined operations")
        encrypted_file = Path("test_combined.enc")
        
        sig_file_path = encrypt_and_sign_file(test_file, encrypted_file, "filepass", priv)
        assert Path(sig_file_path).exists()
        
        decrypted_file = Path("test_combined_decrypted.txt")
        verify_and_decrypt_file(encrypted_file, decrypted_file, sig_file_path, "filepass", pub)
        assert decrypted_file.read_text() == "Test file content for combined operations"
        print("File Encrypt+Sign / Verify+Decrypt round-trip OK")

        # Hash/HMAC
        assert hash_string("abc", ALGORITHMS[0]) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        hm = hmac("msg", "key", HMAC_ALGORITHMS[0])
        assert hmac_verify("msg", hm, "key", HMAC_ALGORITHMS_MAP["sha256"]) is True
        print("Hash/HMAC OK")

        # Clean up test files
        for cleanup_file in [tmp, test_file, encrypted_file, decrypted_file, Path(sig_file), Path(sig_file_path)]:
            try:
                cleanup_file.unlink()
            except:
                pass

        print("[securecrypto] Self-test PASSED [OK]")
        print("\nTo use CLI interface, run with arguments:")
        print("python securecrypto.py --help")