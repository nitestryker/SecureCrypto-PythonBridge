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
#
# Works with pythonnet >= 3.x.

import os
import sys
from pathlib import Path
import importlib.resources as ir  # NEW: for loading DLL when installed as a package

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
        raise RuntimeError("pythonnet is required. Install with: pip install pythonnet") from e

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
        clr.AddReference(str(candidate))
    else:
        # Fallback to assembly name if DLL is discoverable by CLR (e.g., in CWD)
        try:
            clr.AddReference("SecureCrypto")
        except Exception as e:
            where = candidate if candidate is not None else Path("<not found>")
            raise FileNotFoundError(
                f"Could not locate SecureCrypto.dll (looked at {where}). "
                f"Ensure the DLL is packaged with this module or provide dll_path to init()."
            ) from e

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
            
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# --------- Tiny self-test when run directly ---------
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

        # Hash/HMAC
        assert hash_string("abc", ALGORITHMS[0]) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        hm = hmac("msg", "key", HMAC_ALGORITHMS[0])
        assert hmac_verify("msg", hm, "key", HMAC_ALGORITHMS_MAP["sha256"]) is True
        print("Hash/HMAC OK")

        print("[securecrypto] Self-test PASSED [OK]")
        print("\nTo use CLI interface, run with arguments:")
        print("python securecrypto.py --help")