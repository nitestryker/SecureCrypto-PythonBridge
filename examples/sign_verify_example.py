import securecrypto as sc
from pathlib import Path

sc.init()

# Generate RSA keypair
pub, priv = sc.generate_keypair()

# String signing
sig = sc.sign_string("hello world", priv)
print("Signature:", sig[:60] + "...")
print("Verify:", sc.verify_string("hello world", sig, pub))

# File signing
path = Path("demo.txt")
path.write_text("This is a demo file.")

sig_file = sc.sign_file_to(path, priv)
print("Signature file:", sig_file)
print("Verify file:", sc.verify_file_from(path, sig_file, pub))
