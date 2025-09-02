import securecrypto as sc

sc.init()

# Generate RSA keypair
pub, priv = sc.generate_keypair()

# Encrypt with Hybrid (RSA + AES)
msg = "Top Secret Hybrid Message"
ciphertext = sc.hybrid_encrypt(msg, pub)
print("Hybrid Encrypted:", ciphertext[:60] + '...')

# Decrypt with private key
decrypted = sc.hybrid_decrypt(ciphertext, priv)
print("Hybrid Decrypted:", decrypted)
