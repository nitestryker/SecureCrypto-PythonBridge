import securecrypto as sc

sc.init()

password = "mypassword"
plaintext = "Hello AES Encryption!"

# Encrypt (Base64)
ciphertext = sc.encrypt(plaintext, password)
print("Ciphertext:", ciphertext)

# Decrypt
decrypted = sc.decrypt(ciphertext, password)
print("Decrypted:", decrypted)
