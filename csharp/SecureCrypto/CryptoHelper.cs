using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace SecureCrypto
{
    public enum OutputEncoding
    {
        Base64,
        Hex,
        Raw
    }

    public static class CryptoHelper
    {
        /// <summary>
        ///   Utility Method to Encode Bytes
        /// </summary>
        /// <param name="data"></param>
        /// <param name="format"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static object EncodeBytes(byte[] data, OutputEncoding format)
        {
            switch (format)
            {
                case OutputEncoding.Base64:
                    return Convert.ToBase64String(data);
                case OutputEncoding.Hex:
                    return BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();
                case OutputEncoding.Raw:
                    return data; // Return byte[] directly
                default:
                    throw new ArgumentOutOfRangeException(nameof(format), format, null);
            }
        }

        /// <summary>
        /// Encrypt string with encoding option
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="password"></param>
        /// <param name="format"></param>
        /// <returns></returns>
        public static object EncryptWithEncoding(string plainText, string password, OutputEncoding format = OutputEncoding.Base64)
        {
            string base64 = Encrypt(plainText, password);
            byte[] raw = Convert.FromBase64String(base64);
            return EncodeBytes(raw, format);
        }


        // Encrypt plain text to Base64 string
        public static string Encrypt(string plainText, string password)
        {
            byte[] salt = GenerateRandomBytes(16);
            byte[] iv = GenerateRandomBytes(16);
            byte[] key = DeriveKey(password, salt);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    ms.Write(salt, 0, salt.Length);
                    ms.Write(iv, 0, iv.Length);

                    using (var encryptor = aes.CreateEncryptor())
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        // Decrypt Base64 string back to plain text
        public static string Decrypt(string encryptedBase64, string password)
        {
            byte[] encryptedData = Convert.FromBase64String(encryptedBase64);
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];

            Array.Copy(encryptedData, 0, salt, 0, 16);
            Array.Copy(encryptedData, 16, iv, 0, 16);

            byte[] key = DeriveKey(password, salt);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream(encryptedData, 32, encryptedData.Length - 32))
                using (var decryptor = aes.CreateDecryptor())
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        // Encrypt file to .enc file
        public static void EncryptFile(string inputFilePath, string outputFilePath, string password)
        {
            byte[] salt = GenerateRandomBytes(16);
            byte[] iv = GenerateRandomBytes(16);
            byte[] key = DeriveKey(password, salt);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var fsOut = new FileStream(outputFilePath, FileMode.Create))
                {
                    fsOut.Write(salt, 0, salt.Length);
                    fsOut.Write(iv, 0, iv.Length);

                    using (var encryptor = aes.CreateEncryptor())
                    using (var cs = new CryptoStream(fsOut, encryptor, CryptoStreamMode.Write))
                    using (var fsIn = new FileStream(inputFilePath, FileMode.Open))
                    {
                        fsIn.CopyTo(cs);
                    }
                }
            }
        }

        // Decrypt file from .enc back to original
        public static void DecryptFile(string inputFilePath, string outputFilePath, string password)
        {
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];

            using (var fsIn = new FileStream(inputFilePath, FileMode.Open))
            {
                fsIn.Read(salt, 0, 16);
                fsIn.Read(iv, 0, 16);
                byte[] key = DeriveKey(password, salt);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var cs = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read))
                    using (var fsOut = new FileStream(outputFilePath, FileMode.Create))
                    {
                        cs.CopyTo(fsOut);
                    }
                }
            }
        }
        /// <summary>
        ///  Sign a string with private key
        /// </summary>
        /// <param name="text"></param>
        /// <param name="privateKeyXml"></param>
        /// <returns></returns>
        public static string SignString(string text, string privateKeyXml)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                byte[] signature = rsa.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
                return Convert.ToBase64String(signature);
            }
        }
        /// <summary>
        ///  Verify string signature with public key
        /// </summary>
        /// <param name="text"></param>
        /// <param name="signatureBase64"></param>
        /// <param name="publicKeyXml"></param>
        /// <returns></returns>
        public static bool VerifyString(string text, string signatureBase64, string publicKeyXml)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXml);
                return rsa.VerifyData(data, CryptoConfig.MapNameToOID("SHA256"), signature);
            }
        }
        /// <summary>
        ///  Generate Key pair (Optional)
        /// </summary>
        /// <param name="publicKeyXml"></param>
        /// <param name="privateKeyXml"></param>
        public static void GenerateKeyPair(out string publicKeyXml, out string privateKeyXml)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                publicKeyXml = rsa.ToXmlString(false);  // public only
                privateKeyXml = rsa.ToXmlString(true);  // private + public
            }
        }
        /// <summary>
        ///  Sign a file 
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="privateKeyXml"></param>
        /// <returns></returns>
        public static string SignFile(string filePath, string privateKeyXml)
        {
            byte[] data = File.ReadAllBytes(filePath);
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                byte[] signature = rsa.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
                return Convert.ToBase64String(signature);
            }
        }

        /// <summary>
        /// Verify a Signed File
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="signatureBase64"></param>
        /// <param name="publicKeyXml"></param>
        /// <returns></returns>
        public static bool VerifyFile(string filePath, string signatureBase64, string publicKeyXml)
        {
            byte[] data = File.ReadAllBytes(filePath);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXml);
                return rsa.VerifyData(data, CryptoConfig.MapNameToOID("SHA256"), signature);
            }
        }
        // Encrypt raw bytes (for PDFs, images, etc.)
       
        /// <summary>
        /// Hybrid Encrypt
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="rsaPublicKeyXml"></param>
        /// <returns></returns>
        public static string HybridEncrypt(string plainText, string rsaPublicKeyXml)
        {
            // 1. Generate AES key + IV
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] encryptedData;
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                    sw.Flush();
                    cs.FlushFinalBlock();
                    encryptedData = ms.ToArray();
                }

                // 2. Encrypt AES key + IV with RSA public key
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(rsaPublicKeyXml);

                    byte[] aesBundle = new byte[aes.Key.Length + aes.IV.Length];
                    Buffer.BlockCopy(aes.Key, 0, aesBundle, 0, aes.Key.Length);
                    Buffer.BlockCopy(aes.IV, 0, aesBundle, aes.Key.Length, aes.IV.Length);

                    byte[] encryptedKeyIv = rsa.Encrypt(aesBundle, false);

                    // 3. Combine all pieces: [keyLen(4)][encKeyIv][encData]
                    using (var output = new MemoryStream())
                    {
                        byte[] keyLenBytes = BitConverter.GetBytes(encryptedKeyIv.Length);
                        output.Write(keyLenBytes, 0, 4);
                        output.Write(encryptedKeyIv, 0, encryptedKeyIv.Length);
                        output.Write(encryptedData, 0, encryptedData.Length);
                        return Convert.ToBase64String(output.ToArray());
                    }
                }
            }
        }

        /// <summary>
        ///  Hybrid Decrypt 
        /// </summary>
        /// <param name="encryptedBase64"></param>
        /// <param name="rsaPrivateKeyXml"></param>
        /// <returns></returns>
        public static string HybridDecrypt(string encryptedBase64, string rsaPrivateKeyXml)
        {
            byte[] fullData = Convert.FromBase64String(encryptedBase64);

            int encKeyLen = BitConverter.ToInt32(fullData, 0);
            byte[] encryptedKeyIv = new byte[encKeyLen];
            Buffer.BlockCopy(fullData, 4, encryptedKeyIv, 0, encKeyLen);

            byte[] encryptedData = new byte[fullData.Length - 4 - encKeyLen];
            Buffer.BlockCopy(fullData, 4 + encKeyLen, encryptedData, 0, encryptedData.Length);

            // Decrypt AES key + IV using RSA private key
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(rsaPrivateKeyXml);
                byte[] aesBundle = rsa.Decrypt(encryptedKeyIv, false);

                byte[] aesKey = new byte[32]; // 256-bit key
                byte[] aesIV = new byte[16];  // 128-bit block size

                Buffer.BlockCopy(aesBundle, 0, aesKey, 0, 32);
                Buffer.BlockCopy(aesBundle, 32, aesIV, 0, 16);

                using (var aes = Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = aesIV;

                    using (var ms = new MemoryStream(encryptedData))
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }


        /// <summary>
        /// Encrypt Bytes 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] EncryptBytes(byte[] data, string password)
        {
            byte[] salt = GenerateRandomBytes(16);
            byte[] iv = GenerateRandomBytes(16);
            byte[] key = DeriveKey(password, salt);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    ms.Write(salt, 0, salt.Length);
                    ms.Write(iv, 0, iv.Length);

                    using (var encryptor = aes.CreateEncryptor())
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        // Decrypt raw bytes
        public static byte[] DecryptBytes(byte[] encryptedData, string password)
        {
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];

            Array.Copy(encryptedData, 0, salt, 0, 16);
            Array.Copy(encryptedData, 16, iv, 0, 16);
            byte[] key = DeriveKey(password, salt);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var msIn = new MemoryStream(encryptedData, 32, encryptedData.Length - 32))
                using (var decryptor = aes.CreateDecryptor())
                using (var cs = new CryptoStream(msIn, decryptor, CryptoStreamMode.Read))
                using (var msOut = new MemoryStream())
                {
                    cs.CopyTo(msOut);
                    return msOut.ToArray();
                }
            }
        }

        /// <summary>
        ///  Export Key to file
        /// </summary>
        /// <param name="keyXml"></param>
        /// <param name="filePath"></param>
        public static void ExportKeyToFile(string keyXml, string filePath)
        {
            File.WriteAllText(filePath, keyXml);
        }

        /// <summary>
        /// import key from file
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static string ImportKeyFromFile(string filePath)
        {
            return File.ReadAllText(filePath);
        }

        /// <summary>
        ///  HashString (SHA256 or SHA512)
        /// </summary>
        /// <param name="input"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string HashString(string input, string algorithm = "SHA256")
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            using (var hasher = HashAlgorithm.Create(algorithm))
            {
                byte[] hash = hasher.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        /// HashFile (SHA256 or SHA512)
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string HashFile(string filePath, string algorithm = "SHA256")
        {
            using (var stream = File.OpenRead(filePath))
            using (var hasher = HashAlgorithm.Create(algorithm))
            {
                byte[] hash = hasher.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        /// GenerateHMAC(string message, string key, string algorithm = "HMACSHA256")
        /// </summary>
        /// <param name="message"></param>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string GenerateHMAC(string message, string key, string algorithm = "HMACSHA256")
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            using (var hmac = HMAC.Create(algorithm))
            {
                hmac.Key = keyBytes;
                byte[] hash = hmac.ComputeHash(messageBytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        ///  VerifyHMAC(string message, string expectedHexHmac, string key, string algorithm = "HMACSHA256")
        /// </summary>
        /// <param name="message"></param>
        /// <param name="expectedHexHmac"></param>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static bool VerifyHMAC(string message, string expectedHexHmac, string key, string algorithm = "HMACSHA256")
        {
            string computedHmac = GenerateHMAC(message, key, algorithm);
            return string.Equals(computedHmac, expectedHexHmac, StringComparison.OrdinalIgnoreCase);
        }

        // Helper: derive AES key from password + salt
        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000))
            {
                return pbkdf2.GetBytes(32); // 256-bit key
            }
        }

        // Helper: generate secure random bytes
        private static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }
    }
}
