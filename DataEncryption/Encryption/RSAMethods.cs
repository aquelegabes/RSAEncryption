using RSAEncryption.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace RSAEncryption.Encryption
{
    /// <summary>
    /// Class responsible for generating, encrypting, signing, decrypting files and text messages.
    /// Using <see cref="RSA" /> and <see cref="RijndaelManaged"/> algorithm.
    /// </summary>
    public static class RSAMethods
    {
        /// <summary>
        /// Encrypts a file using a <see cref="RSACryptoServiceProvider"/> public key.
        /// In combination with <see cref="RijndaelManaged"/>.
        /// </summary>
        /// <param name="file">Bytes from the file.</param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] EncryptFile(byte[] file, EncryptionPairKey publicKey)
        {
            // Importing 
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey.RSAParameters);

            // Create instance of Rijndael for
            // symetric encryption of the data.
            using var rjndl = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            };
            using var transform = rjndl.CreateEncryptor();

            // Use RSACryptoServiceProvider to
            // enrypt the Rijndael key.
            byte[] keyEncrypted = rsa.Encrypt(rjndl.Key, false);

            // Create byte arrays to contain
            // the length values of the key and IV.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

            int lKey = keyEncrypted.Length;
            LenK = BitConverter.GetBytes(lKey);
            int lIV = rjndl.IV.Length;
            LenIV = BitConverter.GetBytes(lIV);

            using var outStream = new MemoryStream();
            outStream.Write(LenK, 0, 4);
            outStream.Write(LenIV, 0, 4);
            outStream.Write(keyEncrypted, 0, lKey);
            outStream.Write(rjndl.IV, 0, lIV);

            // Now write the cipher text using
            // a CryptoStream for encrypting.
            using var outStreamEncrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write);
            // By encrypting a chunk at
            // a time, you can save memory
            // and accommodate large files.
            int count = 0;
            int offset = 0;

            // blockSizeBytes can be any arbitrary size.
            int blockSizeBytes = rjndl.BlockSize / 8;
            byte[] data = new byte[blockSizeBytes];
            int bytesRead = 0;

            using var inStream = new MemoryStream(file);
            do
            {
                count = inStream.Read(data, 0, blockSizeBytes);
                offset += count;
                outStreamEncrypted.Write(data, 0, count);
                bytesRead += blockSizeBytes;
            }
            while (count > 0);
            inStream.Close();
            outStreamEncrypted.FlushFinalBlock();
            outStreamEncrypted.Close();
            outStream.Flush();
            return outStream.ToArray();
        }

        /// <summary>
        /// Decrypts a file using a <see cref="RSACryptoServiceProvider"/> private key.
        /// In combination with <see cref="RijndaelManaged"/>.
        /// </summary>
        /// <param name="file">Bytes from the file.</param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static byte[] DecryptFile(byte[] encryptedFile, EncryptionPairKey privateKey)
        {
            // Importing 
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(privateKey.RSAParameters);

            // Create instance of Rijndael for
            // symetric decryption of the data.
            using var rjndl = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            };

            // Create byte arrays to get the length of
            // the encrypted key and IV.
            // These values were stored as 4 bytes each
            // at the beginning of the encrypted package.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

            // Use MemoryStream objects to read the encrypted
            // file (inStream) and save the decrypted file (outStream).
            using var inStream = new MemoryStream(encryptedFile, false);
            inStream.Seek(0, SeekOrigin.Begin);
            inStream.Seek(0, SeekOrigin.Begin);
            inStream.Read(LenK, 0, 3);
            inStream.Seek(4, SeekOrigin.Begin);
            inStream.Read(LenIV, 0, 3);

            // Convert the lengths to integer values.
            int lenK = BitConverter.ToInt32(LenK, 0);
            int lenIV = BitConverter.ToInt32(LenIV, 0);

            // Determine the start postition of
            // the ciphter text (startC)
            // and its length(lenC).
            int startC = lenK + lenIV + 8;
            int lenC = (int)inStream.Length - startC;

            // Create the byte arrays for
            // the encrypted Rijndael key,
            // the IV, and the cipher text.
            byte[] KeyEncrypted = new byte[lenK];
            byte[] IV = new byte[lenIV];

            // Extract the key and IV
            // starting from index 8
            // after the length values.
            inStream.Seek(8, SeekOrigin.Begin);
            inStream.Read(KeyEncrypted, 0, lenK);
            inStream.Seek(8 + lenK, SeekOrigin.Begin);
            inStream.Read(IV, 0, lenIV);

            // Use RSACryptoServiceProvider
            // to decrypt the Rijndael key.
            byte[] KeyDecrypted = rsa.Decrypt(KeyEncrypted, false);

            // Decrypt the key.
            ICryptoTransform transform = rjndl.CreateDecryptor(KeyDecrypted, IV);

            // Decrypt the cipher text from
            // from the MemoryStream of the encrypted
            // file (inStream) into the MemoryStream
            // for the decrypted file (outStream).
            using var outStream = new MemoryStream();
            int count = 0;
            int offset = 0;

            // blockSizeBytes can be any arbitrary size.
            int blockSizeBytes = rjndl.BlockSize / 8;
            byte[] data = new byte[blockSizeBytes];

            // By decrypting a chunk a time,
            // you can save memory and
            // accommodate large files.

            // Start at the beginning
            // of the cipher text.
            inStream.Seek(startC, SeekOrigin.Begin);
            using var outStreamDecrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write);

            do
            {
                count = inStream.Read(data, 0, blockSizeBytes);
                offset += count;
                outStreamDecrypted.Write(data, 0, count);
            }
            while (count > 0);

            outStreamDecrypted.FlushFinalBlock();
            outStreamDecrypted.Close();
            inStream.Close();
            outStream.Flush();

            return outStream.ToArray();
        }

        /// <summary>
        /// Encrypts data with the <see cref="System.Security.Cryptography.RSA" /> algorithm.
        /// </summary>
        /// <returns></returns>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="publicKey">The public key to encrypt with.</param>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static byte[] Encrypt(byte[] data, EncryptionPairKey publicKey)
        {
            if (data == null)
                throw new ArgumentNullException(
                    message: "Data to be encrypted must not be null.",
                    paramName: nameof(data)
                );

            if (publicKey == null)
            {
                throw new ArgumentNullException(
                    message: "Public key must not be null.",
                    paramName: nameof(publicKey)
                );
            }

            using (var rsa = new RSACryptoServiceProvider(publicKey.KeySize))
            {
                try
                {
                    rsa.ImportParameters(publicKey.RSAParameters);

                    return rsa.Encrypt(data, false);
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { data, publicKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Computes the hash value of the specified collection of byte array using the specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="encryptedData">The data encrypted.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="hashAlgorithmName">Any of the hash Algorithm Name example: SHA1</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static byte[] SignData(byte[] encryptedData, EncryptionPairKey privateKey, string hashAlgorithmName)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(
                    message: "Encrypted data must not be null.",
                    paramName: nameof(encryptedData)
                );

            if (privateKey == null)
                throw new ArgumentNullException(
                    message: "Private key must not be null.",
                    paramName: nameof(privateKey)
                );

            using (var rsa = new RSACryptoServiceProvider(privateKey.KeySize))
            {
                try
                {
                    rsa.ImportParameters(privateKey.RSAParameters);
                    return rsa.SignData(encryptedData, CryptoConfig.MapNameToOID(hashAlgorithmName));
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { encryptedData, privateKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the provided public key and comparing it to the hash value of the provided data.
        /// </summary>
        /// <param name="dataToBeSigned">The data that was signed.</param>
        /// <param name="signedData">The signature data to be verified.</param>
        /// <param name="publicKey">The public key.</param>
        /// <param name="hashAlgorithmName">Any of the hash Algorithm Name example: SHA1</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static bool VerifySignedData(byte[] dataToBeSigned, byte[] signedData, EncryptionPairKey publicKey, string hashAlgorithmName)
        {
            if (dataToBeSigned == null
                || signedData == null)
                throw new ArgumentNullException(
                    message: "Both signed data and encrypted data must not be null.",
                    paramName: $"Params: [ {nameof(dataToBeSigned)}, {nameof(signedData)} ]"
                );

            if (publicKey == null)
                throw new ArgumentNullException(
                    message: "Public key must not be null.",
                    paramName: nameof(publicKey)
                );

            using (var rsa = new RSACryptoServiceProvider(publicKey.KeySize))
            {
                try
                {
                    rsa.ImportParameters(publicKey.RSAParameters);

                    if (!rsa.VerifyData(dataToBeSigned, CryptoConfig.MapNameToOID(hashAlgorithmName), signedData))
                        return false;

                    return true;
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { publicKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { dataToBeSigned, signedData, publicKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Decrypt data with the <see cref="System.Security.Cryptography.RSA" /> algorithm.
        /// </summary>
        /// <param name="encryptedData">Encrypted data.</param>
        /// <param name="privateKey">Private key.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static byte[] Decrypt(byte[] encryptedData, EncryptionPairKey privateKey)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(
                    message: "Data to decrypt must not be null.",
                    paramName: nameof(encryptedData)
                );

            if (privateKey == null)
                throw new ArgumentNullException(
                    message: "Private key must not be null.",
                    paramName: nameof(privateKey)
                );

            using (var rsa = new RSACryptoServiceProvider(privateKey.KeySize))
            {
                try
                {
                    rsa.ImportParameters(privateKey.RSAParameters);

                    return rsa.Decrypt(encryptedData, false);
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                // invalid private key
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { privateKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { encryptedData, privateKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}