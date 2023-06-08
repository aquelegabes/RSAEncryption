using System.Security.Cryptography;

namespace RSAEncryption.Core.Encryption
{
    /// <summary>
    /// Class responsible for encryption keys and it's methods.
    /// </summary>
    public partial class EncryptionKeyPair
    {
        public RSAParameters RSAParameters { get; internal set; }
        public int KeySize { get; }
        public bool PublicOnly { get; }

        /// <summary>
        /// Constructor responsible for setting the key size in bits.
        /// </summary>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="publicOnly">Is the key public only?</param>
        internal EncryptionKeyPair(int keySize, bool publicOnly)
        {
            KeySize = keySize;
            PublicOnly = publicOnly;
        }


        /// <summary>
        /// Encrypts a file using a <see cref="RSACryptoServiceProvider"/> public key.
        /// In combination with <see cref="RijndaelManaged"/> algorithm.
        /// </summary>
        /// <param name="file">Bytes from the file.</param>
        /// <returns></returns>
        [Obsolete()]
        public byte[] EncryptRijndael(byte[] file)
        {
            // Importing 
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(this.RSAParameters);

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

            rsa.PersistKeyInCsp = false;
            return outStream.ToArray();
        }

        /// <summary>
        /// Decrypts a file using a <see cref="RSACryptoServiceProvider"/> private key.
        /// In combination with <see cref="RijndaelManaged"/> algorithm.
        /// </summary>
        /// <param name="encryptedFile">Bytes from the file.</param>
        /// <returns></returns>
        [Obsolete()]
        public byte[] DecryptRijndael(byte[] encryptedFile)
        {
            if (this.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to decrypt data using a public key.");

            // Importing 
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(this.RSAParameters);

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

            rsa.PersistKeyInCsp = false;
            return outStream.ToArray();
        }

        /// <summary>
        /// Encrypts data with the <see cref="System.Security.Cryptography.RSA" /> algorithm.
        /// </summary>
        /// <returns></returns>
        /// <param name="data">The data to be encrypted.</param>
        /// <exception cref="ArgumentNullException">Data null.</exception>
        /// <exception cref="NullReferenceException">Null key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(
                    message: "Data to be encrypted must not be null.",
                    paramName: nameof(data)
                );

            if (this == null)
            {
                throw new NullReferenceException(
                    message: "Public key must not be null.");
            }

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    rsa.ImportParameters(this.RSAParameters);

                    return rsa.Encrypt(data, false);
                }
                catch { throw; }
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
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="NullReferenceException">Key is null.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        /// <exception cref="InvalidOperationException">Impossible decrypting using public key.</exception>
        public byte[] Decrypt(byte[] encryptedData)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(
                    message: "Data to decrypt must not be null.",
                    paramName: nameof(encryptedData)
                );

            if (this == null)
                throw new NullReferenceException(
                    message: "Private key must not be null.");

            if (this.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to decrypt data using a public key.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    rsa.ImportParameters(this.RSAParameters);

                    return rsa.Decrypt(encryptedData, false);
                }
                catch { throw; }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Computes the hash value of the specified collection of byte array using the specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="data">The data to be signed.</param>
        /// <param name="hashAlgorithmName">Any valid hash algorithm name. Example: SHA1</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="NullReferenceException">Key is null.</exception>
        /// <exception cref="InvalidOperationException">Impossible signing with a public key.</exception>
        /// <exception cref="InvalidCastException">Invalid hash algorithm name.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public byte[] SignData(byte[] data, string hashAlgorithmName)
        {
            if (data == null)
                throw new ArgumentNullException(
                    message: "Encrypted data must not be null.",
                    paramName: nameof(data)
                );

            if (this == null)
                throw new NullReferenceException(
                    message: "Private key must not be null.");

            if (this.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to sign data using a public key.");

            var hashAlg = CryptoConfig.MapNameToOID(hashAlgorithmName);
            if (hashAlg == null)
                throw new InvalidCastException(
                    message: "Invalid hash algorithm name.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    rsa.ImportParameters(this.RSAParameters);
                    return rsa.SignData(data, hashAlg);
                }
                catch { throw; }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the provided public key and comparing it to the hash value of the provided data.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature from the signed data.</param>
        /// <param name="hashAlgorithmName">Any valid hash algorithm name. Example: SHA1</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="NullReferenceException">Key is null.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        /// <exception cref="InvalidCastException">Invalid hash algorithm name.</exception>
        public bool VerifySignedData(byte[] data, byte[] signature, string hashAlgorithmName)
        {
            if (data == null
                || signature == null)
                throw new ArgumentNullException(
                    message: "Both signed data and encrypted data must not be null.",
                    paramName: $"Params: [ {nameof(data)}, {nameof(signature)} ]"
                );

            if (this == null)
                throw new NullReferenceException(
                    message: "Public key must not be null.");

            var hashAlg = CryptoConfig.MapNameToOID(hashAlgorithmName);

            if (hashAlg == null)
                throw new InvalidCastException(
                    message: "Invalid hash algorithm name.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    rsa.ImportParameters(this.RSAParameters);

                    return rsa.VerifyData(data, hashAlg, signature);
                }
                catch { throw; }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Export this <see cref="EncryptionKeyPair"/> into a PEM file.
        /// </summary>
        /// <param name="path">Only path name. DO NOT include filename.</param>
        /// <param name="filename">
        /// Filename to export, if not specified it sets to pub.key/priv.key adequately.
        /// DO NOT include extension.
        /// </param>
        /// <param name="includePrivate">On exporting to file include private key content, otherwise false</param>
        /// <exception cref="ArgumentNullException">Directory not specified.</exception>
        /// <exception cref="ArgumentException">Directory not found.</exception>
        /// <exception cref="InvalidOperationException">Error when exporting key.</exception>
        public void ExportAsPEMFile(string path, string filename = "key", bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Directory not specified.");

            if (!Directory.Exists(path))
                throw new ArgumentException(
                    paramName: nameof(path),
                    message: "Directory not found.");

            // trying to export private key from a public key
            if (PublicOnly && includePrivate)
                throw new InvalidOperationException(
                    message: "Impossible to export private content from a public key.");

            var fileContents = AsByteArray(EKeyType.PEM);

            filename = includePrivate ? "priv." + filename + ".pem" : "pub." + filename + ".pem";

            FileManipulation.SaveFile(
                fileContents, path, filename, attributes: FileAttributes.ReadOnly);
        }

        /// <summary>
        /// Convert an <see cref="EncryptionKeyPair" /> as a blob string.
        /// </summary>
        /// <param name="includePrivate">includePrivate: true to include the private key; default is false.</param>
        /// <returns></returns>
        public string ExportAsBlobString(bool includePrivate = false)
        {
            if (PublicOnly && includePrivate)
                throw new InvalidOperationException(
                    message: "Impossible to export private content from a public key.");

            return Convert.ToBase64String(
                AsByteArray(EKeyType.BlobString));
        }

        /// <summary>
        /// Export an <see cref="EncryptionKeyPair"/> as an encrypted key using a password./>
        /// </summary>
        /// <param name="password">password to encrypt key.</param>
        /// <param name="path">output path</param>
        /// <param name="filename">output file name</param>
        /// <exception cref="ArgumentNullException">Password or path are missing.</exception>
        /// <exception cref="ArgumentException">File not found.</exception>
        /// <exception cref="InvalidOperationException">Impossible to export as encrypted key when public only.</exception>
        /// <exception cref="CryptographicException">Password is incorrect.</exception>
        public void ExportAsPKCS8(string password, string path, string filename = "key")
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException(
                    paramName: nameof(password),
                    message: "In order to export as an encrypted key a password is needed.");
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Directory not specified.");

            if (this.PublicOnly)
                throw new InvalidOperationException(
                    message: "Must be a private key to export as an encrypted key.");

            filename = $"priv.{filename}.pem";
            var fileContents = AsByteArray(EKeyType.PKCS8, password);

            FileManipulation.SaveFile(fileContents, path, filename);
        }

        public byte[] AsByteArray(
            EKeyType keyType,
            ReadOnlySpan<char> password = default)
        {
            bool includePrivate = !password.IsEmpty;

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    rsa.ImportParameters(this.RSAParameters);
                    switch (keyType)
                    {
                        case EKeyType.PEM:
                        {
                            return includePrivate ?
                                rsa.ExportRSAPrivateKeyAsPEM().ToByteArray()
                                : rsa.ExportRSAPublicKeyAsPEM().ToByteArray();
                        }
                        case EKeyType.BlobString:
                        {
                            return rsa.ExportCspBlob(includePrivate);
                        }
                        case EKeyType.PKCS8:
                        {
                            if (password.IsEmpty)
                            {
                                throw new ArgumentNullException(
                                    paramName: nameof(password),
                                    message: "This type of import requires a password.");
                            }

                            var hashalg = new HashAlgorithmName("SHA1");
                            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, hashalg, 64);
                            string fileContent = rsa.ExportEncryptedPkcs8PrivateKeyAsPEM(password, pbe);
                            return fileContent.ToByteArray();
                        }
                        default:
                        {
                            throw new ArgumentNullException(
                                paramName: nameof(keyType),
                                message: "Must be a valid KeyType.");
                        }
                    }
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}