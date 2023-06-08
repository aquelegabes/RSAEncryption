using System.Security.Cryptography;

namespace RSAEncryption.Core.Encryption
{
    public partial class EncryptionKeyPair
    {
        /// <summary>
        /// Import a <see cref="EncryptionKeyPair"/> from an encrypted key.
        /// </summary>
        /// <param name="password">password used to encrypt the key.</param>
        /// <param name="path">path to encrypted key file.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException">Password is missing./File not found.</exception>
        /// <exception cref="ArgumentNullException">Path is null.</exception>
        public static EncryptionKeyPair ImportPKCS8(string password, string path)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException(
                    paramName: nameof(password),
                    message: "In order to export as an encrypted key a password is needed.");
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Path must not be null.");

            if (!File.Exists(path))
                throw new ArgumentException(
                    paramName: nameof(path),
                    message: "File not found.");

            using (var reader = new StreamReader(path))
            using (var memStream = new MemoryStream())
            {
                reader.BaseStream.CopyTo(memStream);
                var content = memStream.ToArray();
                return ImportKey(EKeyType.PKCS8, content, password);
            }

        }

        /// <summary>
        /// Import an <see cref="EncryptionKeyPair" /> as a blob string.
        /// </summary>
        /// <param name="blobKey">A valid blob key</param>
        /// <param name="keySize">The size of the key in bits.</param>
        /// <param name="includePrivate">includePrivate: true to include private parameters; otherwise, false.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">blobKey is null.</exception>
        /// <exception cref="InvalidCastException">Wasn't possible to import key.</exception>
        public static EncryptionKeyPair ImportBlobString(string blobKey, bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(blobKey))
                throw new ArgumentNullException(
                    message: "'blobKey' must not be null.",
                    paramName: nameof(blobKey)
                );

            return ImportKey(EKeyType.BlobString, Convert.FromBase64String(blobKey));
        }

        /// <summary>
        /// Import a <see cref="EncryptionKeyPair"/> from a PEM file.
        /// </summary>
        /// <param name="path">Where the pem file is located.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Directory not specified.</exception>
        /// <exception cref="ArgumentException">Directory not found.</exception>
        /// <exception cref="InvalidCastException">Wasn't possible to import key.</exception>
        public static EncryptionKeyPair ImportPEMFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Directory not specified.");

            if (!File.Exists(path))
                throw new ArgumentException(
                    paramName: nameof(path),
                    message: "File not found.");

            FileManipulation.OpenFile(path, out byte[] content);
            return ImportKey(EKeyType.PEM, content);
        }

        /// <summary>
        /// Generate public and private <see cref="RSA" /> keys.
        /// </summary>
        /// <returns></returns>
        /// <param name="keySize">The size of the key in bits. Default 2048.</param>
        /// <exception cref="ArgumentException">Key size outside of accepted sizes.</exception>
        /// <exception cref="CryptographicException">Keys ize outside of accepted sizes.</exception>
        public static EncryptionKeyPair New(int keySize = 2048)
        {
            if (keySize > 16384 && keySize < 384)
                throw new ArgumentException(
                    message: "Key size must be between 384 and 16384 bits.",
                    paramName: nameof(keySize));

            if (keySize % 8 != 0)
                throw new CryptographicException(
                    message: "Key size must in increments of 8 bits starting at 384.");

            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                try
                {
                    return new EncryptionKeyPair(keySize, rsa.PublicOnly)
                    {
                        RSAParameters = rsa.ExportParameters(true)
                    };
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        
        public static EncryptionKeyPair ImportKey(
            EKeyType keyType,
            byte[] keyContent,
            ReadOnlySpan<char> keyPassword = default)
        {
            using var rsa = new RSACryptoServiceProvider();

            try
            {
                switch(keyType)
                {
                    case EKeyType.BlobString:
                    {
                        rsa.ImportCspBlob(keyContent);
                        return new EncryptionKeyPair(rsa.KeySize, rsa.PublicOnly)
                        {
                            RSAParameters = rsa.ExportParameters(!keyPassword.IsEmpty)
                        };
                    }
                    case EKeyType.PEM:
                    {
                        return keyPassword.IsEmpty ?
                            rsa.ImportRSAKeyPEM(keyContent.AsEncodedString())
                            : rsa.ImportRSAKeyPEM(keyContent.AsEncodedString());
                    }
                    case EKeyType.PKCS8:
                    {
                        rsa.ImportEncryptedPkcs8PrivateKeyFromPEM(
                            keyPassword, keyContent, out int bytesRead);
                        return new EncryptionKeyPair(rsa.KeySize, rsa.PublicOnly)
                        {
                            RSAParameters = rsa.ExportParameters(true)
                        };
                    }
                    default:
                        throw new ArgumentException(
                            paramName: nameof(keyType),
                            message: "Key type must be valid."
                        );
                }
            }
            catch (Exception ex)
            {
                ex.Data["params"] = new { key = keyContent };
                throw new InvalidCastException(
                    message: "Could not import key.",
                    innerException: ex
                );
            }
            finally
            {
                rsa.PersistKeyInCsp = false;
            }
        }
    }
}