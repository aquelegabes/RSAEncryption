using System;
using System.IO;
using System.Security.Cryptography;
using RSAEncryption.Extensions;

namespace RSAEncryption.Encryption
{
    /// <summary>
    /// Model responsible for encryption keys.
    /// </summary>
    public class EncryptionPairKey
    {
        public RSAParameters RSAParameters { get; internal set; }
        public int KeySize { get; }
        public bool PublicOnly { get; }

        /// <summary>
        /// Constructor responsible for setting the key size in bits.
        /// </summary>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name=""
        internal EncryptionPairKey(int keySize, bool publicOnly)
        {
            KeySize = keySize;
            PublicOnly = publicOnly;
        }

        /// <summary>
        /// Generate public and private <see cref="RSA" /> keys.
        /// </summary>
        /// <returns></returns>
        /// <param name="keySize">The size of the key in bits. Default 2048.</param>
        public static EncryptionPairKey New(int keySize = 2048)
        {
            if (keySize < 0)
                throw new ArgumentException(
                    message: "Key size must not be negative.",
                    paramName: nameof(keySize));

            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                try
                {
                    return new EncryptionPairKey(keySize, rsa.PublicOnly)
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

        /// <summary>
        /// Export this <see cref="EncryptionPairKey"/> into a PEM file.
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
        public void ToPEMFile(string path, string filename = "key", bool includePrivate = false)
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

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                rsa.ImportParameters(this.RSAParameters);
                if (includePrivate)
                {
                    filename = "priv." + filename + ".pem";
                    string fileContent = rsa.ExportPrivateKey();
                    FileManipulation.SaveFile(fileContent.ToByteArray(), path, filename, attributes: FileAttributes.ReadOnly);
                }
                else
                {
                    filename = "pub." + filename + ".pem";
                    string fileContent = rsa.ExportPublicKey();
                    FileManipulation.SaveFile(fileContent.ToByteArray(), path, filename, attributes: FileAttributes.ReadOnly);
                }
            }
        }

        /// <summary>
        /// Import a <see cref="EncryptionPairKey"/> from a PEM file.
        /// </summary>
        /// <param name="path">Where the pem file is located.</param>
        /// <param name="includePrivate">Is it a prviate key, otherwise false.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Directory not specified.</exception>
        /// <exception cref="ArgumentException">Directory not found.</exception>
        /// <exception cref="InvalidCastException">Wasn't possible to import key.</exception>
        public static EncryptionPairKey FromPEMFile(string path, bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Directory not specified.");

            if (!File.Exists(path))
                throw new ArgumentException(
                    paramName: nameof(path),
                    message: "Directory not found.");

            using (var rsa = new RSACryptoServiceProvider())
            {
                FileManipulation.OpenFile(path, out byte[] content);
                return rsa.ImportKey(content.AsEncodedString(), includePrivate);
            }
        }

        /// <summary>
        /// Import an <see cref="EncryptionPairKey" /> as a blob string.
        /// </summary>
        /// <param name="blobKey">A valid blob key</param>
        /// <param name="keySize">The size of the key in bits.</param>
        /// <param name="includePrivate">includePrivate: true to include private parameters; otherwise, false.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">blobKey is null.</exception>
        /// <exception cref="InvalidCastException">Wasn't possible to import key.</exception>
        public static EncryptionPairKey FromBlobString(string blobKey, int keySize, bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(blobKey))
                throw new ArgumentNullException(
                    message: "'blobKey' must not be null.",
                    paramName: nameof(blobKey)
                );

            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                try
                {
                    var blob = Convert.FromBase64String(blobKey);
                    rsa.ImportCspBlob(blob);
                    return new EncryptionPairKey(keySize, !includePrivate)
                    {
                        RSAParameters = rsa.ExportParameters(includePrivate)
                    };
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new { key = blobKey };
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

        /// <summary>
        /// Convert an <see cref="EncryptionPairKey" /> as a blob string.
        /// </summary>
        /// <param name="includePrivate">includePrivate: true to include the private key; default is false.</param>
        /// <returns></returns>
        public string ToBlobString(bool includePrivate = false)
        {
            if (PublicOnly && includePrivate)
                throw new InvalidOperationException(
                    message: "Impossible to export private content from a public key.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                rsa.ImportParameters(this.RSAParameters);
                var blob = rsa.ExportCspBlob(includePrivate);
                return Convert.ToBase64String(blob);
            }
        }
    }
}