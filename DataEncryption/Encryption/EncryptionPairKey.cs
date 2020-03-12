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
        public RSAPublicKeyB64 Public { get; set; }
        public RSAPrivateKeyB64 Private { get; set; }
        public int KeySize { get; }

        /// <summary>
        /// Constructor responsible for setting the key size in bits.
        /// </summary>
        /// <param name="keySize">The key size in bits.</param>
        private EncryptionPairKey(int keySize) { KeySize = keySize; }

        /// <summary>
        /// Import a <see cref="EncryptionPairKey"/> from <see cref="RSAParameters"/> and it's key size in bits.
        /// </summary>
        /// <param name="rsaParams">The key parameters.</param>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="includePrivate">includePrivate: true to include private parameters; otherwise, false.</param>
        /// <returns></returns>
        /// /// <exception cref="MissingFieldException"></exception>
        public static EncryptionPairKey ImportFromRSAParameters(RSAParameters rsaParams, int keySize, bool includePrivate = false)
        {
            var keyPair = new EncryptionPairKey(keySize)
            {
                Public = new RSAPublicKeyB64
                {
                    Exponent = Convert.ToBase64String(rsaParams.Exponent ?? throw new MissingFieldException("Missing Exponent property.")),
                    Modulus = Convert.ToBase64String(rsaParams.Modulus ?? throw new MissingFieldException("Missing Modulus property."))
                },
            };

            if (!includePrivate)
                return keyPair;

            keyPair.Private = new RSAPrivateKeyB64
            {
                D = Convert.ToBase64String(rsaParams.D ?? throw new MissingFieldException("Missing D property.")),
                DP = Convert.ToBase64String(rsaParams.DP ?? throw new MissingFieldException("Missing DP property.")),
                DQ = Convert.ToBase64String(rsaParams.DQ ?? throw new MissingFieldException("Missing DQ property.")),
                InverseQ = Convert.ToBase64String(rsaParams.InverseQ ?? throw new MissingFieldException("Missing InverseQ property")),
                P = Convert.ToBase64String(rsaParams.P ?? throw new MissingFieldException("Missing P property.")),
                Q = Convert.ToBase64String(rsaParams.Q ?? throw new MissingFieldException("Missing Q property."))
            };

            return keyPair;
        }

        /// <summary>
        /// Export this <see cref="EncryptionPairKey"/> into a <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="kp">this <see cref="EncryptionPairKey"/>.</param>
        /// <param name="includePrivate">includePrivate: true to include private parameters; otherwise, false.</param>
        /// <returns></returns>
        /// <exception cref="MissingFieldException"></exception>
        public RSAParameters ExportToRSAParameters(bool includePrivate = false)
        {
            var rsaParam = new RSAParameters
            {
                Exponent = Convert.FromBase64String(this.Public?.Exponent ?? throw new MissingFieldException("Missing Exponent property.")),
                Modulus = Convert.FromBase64String(this.Public?.Modulus ?? throw new MissingFieldException("Missing Modulus property.")),
            };

            if (!includePrivate)
                return rsaParam;

            rsaParam.D = Convert.FromBase64String(this.Private?.D ?? throw new MissingFieldException("Missing D property."));
            rsaParam.DP = Convert.FromBase64String(this.Private?.DP ?? throw new MissingFieldException("Missing DP property."));
            rsaParam.DQ = Convert.FromBase64String(this.Private?.DQ ?? throw new MissingFieldException("Missing DQ property."));
            rsaParam.InverseQ = Convert.FromBase64String(this.Private?.InverseQ ?? throw new MissingFieldException("Missing InverseQ property"));
            rsaParam.P = Convert.FromBase64String(this.Private?.P ?? throw new MissingFieldException("Missing P property."));
            rsaParam.Q = Convert.FromBase64String(this.Private?.Q ?? throw new MissingFieldException("Missing Q property."));
            return rsaParam;
        }

        /// <summary>
        /// Export this <see cref="EncryptionPairKey"/> into a file.
        /// </summary>
        /// <param name="path">Only path name. DO NOT include filename.</param>
        /// <param name="includePrivate"></param>
        public void ExportToFile(string path, bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(
                    paramName: nameof(path),
                    message: "Directory not specified.");

            if (!Directory.Exists(path))
                throw new ArgumentException(
                    paramName: nameof(path),
                    message: "Directory not found.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                rsa.ImportParameters(this.ExportToRSAParameters(includePrivate));
                if (includePrivate)
                {
                    string fileContent = rsa.ExportPrivateKey();
                    FileManipulation.SaveFile(fileContent.ToByteArray(), path, "privkey.pem");
                }
                else
                {
                    string fileContent = rsa.ExportPublicKey();
                    FileManipulation.SaveFile(fileContent.ToByteArray(), path, "pubkey.pem");
                }
            }
        }

        /// <summary>
        /// Import a <see cref="EncryptionPairKey"/> from a file.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="includePrivate"></param>
        /// <returns></returns>
        public static EncryptionPairKey ImportFromFile(string path, bool includePrivate = false)
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
        /// Generate public and private <see cref="System.Security.Cryptography.RSA" /> keys.
        /// </summary>
        /// <returns></returns>
        /// <param name="keySize">The size of the key in bits. Default 2048.</param>
        public static EncryptionPairKey New(int keySize = 2048)
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                try
                {
                    var rsaParams = rsa.ExportParameters(true);
                    return ImportFromRSAParameters(rsaParams, keySize, true);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
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
        public static EncryptionPairKey ImportFromBlobString(string blobKey, int keySize, bool includePrivate = false)
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
                    return ImportFromRSAParameters(rsa.ExportParameters(includePrivate), keySize, includePrivate);
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
        /// Try to convert an <see cref="EncryptionPairKey" /> as a blob string.
        /// </summary>
        /// <param name="blobKey">Where to return the blob.</param>
        /// <param name="includePrivate">includePrivate: true to include the private key; default is false.</param>
        /// <returns></returns>
        public string ExportToBlobString(bool includePrivate = false)
        {
            if (this?.Public == null || this.KeySize == 0)
                throw new ArgumentNullException(
                    paramName: "this",
                    message: "This EncryptionPairKey must not be null.");

            using (var rsa = new RSACryptoServiceProvider(this.KeySize))
            {
                try
                {
                    RSAParameters rsaParams = ExportToRSAParameters(includePrivate);

                    rsa.ImportParameters(rsaParams);
                    var blob = rsa.ExportCspBlob(includePrivate);
                    return Convert.ToBase64String(blob);
                }
                catch { throw; }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}