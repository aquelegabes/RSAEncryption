using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using RSAEncryption.Encryption;
using System;
using System.IO;
using System.Security.Cryptography;

namespace RSAEncryption.Extensions
{
    public static class RSACryptoServiceProviderExtensions
    {
        /// <summary>
        /// Import OpenSSH PEM private/public key string into MS <see cref="RSACryptoServiceProvider" />
        /// </summary>
        /// <param name="pem">Encoded byte string from PEM file</param>
        /// <returns></returns>
        public static EncryptionKeyPair ImportRSAKeyPEM(this RSACryptoServiceProvider csp, string pem)
        {
            RSAParameters rsaParams = default;

            try
            {
                var pr = new PemReader(new StringReader(pem));
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                rsaParams = DotNetUtilities
                    .ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            }
            catch (InvalidCastException)
            {// if not private then public
                var pr = new PemReader(new StringReader(pem));
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidCastException(
                        message: "You're trying to use a encrypted key without a password.",
                        errorCode: 11);
                }
            }

            csp.ImportParameters(rsaParams);

            return new EncryptionKeyPair(csp.KeySize, csp.PublicOnly)
            {
                RSAParameters = rsaParams
            };
        }

        /// <summary>
        /// Exports the current key in the PKCS#8 EncryptedPrivateKeyInfo format with a char-based password.
        /// </summary>
        /// <param name="csp"></param>
        /// <param name="password">The password to use when encrypting the key material.</param>
        /// <param name="pbeParameters">The password-based encryption (PBE) parameters to use when encrypting the key material.</param>
        /// <returns cref="String">A PEMBase64 string containing the PKCS#8 EncryptedPrivateKeyInfo representation of this key.</returns>
        /// <remarks>
        /// When pbeParameters indicates an algorithm that uses PBKDF2 (Password-
        /// Based Key Derivation Function 2), the password is converted to bytes via the
        /// UTF-8 encoding.
        /// </remarks>
        /// <exception cref="CryptographicException">The key could not be exported.</exception>
        public static string ExportEncryptedPkcs8PrivateKeyAsPEM(this RSACryptoServiceProvider csp, ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            var result = csp.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
            var base64 = Convert.ToBase64String(result).ToCharArray();
            using (var sw = new StringWriter())
            {
                sw.Write("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    sw.Write(base64, i, Math.Min(64, base64.Length - i));
                    sw.Write('\n');
                }
                sw.Write("-----END ENCRYPTED PRIVATE KEY-----");
                return sw.ToString();
            }
        }

        /// <summary>
        /// Imports the public/private keypair from a PKCS#8 EncryptedPrivateKeyInfo
        /// structure after decrypting with a char-based password, replacing the keys for
        /// this object.
        /// </summary>
        /// <param name="password">The password to use for decrypting the key material.</param>
        /// <param name="pemFile">The bytes of a PKCS#8 EncryptedPrivateKeyInfo structure in the from the <see cref="ExportEncryptedPkcs8PrivateKeyAsPEM"/> method.</param>
        /// <param name="bytesRead">When this method returns, contains a value that indicates the number of bytes read from <paramref name="pemFile"/> . This parameter is treated as uninitialized.</param>
        /// <exception cref="CryptographicException">The password is incorrect.</exception>
        /// <remarks>
        /// When the contents of source indicate an algorithm that uses PBKDF1 (Password-Based Key Derivation Function 1) or PBKDF2 (Password-Based Key Derivation Function 2), the password is converted to bytes via the UTF-8 encoding. This method only supports the binary(BER/CER/DER) encoding of EncryptedPrivateKeyInfo.If the value is Base64-encoded or in the PEM text format, the caller must Base64-decode the contents before calling this method.
        /// </remarks>
        public static void ImportEncryptedPkcs8PrivateKeyFromPEM(this RSACryptoServiceProvider csp,
            ReadOnlySpan<char> password, StreamReader pemFile, out int bytesRead)
        {
            try
            {
                string fileContent = string.Empty;
                char[] bufferHolder = new char[3];
                while (!pemFile.EndOfStream)
                {
                    string charHolder;
                    // loking for pem starter (MII)
                    while (string.IsNullOrWhiteSpace(fileContent))
                    {
                        pemFile.Read(bufferHolder, 0, 3);
                        charHolder = new string(bufferHolder);
                        if (!charHolder.Equals("MII", StringComparison.OrdinalIgnoreCase))
                        {
                            pemFile.ReadLine();
                        }
                        else
                        {
                            fileContent += charHolder;
                            fileContent += pemFile.ReadLine();
                            break;
                        }
                    }
                    // reading rest of file
                    pemFile.Read(bufferHolder, 0, 3);
                    charHolder = new string(bufferHolder);
                    // looking for the ending line
                    if (!charHolder.Equals("---", StringComparison.OrdinalIgnoreCase))
                    {
                        fileContent += charHolder;
                        fileContent += pemFile.ReadLine();
                    }
                    else break;
                }

                byte[] fromBase64 = Convert.FromBase64String(fileContent);

                csp.ImportEncryptedPkcs8PrivateKey(password, fromBase64, out bytesRead);
            }
            catch (Exception e)
            {
                throw new CryptographicException(
                    message: "Not a valid PKCS#8 key.");
            }
        }

        /// <summary>
        /// Export private (including public) key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportRSAPrivateKeyAsPEM(this RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", nameof(csp));
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    Encode.IntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    Encode.IntegerBigEndian(innerWriter, parameters.Modulus);
                    Encode.IntegerBigEndian(innerWriter, parameters.Exponent);
                    Encode.IntegerBigEndian(innerWriter, parameters.D);
                    Encode.IntegerBigEndian(innerWriter, parameters.P);
                    Encode.IntegerBigEndian(innerWriter, parameters.Q);
                    Encode.IntegerBigEndian(innerWriter, parameters.DP);
                    Encode.IntegerBigEndian(innerWriter, parameters.DQ);
                    Encode.IntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    Encode.Length(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }

        /// <summary>
        /// Export public key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/28407693
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportRSAPublicKeyAsPEM(this RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    Encode.Length(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    Encode.Length(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    Encode.Length(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            Encode.IntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            Encode.IntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            Encode.Length(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        Encode.Length(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    Encode.Length(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }
    }
}
