using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using RSAEncryption.Encryption;
using System;
using System.IO;
using System.Security.Cryptography;

namespace RSAEncryption.Extensions
{
    public static class RSACryptoServiceProviderExtensions
    {
        // <summary>
        /// Import OpenSSH PEM private/public key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="csp"></param>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static EncryptionPairKey ImportKey(this RSACryptoServiceProvider csp, string pem, bool includePrivate = false)
        {
            PemReader pr = new PemReader(new StringReader(pem));

            RSAParameters rsaParams;
            if (includePrivate)
            {
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                rsaParams = DotNetUtilities
                    .ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            }
            else
            {
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
            }

            csp.ImportParameters(rsaParams);
            return EncryptionPairKey.ImportFromRSAParameters(rsaParams, csp.KeySize, includePrivate);
        }

        /// <summary>
        /// Export private (including public) key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportPrivateKey(this RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
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
        public static string ExportPublicKey(this RSACryptoServiceProvider csp)
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
