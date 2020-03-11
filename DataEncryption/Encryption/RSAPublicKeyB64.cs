using System;
using System.Security.Cryptography;

namespace RSAEncryption.Encryption
{
    /// <summary>
    /// RSA public parameters as Base64String.
    /// </summary>
    public class RSAPublicKeyB64
    {
        public string Exponent { get; set; }
        public string Modulus { get; set; }
    }
}