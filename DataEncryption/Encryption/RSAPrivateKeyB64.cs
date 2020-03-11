using System;
using System.Security.Cryptography;

namespace RSAEncryption.Encryption
{
    /// <summary>
    /// RSA private parameters as Base64String.
    /// </summary>
    public class RSAPrivateKeyB64
    {
        public string D { get; set; }
        public string DP { get; set; }
        public string DQ { get; set; }
        public string InverseQ { get; set; }
        public string P { get; set; }
        public string Q { get; set; }
    }
}