using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class GenerateKeyTests
    {
        [Theory]
        [InlineData("key_2048", 2048)]
        [InlineData("key_4096", 4096)]
        public void Main_GenerateKey_CustomName_Verbosity_OK(string keyName, int keySize)
        {
            string privateKeyPath = Path.Combine(Setup.AbsolutePath, $"priv.{keyName}.pem");
            string publicKeyPath = Path.Combine(Setup.AbsolutePath, $"pub.{keyName}.pem");

            string[] args = new string[]
            {
                "--newkey",
                "--verbose",
                $"--keysize={keySize}",
                $"--keyfilename={keyName}",
                $"--output={Setup.AbsolutePath}"
            };

            Program.Main(args);

            Assert.True(File.Exists(privateKeyPath));
            Assert.True(File.Exists(publicKeyPath));
        }

        [Fact]
        public void GenerateKey_DefaultName_Verbosity_OK()
        {
            string privateKeyPath = Path.Combine(Setup.AbsolutePath, "priv.key.pem");
            string publicKeyPath = Path.Combine(Setup.AbsolutePath, "pub.key.pem");

            Program.GenerateKey(1024, false, Setup.AbsolutePath);

            Assert.True(File.Exists(privateKeyPath));
            Assert.True(File.Exists(publicKeyPath));
        }
    }
}
