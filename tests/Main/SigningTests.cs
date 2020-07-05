using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class SigningTests
    {
        [Fact]
        public void Main_Signing_Verbosity_OK()
        {
            const string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            var key = EncryptionPairKey.FromPEMFile($"{Setup.AbsolutePath}\\priv.key.pem", true);
            var signatureLength = key.SignData(new byte[] { 114 }, hashalg).Length;

            string targetFile = Directory.GetFiles(testFolders["original"])[0];
            // default hashing algorithm is SHA256.
            string outputFile =
                Path.Combine(
                    testFolders["encrypted"],
                    Path.GetFileNameWithoutExtension(targetFile) + $".{hashalg}.txt"
                );

            string[] args =
            {
                "-s", "--verbose", $"--hashalg={hashalg}",
                $@"--privatekey={Setup.AbsolutePath}\priv.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={targetFile}",
            };

            Program.Main(args);

            Assert.True(File.Exists(outputFile));

            var outputFileInfo = new FileInfo(outputFile);
            Assert.True(outputFileInfo.Length == signatureLength);
        }

        [Fact]
        public void Signing_NullKey_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*")[0];

            Assert.Throws<ArgumentNullException>(() =>
                Program.Sign(targetFile, null, testFolders["encrypted"], false));
        }

        [Fact]
        public void Signing_InvalidTarget_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\priv.key.pem", true);

            Assert.Throws<ArgumentException>(() =>
                Program.Sign("", key, testFolders["encrypted"], false));
        }

        [Fact]
        public void Signing_UsingPublicKey_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*")[0];
            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.Throws<InvalidOperationException>(() =>
                Program.Sign(targetFile, key, testFolders["encrypted"], false));
        }
    }
}
