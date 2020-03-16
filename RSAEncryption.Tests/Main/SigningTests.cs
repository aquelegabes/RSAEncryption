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
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*").First();
            string outputFile = targetFile.Replace(".encrypted", ".signature");

            string[] args =
            {
                "-s", "--verbose",
                $@"--privatekey={Setup.AbsolutePath}\priv.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={targetFile}",
            };

            Program.Main(args);

            Assert.True(File.Exists(outputFile));

            var outputFileInfo = new FileInfo(outputFile);
            Assert.True(outputFileInfo.Length == 256);
        }

        [Fact]
        public void Signing_NullKey_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*").First();

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

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*").First();
            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.Throws<InvalidOperationException>(() =>
                Program.Sign(targetFile, key, testFolders["encrypted"], false));
        }
    }
}
