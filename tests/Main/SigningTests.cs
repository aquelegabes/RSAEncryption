using System;
using System.IO;
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

            var signatureLength = Setup.PrivateKey.SignData(new byte[] { 114 }, hashalg).Length;

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
                $@"--key={Setup.AbsolutePath}\priv.key.pem",
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

            Assert.Throws<ArgumentException>(() =>
                Program.Sign("", Setup.PrivateKey, testFolders["encrypted"], false));
        }

        [Fact]
        public void Signing_UsingPublicKey_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetEncryptedFiles(testFolders);

            string targetFile = Directory.GetFiles(testFolders["encrypted"], "*encryp*")[0];

            Assert.Throws<InvalidOperationException>(() =>
                Program.Sign(targetFile, Setup.PublicKey, testFolders["encrypted"], false));
        }
    }
}
