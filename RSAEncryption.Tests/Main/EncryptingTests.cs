using RSAEncryption.Encryption;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class EncryptingTests
    {
        [Fact]
        public void Main_Encrypting_SingleFile_Verbosity_OK()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"]).First();
            string outputFilePath = Path.Combine(
                path1: testFolders["encrypted"],
                path2: Path.GetFileNameWithoutExtension(targetFilePath) + ".encrypted.txt");

            string[] args =
            {
                "-e", "--verbose",
                $@"--publickey={Setup.AbsolutePath}\pub.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={targetFilePath}",
            };

            Program.Main(args);
            Assert.True(File.Exists(outputFilePath));

            var targetFileInfo = new FileInfo(targetFilePath);
            var outputFileInfo = new FileInfo(outputFilePath);
            Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
        }

        [Fact]
        public void Main_Encrypting_Signing_SingleFile_Verbosity_OK()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"]).First();
            string outputFilePath = Path.Combine(
                path1: testFolders["encrypted"],
                path2: Path.GetFileNameWithoutExtension(targetFilePath) + ".encrypted.txt");

            string signatureFilePath = Path.Combine(
                path1: testFolders["encrypted"],
                path2: Path.GetFileNameWithoutExtension(targetFilePath) + ".signature.txt");

            string[] args =
            {
                "-e", "-s", "--verbose",
                $@"--privatekey={Setup.AbsolutePath}\priv.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={targetFilePath}",
            };

            Program.Main(args);

            Assert.True(File.Exists(outputFilePath));
            Assert.True(File.Exists(signatureFilePath));

            var targetFileInfo = new FileInfo(targetFilePath);
            var outputFileInfo = new FileInfo(outputFilePath);
            var signatureFileInfo = new FileInfo(signatureFilePath);

            Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
            Assert.True(signatureFileInfo.Length == 256);
        }

        [Fact]
        public void Main_Encrypting_MultipleFile_Verbosity_OK()
        {
            Setup.Initialize(out var testFolders);

            string[] args =
            {
                "-e", "--verbose",
                $@"--publickey={Setup.AbsolutePath}\pub.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={testFolders["original"]}",
            };

            Program.Main(args);

            var originalFiles = Directory.GetFiles(testFolders["original"]);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(testFolders["encrypted"], "*encryp*");
            Array.Sort(generatedEncryptedFiles);

            Assert.True(originalFiles.Length == generatedEncryptedFiles.Length);
            for (int i = 0; i < originalFiles.Length; i++)
            {
                var targetFileInfo = new FileInfo(originalFiles[i]);
                var outputFileInfo = new FileInfo(generatedEncryptedFiles[i]);
                Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
            }
        }

        [Fact]
        public void Main_Encrypting_Signing_MultipleFile_Verbosity_OK()
        {
            Setup.Initialize(out var testFolders);

            string[] args =
            {
                "-e", "-s", "--verbose",
                $@"--privatekey={Setup.AbsolutePath}\priv.key.pem",
                $"--output={testFolders["encrypted"]}",
                $"--target={testFolders["original"]}",
            };

            Program.Main(args);

            var originalFiles = Directory.GetFiles(testFolders["original"]);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(testFolders["encrypted"], "*encryp*");
            Array.Sort(generatedEncryptedFiles);
            var generatedSignatureFiles = Directory.GetFiles(testFolders["encrypted"], "*sign*");
            Array.Sort(generatedSignatureFiles);

            Assert.True(originalFiles.Length == generatedEncryptedFiles.Length &&
                        originalFiles.Length == generatedSignatureFiles.Length);
            for (int i = 0; i < originalFiles.Length; i++)
            {
                var targetFileInfo = new FileInfo(originalFiles[i]);
                var outputFileInfo = new FileInfo(generatedEncryptedFiles[i]);
                var signatureFileInfo = new FileInfo(generatedSignatureFiles[i]);

                Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
                Assert.True(signatureFileInfo.Length == 256);
            }
        }

        [Fact]
        public void Encrypting_Signing_UsingPublicKey_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = $@"{testFolders["original"]}\nonexisting.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            Assert.Throws<InvalidOperationException>(()
                => Program.Encrypt(targetFilePath, true, key, false, testFolders["encrypted"]));
        }

        [Fact]
        public void Encrypting_NonExistentTarget_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = $@"{testFolders["original"]}\nonexisting.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, testFolders["encrypted"]));
        }

        [Fact]
        public void Encrypting_OutputInvalid_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"]).First();
            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, @$"{Setup.AbsolutePath}\invalidpath"));
        }

        [Fact]
        public void Encrypting_TargetNull_Exc()
        {
            Setup.Initialize(out var testFolders);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt("", false, key, false, testFolders["encrypted"]));
        }

        [Fact]
        public void Encrypting_NullKey_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"]).First();

            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt(targetFilePath, false, null, false, testFolders["encrypted"]));
        }
    }
}
