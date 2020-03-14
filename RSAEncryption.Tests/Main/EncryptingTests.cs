using RSAEncryption.Encryption;
using System;
using System.IO;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class EncryptingTests
    {
        [Fact]
        public void Main_Encrypting_SingleFile_Verbosity_OK()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\text1.txt";
            string outputFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";

            string[] args =
            {
                "-e", "--verbose",
                $@"--publickey={UtilsTests.AbsolutePath}\pub.key.pem",
                $"--output={UtilsTests.EncryptedPath}",
                @$"--target={targetFilePath}",
            };

            UtilsTests.InitializeTests();
            Program.Main(args);
            Assert.True(File.Exists(outputFilePath));

            var targetFileInfo = new FileInfo(targetFilePath);
            var outputFileInfo = new FileInfo(outputFilePath);
            Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
        }

        [Fact]
        public void Main_Encrypting_Signing_SingleFile_Verbosity_OK()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\text1.txt";
            string outputFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";
            string signatureFilePath = $@"{UtilsTests.EncryptedPath}\text1.signature.txt";

            string[] args =
            {
                "-e", "-s", "--verbose",
                $@"--privatekey={UtilsTests.AbsolutePath}\priv.key.pem",
                $"--output={UtilsTests.EncryptedPath}",
                @$"--target={targetFilePath}",
            };

            UtilsTests.InitializeTests();
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
            // using OriginalPath as target path
            // using EncryptedPath as output path

            string[] args =
            {
                "-e", "--verbose",
                $@"--publickey={UtilsTests.AbsolutePath}\pub.key.pem",
                $"--output={UtilsTests.EncryptedPath}",
                @$"--target={UtilsTests.OriginalPath}",
            };

            UtilsTests.InitializeTests();
            Program.Main(args);

            var originalFiles = Directory.GetFiles(UtilsTests.OriginalPath);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(UtilsTests.EncryptedPath, "*encryp*");
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
            // using OriginalPath as target path
            // using EncryptedPath as output path

            string[] args =
            {
                "-e", "-s", "--verbose",
                $@"--privatekey={UtilsTests.AbsolutePath}\priv.key.pem",
                $"--output={UtilsTests.EncryptedPath}",
                @$"--target={UtilsTests.OriginalPath}",
            };

            UtilsTests.InitializeTests();
            Program.Main(args);

            var originalFiles = Directory.GetFiles(UtilsTests.OriginalPath);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(UtilsTests.EncryptedPath, "*encryp*");
            Array.Sort(generatedEncryptedFiles);
            var generatedSignatureFiles = Directory.GetFiles(UtilsTests.EncryptedPath, "*sign*");
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
            string targetFilePath = $@"{UtilsTests.OriginalPath}\nonexisting.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<InvalidOperationException>(()
                => Program.Encrypt(targetFilePath, true, key, false, UtilsTests.EncryptedPath));
        }

        [Fact]
        public void Encrypting_NonExistentTarget_Exc()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\nonexisting.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, UtilsTests.EncryptedPath));
        }

        [Fact]
        public void Encrypting_OutputInvalid_Exc()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\text1.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, @$"{UtilsTests.AbsolutePath}\invalidpath"));
        }

        [Fact]
        public void Encrypting_TargetNull_Exc()
        {
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt("", false, key, false, UtilsTests.EncryptedPath));
        }

        [Fact]
        public void Encrypting_NullKey_Exc()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\text1.txt";

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt(targetFilePath, false, null, false, UtilsTests.EncryptedPath));
        }
    }
}
