using RSAEncryption.Encryption;
using System;
using System.IO;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class DecryptingTests
    {
        readonly EncryptingTests encryptingTest = new EncryptingTests();

        [Fact]
        public void Main_Decrypting_SingleFile_Verbosity_OK()
        {
            encryptingTest.Main_Encrypting_SingleFile_Verbosity_OK();

            string originalFilePath = $@"{UtilsTests.OriginalPath}\text1.txt";
            string targetFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";
            string outputFilePath = $@"{UtilsTests.DecryptedPath}\text1.decrypted.txt";

            string[] args =
            {
                "-d", "--verbose",
                $@"--privatekey={UtilsTests.AbsolutePath}\priv.key.pem",
                $"--output={UtilsTests.DecryptedPath}",
                @$"--target={targetFilePath}",
            };

            Program.Main(args);

            Assert.True(File.Exists(outputFilePath));

            FileManipulation.OpenFile(outputFilePath, out var outputFile);
            Assert.NotNull(outputFile);

            FileManipulation.OpenFile(originalFilePath, out var originalFile);
            Assert.NotNull(originalFile);

            Assert.Equal(outputFile.Length, originalFile.Length);
            Assert.Equal(outputFile, originalFile);
        }

        [Fact]
        public void Main_Decrypting_MultipleFile_Verbosity_OK()
        {
            encryptingTest.Main_Encrypting_MultipleFile_Verbosity_OK();

            string[] originalFilesPath = Directory.GetFiles(UtilsTests.OriginalPath);
            string[] targetFilesPath = Directory.GetFiles(UtilsTests.EncryptedPath, "*encrypt*");
            Array.Sort(targetFilesPath);

            string[] args =
            {
                "-d", "--verbose",
                $@"--privatekey={UtilsTests.AbsolutePath}\priv.key.pem",
                $"--output={UtilsTests.DecryptedPath}",
                @$"--target={UtilsTests.EncryptedPath}",
            };

            Program.Main(args);

            string[] outputFilesPath = Directory.GetFiles(UtilsTests.DecryptedPath);
            Array.Sort(outputFilesPath);

            Assert.Equal(outputFilesPath.Length, originalFilesPath.Length);

            for (int i = 0; i < targetFilesPath.Length; i++)
            {
                FileManipulation.OpenFile(outputFilesPath[i], out var outputFile);
                Assert.NotNull(outputFile);

                FileManipulation.OpenFile(originalFilesPath[i], out var originalFile);
                Assert.NotNull(originalFile);

                Assert.Equal(outputFile.Length, originalFile.Length);
                Assert.Equal(outputFile, originalFile);
            }
        }

        [Fact]
        public void Decrypting_NonExistentTarget_Exc()
        {
            string targetFilePath = $@"{UtilsTests.OriginalPath}\nonexisting.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\priv.key.pem", true);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Decrypt(targetFilePath, key, UtilsTests.EncryptedPath, false));
        }

        [Fact]
        public void Decrypting_OutputInvalid_Exc()
        {
            encryptingTest.Main_Encrypting_SingleFile_Verbosity_OK();

            string targetFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\priv.key.pem", true);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Decrypt(targetFilePath, key, @$"{UtilsTests.AbsolutePath}\invalidpath",false));
        }

        [Fact]
        public void Decrypting_TargetNull_Exc()
        {
            encryptingTest.Main_Encrypting_SingleFile_Verbosity_OK();

            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\priv.key.pem", true);

            Assert.NotNull(key);

            UtilsTests.InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Decrypt("", key, UtilsTests.EncryptedPath, false));
        }

        [Fact]
        public void Decrypting_NullKey_Exc()
        {
            string targetFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";

            Assert.Throws<ArgumentNullException>(() 
                => Program.Decrypt(targetFilePath, null, UtilsTests.DecryptedPath, false));
        }

        [Fact]
        public void Decrypting_UsingPublicKey_Exc()
        {
            string targetFilePath = $@"{UtilsTests.EncryptedPath}\text1.encrypted.txt";
            var key = EncryptionPairKey.FromPEMFile($@"{UtilsTests.AbsolutePath}\pub.key.pem", false);

            Assert.NotNull(key);

            Assert.Throws<InvalidOperationException>(()
                => Program.Decrypt(targetFilePath, key, UtilsTests.DecryptedPath, false));
        }
    }
}
