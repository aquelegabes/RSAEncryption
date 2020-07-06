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

            string targetFilePath = Directory.GetFiles(testFolders["original"])[0];
            string outputFilePath = Path.Combine(
                path1: testFolders["encrypted"],
                path2: Path.GetFileNameWithoutExtension(targetFilePath) + ".encrypted.txt");

            string[] args =
            {
                "-e", "--verbose",
                $@"--key={Setup.AbsolutePath}\pub.key.pem",
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
        public void Main_Encrypting_MultipleFile_Verbosity_OK()
        {
            Setup.Initialize(out var testFolders);

            string[] args =
            {
                "-e", "--verbose",
                $@"--key={Setup.AbsolutePath}\pub.key.pem",
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
        public void Encrypting_NonExistentTarget_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = $@"{testFolders["original"]}\nonexisting.txt";

            Assert.Throws<ArgumentException>(()
                => Program.EncryptOption(targetFilePath, Setup.PublicKey, false, testFolders["encrypted"]));
        }

        [Fact]
        public void Encrypting_OutputInvalid_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"])[0];

            Assert.Throws<ArgumentException>(()
                => Program.EncryptOption(targetFilePath, Setup.PublicKey, false, @$"{Setup.AbsolutePath}\invalidpath"));
        }

        [Fact]
        public void Encrypting_TargetNull_Exc()
        {
            Setup.Initialize(out var testFolders);

            Assert.Throws<ArgumentNullException>(()
                => Program.EncryptOption("", Setup.PublicKey, false, testFolders["encrypted"]));
        }

        [Fact]
        public void Encrypting_NullKey_Exc()
        {
            Setup.Initialize(out var testFolders);

            string targetFilePath = Directory.GetFiles(testFolders["original"])[0];

            Assert.Throws<ArgumentNullException>(()
                => Program.EncryptOption(targetFilePath, null, false, testFolders["encrypted"]));
        }
    }
}
