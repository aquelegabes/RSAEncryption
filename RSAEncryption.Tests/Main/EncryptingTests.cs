using RSAEncryption.Encryption;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class EncryptingTests
    {
        readonly string AbsolutePath = Environment.CurrentDirectory;
        readonly string OriginalPath = Path.Combine(Environment.CurrentDirectory, "original");
        readonly string EncryptedPath = Path.Combine(Environment.CurrentDirectory, "encrypted");
        readonly string DecryptedPath = Path.Combine(Environment.CurrentDirectory, "decrypted");

        void InitializeTests()
        {
            Directory.CreateDirectory(OriginalPath);
            Directory.CreateDirectory(EncryptedPath);
            Directory.CreateDirectory(DecryptedPath);

            string file1 = @$"{OriginalPath}\text1.txt";
            string file2 = @$"{OriginalPath}\text2.txt";
            string file3 = @$"{OriginalPath}\text3.txt";
            string pubKey = @$"{AbsolutePath}\pub.key.pem";
            string privKey = @$"{AbsolutePath}\priv.key.pem";
            string[] files = { file1, file2, file3 };

            for (int i = 0; i < files.Length; i++)
            {
                // only try deleting unnecessary exception treatment
                try
                {
                    FileManipulation.DeleteFile(files[i]);
                }
                catch { };

                using (var sw = File.CreateText(files[i]))
                {
                    sw.WriteLine(Guid.NewGuid());
                    sw.WriteLine(Guid.NewGuid());
                    sw.WriteLine(Guid.NewGuid());
                }
            }

            if (!File.Exists(pubKey) && !File.Exists(privKey))
            {
                var key = EncryptionPairKey.New();
                key.ExportToFile(AbsolutePath, includePrivate: false);
                key.ExportToFile(AbsolutePath, includePrivate: true);
            }
        }

        [Fact]
        public void Main_Encrypting_SingleFile_Verbosity_OK()
        {
            string targetFilePath = $@"{OriginalPath}\text1.txt";
            string outputFilePath = $@"{EncryptedPath}\text1.encrypted.txt";

            string[] args =
            {
                "-e", "--verbose",
                $@"--publickey={AbsolutePath}\pub.key.pem",
                $"--output={EncryptedPath}",
                @$"--target={targetFilePath}",
            };

            InitializeTests();
            Program.Main(args);
            Assert.True(File.Exists(outputFilePath));

            var targetFileInfo = new FileInfo(targetFilePath);
            var outputFileInfo = new FileInfo(outputFilePath);
            Assert.True(outputFileInfo.Length >= targetFileInfo.Length);
        }

        [Fact]
        public void Main_Encrypting_Signing_SingleFile_Verbosity_OK()
        {
            string targetFilePath = $@"{OriginalPath}\text1.txt";
            string outputFilePath = $@"{EncryptedPath}\text1.encrypted.txt";
            string signatureFilePath = $@"{EncryptedPath}\text1.signature.txt";

            string[] args =
            {
                "-e", "-s", "--verbose",
                $@"--privatekey={AbsolutePath}\priv.key.pem",
                $"--output={EncryptedPath}",
                @$"--target={targetFilePath}",
            };

            InitializeTests();
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
                $@"--publickey={AbsolutePath}\pub.key.pem",
                $"--output={EncryptedPath}",
                @$"--target={OriginalPath}",
            };

            InitializeTests();
            Program.Main(args);

            var originalFiles = Directory.GetFiles(OriginalPath);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(EncryptedPath, "*encryp*");
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
                $@"--privatekey={AbsolutePath}\priv.key.pem",
                $"--output={EncryptedPath}",
                @$"--target={OriginalPath}",
            };

            InitializeTests();
            Program.Main(args);

            var originalFiles = Directory.GetFiles(OriginalPath);
            Array.Sort(originalFiles);
            var generatedEncryptedFiles = Directory.GetFiles(EncryptedPath, "*encryp*");
            Array.Sort(generatedEncryptedFiles);
            var generatedSignatureFiles = Directory.GetFiles(EncryptedPath, "*sign*");
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
            string targetFilePath = $@"{OriginalPath}\nonexisting.txt";
            var key = EncryptionPairKey.ImportFromFile($@"{AbsolutePath}\pub.key.pem", false);

            InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt(targetFilePath, true, key, false, EncryptedPath));
        }

        [Fact]
        public void Encrypting_NonExistentTarget_Exc()
        {
            string targetFilePath = $@"{OriginalPath}\nonexisting.txt";
            var key = EncryptionPairKey.ImportFromFile($@"{AbsolutePath}\pub.key.pem", false);

            InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, EncryptedPath));
        }

        [Fact]
        public void Encrypting_OutputInvalid_Exc()
        {
            string targetFilePath = $@"{OriginalPath}\text1.txt";
            var key = EncryptionPairKey.ImportFromFile($@"{AbsolutePath}\pub.key.pem", false);

            InitializeTests();
            Assert.Throws<ArgumentException>(()
                => Program.Encrypt(targetFilePath, false, key, false, @$"{AbsolutePath}\invalidpath"));
        }

        [Fact]
        public void Encrypting_TargetNull_Exc()
        {
            var key = EncryptionPairKey.ImportFromFile($@"{AbsolutePath}\pub.key.pem", false);

            InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt("", false, key, false, EncryptedPath));
        }

        [Fact]
        public void Encrypting_NullKey_Exc()
        {
            string targetFilePath = $@"{OriginalPath}\text1.txt";

            InitializeTests();
            Assert.Throws<ArgumentNullException>(()
                => Program.Encrypt(targetFilePath, false, null, false, EncryptedPath));
        }
    }
}
