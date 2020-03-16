using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class VerifySignatureTests
    {
        [Fact]
        public void Main_VerifySignature_Verbosity_OK()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").First();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            string[] args =
            {
                "-v", $"--hashalg={hashalg}", "--verbose",
                $@"--publickey={Setup.AbsolutePath}\pub.key.pem",
                $"--target={originalFilePath}",
                $"--signaturefile={signatureFilePath}"
            };

            Program.Main(args);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem");
            FileManipulation.OpenFile(originalFilePath, out var originalFile);
            FileManipulation.OpenFile(signatureFilePath, out var signatureFile);

            Assert.True(key.VerifySignedData(originalFile, signatureFile, hashalg));
        }

        [Fact]
        public void Main_VerifySignature_NotValidSignature_OK()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"]).Last();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            string[] args =
            {
                "-v", $"--hashalg={hashalg}", "--verbose",
                $@"--publickey={Setup.AbsolutePath}\pub.key.pem",
                $"--target={originalFilePath}",
                $"--signaturefile={signatureFilePath}"
            };

            Program.Main(args);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem");
            FileManipulation.OpenFile(originalFilePath, out var originalFile);
            FileManipulation.OpenFile(signatureFilePath, out var signatureFile);

            Assert.True(!key.VerifySignedData(originalFile, signatureFile, hashalg));
        }

        [Fact]
        public void VerifySignature_NullDataPath_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            Assert.Throws<ArgumentNullException>(()
                => Program.VerifySignature("", signatureFilePath, key, false));
        }

        [Fact]
        public void VerifySignature_NullSignedPath_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            Assert.Throws<ArgumentNullException>(()
                => Program.VerifySignature(originalFilePath, "", key, false));
        }

        [Fact]
        public void VerifySignature_NullKey_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            Assert.Throws<NullReferenceException>(()
                => Program.VerifySignature(originalFilePath, signatureFilePath, null, false));
        }

        [Fact]
        public void VerifySignature_FilesInexistent_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders, hashalg);

            var key = EncryptionPairKey.FromPEMFile($@"{Setup.AbsolutePath}\pub.key.pem", false);

            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*").First().Replace(".encrypted", ""));
            string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            Assert.Throws<ArgumentException>(()
                => Program.VerifySignature("inexistent", signatureFilePath, key, false));
        }
    }
}
