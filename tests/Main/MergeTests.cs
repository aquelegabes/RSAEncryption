using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace RSAEncryption.Tests.Main
{
    public class MergeTests
    {
        [Fact]
        public void Merge_ArgumentExc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders);

            string output = testFolders["encrypted"];
            var pubKey = Encryption.EncryptionPairKey.FromPEMFile($"{Setup.AbsolutePath}\\pub.key.pem");
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

            // invalid data path
            Assert.Throws<ArgumentException>(()
                => Program.MergeSignatureAndData(null, signatureFilePath, output, pubKey));

            // invalid signature path
            Assert.Throws<ArgumentException>(()
                => Program.MergeSignatureAndData(originalFilePath, null, output, pubKey));

            // invalid output path
            Assert.Throws<ArgumentException>(()
                => Program.MergeSignatureAndData(originalFilePath, signatureFilePath, null, pubKey));
        }

        [Fact]
        public void Merge_NullKey_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders);

            string output = testFolders["encrypted"];
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

            Assert.Throws<NullReferenceException>(()
                => Program.MergeSignatureAndData(originalFilePath, signatureFilePath, output, null));
        }

        [Fact]
        public void Merge_InvalidSignature_Exc()
        {
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders);

            string output = testFolders["encrypted"];
            var pubKey = Encryption.EncryptionPairKey.FromPEMFile($"{Setup.AbsolutePath}\\pub.key.pem");
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

            Assert.Throws<InvalidDataException>(()
                => Program.MergeSignatureAndData(originalFilePath, originalFilePath, output, pubKey));
        }

        [Fact]
        public void Main_Merge_Verbosity_OK()
        {
            const string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders);

            string output = testFolders["encrypted"];
            var pubKey = $"{Setup.AbsolutePath}\\pub.key.pem";
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.{hashalg}*")[0];

            var args = new string[]
            {
                "--merge", "--verbose", $"--hashalg={hashalg}",
                $"--output={output}",
                $"--publickey={pubKey}",
                $"--target={originalFilePath}",
                $"--signaturefile={signatureFilePath}",
            };

            Program.Main(args);

            string outputFilePath = Directory.GetFiles(output, "*merge*")[0];

            Assert.False(string.IsNullOrWhiteSpace(outputFilePath));
        }
    }
}
