using System;
using System.IO;
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
            var pubKey = Encryption.EncryptionKeyPair.ImportPEMFile($"{Setup.AbsolutePath}\\pub.key.pem");
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
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

            Assert.Throws<InvalidDataException>(()
                => Program.MergeSignatureAndData(originalFilePath, originalFilePath, output, Setup.PublicKey));
        }

        [Fact]
        public void Main_Merge_Verbosity_OK()
        {
            const string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetSignatureFile(testFolders);

            string output = testFolders["encrypted"];
            var publicKeyPath = $"{Setup.AbsolutePath}\\pub.key.pem";
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
            string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.{hashalg}*")[0];

            var args = new string[]
            {
                "--merge", "--verbose", $"--hashalg={hashalg}",
                $"--output={output}",
                $"--key={publicKeyPath}",
                $"--target={originalFilePath}",
                $"--signaturefile={signatureFilePath}",
            };

            Program.Main(args);

            string outputFilePath = Directory.GetFiles(output, "*merge*")[0];

            Assert.False(string.IsNullOrWhiteSpace(outputFilePath));
        }
    }
}
