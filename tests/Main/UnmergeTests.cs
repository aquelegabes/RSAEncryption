using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;
using Xunit.Sdk;

namespace RSAEncryption.Tests.Main
{
    public class UnmergeTests
    {
        [Fact]
        public void Unmerge_ArgumentExc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], "*merge*")[0];

            // invalid target
            Assert.Throws<ArgumentException>(()
                => Program.UnmergeSignatureAndData(null, output, Setup.PrivateKey, hashalg));

            // invalid output
            Assert.Throws<ArgumentException>(()
                => Program.UnmergeSignatureAndData(mergedFilePath, null, Setup.PrivateKey, hashalg));
        }

        [Fact]
        public void Unmerge_NullKey_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], $"*merge*")[0];

            // using public key
            Assert.Throws<NullReferenceException>(()
                => Program.UnmergeSignatureAndData(mergedFilePath, output, null, hashalg));
        }

        [Fact]
        public void Unmerge_InvalidSignature_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            // not a merged file
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"])[0];

            Assert.Throws<InvalidDataException>(()
                => Program.UnmergeSignatureAndData(mergedFilePath, output, Setup.PrivateKey, hashalg));
        }

        [Fact]
        public void Main_Unmerge_Verbosity_OK()
        {
            const string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string keyPath = $"{Setup.AbsolutePath}\\pub.key.pem";
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], "*merge*")[0];
            string mergedFileName = Path.GetFileNameWithoutExtension(mergedFilePath).Replace(".merged","");

            var args = new string[]
            {
                "--unmerge", "--verbose",
                $"--output={output}",
                $"--hashalg={hashalg}",
                $"--target={mergedFilePath}",
                $"--key={keyPath}"
            };

            Program.Main(args);

            string outputDataFilePath = Directory.GetFiles(testFolders["encrypted"], $"unmerged.{mergedFileName}.txt")[0];
            string outputSignatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"unmerged.{mergedFileName}.{hashalg}*")[0];

            Assert.False(string.IsNullOrWhiteSpace(outputDataFilePath));
            Assert.False(string.IsNullOrWhiteSpace(outputSignatureFilePath));
        }
    }
}
