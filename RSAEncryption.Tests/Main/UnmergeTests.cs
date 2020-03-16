﻿using System;
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
            var pubKey = Encryption.EncryptionPairKey.FromPEMFile($"{Setup.AbsolutePath}\\pub.key.pem");
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], $"*merge*").First();

            // invalid target
            Assert.Throws<ArgumentException>(()
                => Program.UnmergeSignatureAndData(null, output, pubKey, hashalg));

            // invalid output
            Assert.Throws<ArgumentException>(()
                => Program.UnmergeSignatureAndData(mergedFilePath, null, pubKey, hashalg));
        }

        [Fact]
        public void Unmerge_NullKey_Exc()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], $"*merge*").First();

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
            var privateKey = Encryption.EncryptionPairKey.FromPEMFile($"{Setup.AbsolutePath}\\priv.key.pem", true);
            // not a merged file
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"]).First();

            Assert.Throws<InvalidDataException>(()
                => Program.UnmergeSignatureAndData(mergedFilePath, output, privateKey, hashalg));
        }

        [Fact]
        public void Main_Unmerge_Verbosity_OK()
        {
            string hashalg = "SHA256";
            Setup.Initialize(out var testFolders);
            Setup.SetMergedFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string publicKey = $"{Setup.AbsolutePath}\\pub.key.pem";
            string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], $"*merge*").First();

            var args = new string[]
            {
                "--unmerge", "--verbose",
                $"--output={output}",
                $"--hashalg={hashalg}",
                $"--target={mergedFilePath}",
                $"--publickey={publicKey}"
            };

            Program.Main(args);

            string outputDataFilePath = Directory.GetFiles(testFolders["encrypted"], "*unmerged.data*").First();
            string outputSignatureFilePath = Directory.GetFiles(testFolders["encrypted"], "*unmerged.sign*").First();

            Assert.False(string.IsNullOrWhiteSpace(outputDataFilePath));
            Assert.False(string.IsNullOrWhiteSpace(outputSignatureFilePath));
        }
    }
}
