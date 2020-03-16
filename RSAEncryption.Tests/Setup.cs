using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace RSAEncryption.Tests
{
    public static class Setup
    {
        public readonly static string AbsolutePath = Environment.CurrentDirectory;
        public readonly static string OriginalPath = Path.Combine(Environment.CurrentDirectory, "original");
        public readonly static string EncryptedPath = Path.Combine(Environment.CurrentDirectory, "encrypted");
        public readonly static string DecryptedPath = Path.Combine(Environment.CurrentDirectory, "decrypted");

        public static void Initialize(out Dictionary<string, string> testFolders)
        {
            Guid[] guids = {
                Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()
            };
            string folderName = Guid.NewGuid().ToString();
            testFolders = new Dictionary<string, string>
            {
                { "original", Path.Combine(OriginalPath,folderName) },
                { "encrypted", Path.Combine(EncryptedPath,folderName) },
                { "decrypted", Path.Combine(DecryptedPath,folderName) },
            };

            string[] files = {
                Path.Combine(testFolders["original"], guids[0].ToString() + ".txt"),
                Path.Combine(testFolders["original"], guids[1].ToString() + ".txt"),
                Path.Combine(testFolders["original"], guids[2].ToString() + ".txt"),
            };

            string pubKey = @$"{AbsolutePath}\pub.key.pem";
            string privKey = @$"{AbsolutePath}\priv.key.pem";

            Directory.CreateDirectory(testFolders["original"]);
            Directory.CreateDirectory(testFolders["encrypted"]);
            Directory.CreateDirectory(testFolders["decrypted"]);

            for (int i = 0; i < files.Length; i++)
            {
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
                key.ToPEMFile(AbsolutePath, includePrivate: false);
                key.ToPEMFile(AbsolutePath, includePrivate: true);
            }
        }

        public static void SetEncryptedFiles(Dictionary<string, string> testFolders, bool multiple = false)
        {
            var key = EncryptionPairKey.FromPEMFile(@$"{AbsolutePath}\priv.key.pem", true);

            int files = Directory.GetFiles(testFolders["original"]).Length;

            int i = 0;
            do
            {
                string filePath = Directory.GetFiles(testFolders["original"])[i];

                FileManipulation.OpenFile(filePath, out var originalFile);

                string encryptedFileName = Path.GetFileNameWithoutExtension(filePath) + ".encrypted.txt";
                string encryptedPathFile = Path.Combine(testFolders["encrypted"], encryptedFileName);

                byte[] encryptedFile = key.EncryptRijndael(originalFile);
                File.WriteAllBytes(encryptedPathFile, encryptedFile);
                i++;
            } while (i < (multiple ? files : 1));
        }

        public static void SetSignatureFile(Dictionary<string, string> testFolders, string hashalg = "SHA256")
        {
            SetEncryptedFiles(testFolders);
            var key = EncryptionPairKey.FromPEMFile(@$"{AbsolutePath}\priv.key.pem", true);

            var filePath = Directory.GetFiles(testFolders["original"]).First();
            var fileName = Path.GetFileNameWithoutExtension(filePath).Replace(".encrypted", "");
            var fileExt = Path.GetExtension(filePath);
            FileManipulation.OpenFile(filePath, out var encryptedFile);

            string output = Path.Combine(testFolders["encrypted"], $"{fileName}.signature{fileExt}");
            var signatureData = key.SignData(encryptedFile, hashalg);
            File.WriteAllBytes(output, signatureData);
        }

        public static void SetMergedFile(Dictionary<string, string> testFolders, string hashalg)
        {
            SetSignatureFile(testFolders, hashalg);

            string output = testFolders["encrypted"];
            string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"]).First());
            string originalFilePath = Directory.GetFiles(testFolders["original"]).First();
            string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.sign*").First();

            FileManipulation.OpenFile(originalFilePath, out var data);
            FileManipulation.OpenFile(signatureFilePath, out var signature);

            byte[] mergedFile = new byte[signature.Length + data.Length];
            using (var ms = new MemoryStream(mergedFile))
            {
                ms.Write(signature, 0, signature.Length);
                ms.Write(data, 0, data.Length);
            }

            File.WriteAllBytes($"{output}\\{fileName}.merged", mergedFile);
        }
    }
}
