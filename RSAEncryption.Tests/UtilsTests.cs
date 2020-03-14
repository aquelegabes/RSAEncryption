using RSAEncryption.Encryption;
using System;
using System.IO;

namespace RSAEncryption.Tests
{
    public static class UtilsTests
    {
        public readonly static string AbsolutePath = Environment.CurrentDirectory;
        public readonly static string OriginalPath = Path.Combine(Environment.CurrentDirectory, "original");
        public readonly static string EncryptedPath = Path.Combine(Environment.CurrentDirectory, "encrypted");
        public readonly static string DecryptedPath = Path.Combine(Environment.CurrentDirectory, "decrypted");

        public static void InitializeTests()
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
                key.ToPEMFile(AbsolutePath, includePrivate: false);
                key.ToPEMFile(AbsolutePath, includePrivate: true);
            }
        }
    }
}
