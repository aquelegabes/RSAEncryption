using Mono.Options;
using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace RSAEncryption
{
    public static class Program
    {
        static readonly Stopwatch Stopwatch = new Stopwatch();
        static readonly string exeName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
        static string hashalg = "SHA256";
        static void Decrypt(string target, EncryptionPairKey key, string output, bool verbose)
        {
            string fileName = Path.GetFileNameWithoutExtension(target);
            fileName = fileName.Replace(".encrypted", "");
            string fileExt = Path.GetExtension(target);

            if (verbose)
            {
                Console.WriteLine("[*] Storing file in memory...");
            }

            FileManipulation.OpenFile(target, out var file);
            if (verbose)
            {
                Console.WriteLine("[*] File in memory...");
                Console.WriteLine("[*] Starting decryption...");
                Stopwatch.Restart();
            }

            var decrypted = key.DecryptRijndael(file);

            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for decryption {Stopwatch.ElapsedMilliseconds} ms");
                Console.WriteLine("[*] Saving file...");
            }

            FileManipulation.SaveFile(decrypted, output, $"{fileName}.decrypted{fileExt}", true);
            Console.WriteLine($"[*] File saved as \"{fileName}.decrypted{fileExt}\" at {output}");
        }
        static void Encrypt(string target, EncryptionPairKey keyToEncrypt, bool verbose, string output)
        {
            string fileName = Path.GetFileNameWithoutExtension(target);
            string fileExt = Path.GetExtension(target);

            if (verbose)
                Console.WriteLine("[*] Storing file in memory...");
            FileManipulation.OpenFile(target, out var file);
            if (verbose)
            {
                Console.WriteLine("[*] File in memory...");
                Console.WriteLine("[*] Starting encryption...");
                Stopwatch.Restart();
            }

            var encrypted = keyToEncrypt.EncryptRijndael(file);
            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for encryption {Stopwatch.ElapsedMilliseconds} ms");
            }

            if (verbose)
                Console.WriteLine("[*] Saving file...");

            FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
            Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");

        }

        public static void Main(string[] args)
        {
            bool verbose = false;
            bool help = false;
            bool examples = false;
            bool encrypt = false;
            bool decrypt = false;
            bool sign = false;
            bool verifySignature = false;
            bool version = false;
            bool action = false;
            bool unmerge = false;
            bool merge = false;
            bool newKey = false;
            bool passwordProtected = false;
            int keySize = 2048;
            string passwd = string.Empty;

            var argsValue = new Dictionary<string, string>();

            var opts = new OptionSet
            {
                // action
                { "d|decrypt", "decrypts the encrypted data, requires private key \n[ACTION]",
                    v => { decrypt = v != null; action = true; } },
                // action
                { "e|encrypt", "encrypts the data, if used with -s merge signature to encrypted file \n[ACTION]",
                    v => { encrypt = v != null; action = true; } },
                // action
                { "h|help", "show this message and exit \n[ACTION]",
                    v => { help = v != null; action = true; } },
                { "k|key=", "key to use",
                    v => argsValue.Add("key", v) },
                { "m|merge", "merge signature with another file, use --signaturefile, requires public key used in signature\n[ACTION]",
                    v => { merge = true; action = true; } },
                // action
                { "n|newkey", "generates a new RSA Key, default size is 2048bits, exports as .pem files by default \n[ACTION]",
                    v => { newKey = true; action = true; } },
                { "o|output=", "path to output encrypted files",
                    v => argsValue.Add("output",v) },
                { "p|password", "when generating/using a new key use this flag to set password. when using this flag must always be a private key.",
                    v => passwordProtected = true
                },
                // action
                { "s|sign", "signs data, requires private key \n[ACTION]",
                    v => { sign = v != null; action = true; } },
                { "t|target=", "file or directory to be encrypted, decrypted or to verify its signature if directory encrypts all file from that directory",
                    v => argsValue.Add("target",v) },
                { "u|unmerge", "unmerge signature from file, requires public key used in signature, use --hashalg to identify wich hashing algorithm was used and verify signature (if none was specified uses default: SHA256)\n[ACTION]",
                    v => { unmerge = true; action = true; } },
                // action
                { "v|verifysignature", "verify if signed data is trustworthy \n[ACTION], use --target for signed data and --signaturefile for signature file",
                    v => { verifySignature = v != null; action = true; } },
                { "x|examples", "show specific examples \n[ACTION]",
                    v => { examples = v != null; action = true; } },
                { "hashalg=", "type of hashing algorithm, examples: SHA1, SHA256. default value is SHA256",
                    v => hashalg = v },
                { "keyfilename=", "when generating a new key use this to choose file name, default is \"key\"",
                    v => argsValue.Add("keyfilename",v) },
                { "keysize=", "when generating key use this to choose its size, minimum size is 384 and maximum is 16384, key size must be in increments of 8 bits.",
                    (int v) => keySize = v },
                { "signaturefile=", "signature file generated based on encrypted file",
                    v => argsValue.Add("signaturefile", v) },
                { "verbose", "increase debug message verbosity",
                    v => verbose = v != null },
                // action
                { "version", "shows version \n[ACTION]",
                    v => { version = v != null; action = true; } },
            };
            var extra = new List<string>();
            try
            {
                extra = opts.Parse(args);
                string keyPath = argsValue.ContainsKey("key") ? argsValue["key"] : null;

                // show help when no args, not defined opts
                // missing action option, show help
                if (help || args == null || extra.Count > 0 ||!action ||
                    (string.IsNullOrWhiteSpace(keyPath) && !newKey))
                {
                    ShowHelp(opts);
                    return;
                }

                if (examples)
                {
                    ShowExamples(opts);
                    return;
                }

                if (version)
                {
                    var assembly = Assembly.GetEntryAssembly().GetName();
                    Console.WriteLine($"v{assembly.Version}");
                    return;
                }

                Console.WriteLine($"[*] Starting {exeName}...");

                var output = argsValue.ContainsKey("output") ? argsValue["output"] : Environment.CurrentDirectory;
                hashalg = string.IsNullOrWhiteSpace(hashalg) ? "SHA256" : hashalg.ToUpper();

                EncryptionPairKey key = default;

                if (passwordProtected)
                {
                    Console.Write("[*] Encrypted Key Password: ");
                    while (true)
                    {
                        var cKey = Console.ReadKey(true);
                        if (cKey.Key != ConsoleKey.Backspace && cKey.Key != ConsoleKey.Enter &&
                            cKey.Key != ConsoleKey.Escape && cKey.KeyChar != '\0')
                        {
                            passwd += cKey.KeyChar;
                        }
                        else if (cKey.Key == ConsoleKey.Backspace && passwd.Length > 0)
                        {
                            passwd = passwd[0..^1];
                        }
                        else if (cKey.Key == ConsoleKey.Enter)
                        {
                            Console.Write('\n');
                            break;
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(keyPath))
                    key = default;
                else if (passwordProtected)
                    key = EncryptionPairKey.ImportPKCS8(passwd, keyPath);
                else
                    key = EncryptionPairKey.ImportPEMFile(keyPath);

                if (encrypt)
                {
                    EncryptOption(argsValue["target"], key, verbose, output);
                    return;
                }
                if (sign)
                {
                    Console.WriteLine("[*] Warning: Some hashing algorithms may have issues depending on the key size");
                    Sign(argsValue["target"], key, output, verbose);
                    return;
                }
                if (verifySignature)
                {
                    VerifySignature(argsValue["target"], argsValue["signaturefile"], key, verbose);
                    return;
                }
                if (decrypt)
                {
                    DecryptOption(argsValue["target"], key, output, verbose);
                    return;
                }
                if (merge)
                {
                    MergeSignatureAndData(argsValue["target"], argsValue["signaturefile"], output, key, verbose);
                    return;
                }
                if (unmerge)
                {
                    UnmergeSignatureAndData(argsValue["target"], output, key, hashalg, verbose);
                    return;
                }
                if (newKey)
                {
                    GenerateKey(keySize, verbose, output, argsValue.ContainsKey("keyfilename") ? argsValue["keyfilename"] : "key", passwd);
                    return;
                }
            }
            catch (Exception e)
            {
                Console.Write($"[*] {exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
                Console.WriteLine($"[*] Try '{exeName} --help' for more information or --examples");
                return;
            }
        }

        public static void GenerateKey(int keySize, bool verbose, string output, string filename = "key", string passwd = "")
        {
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));

            bool hasPasswd = !string.IsNullOrWhiteSpace(passwd);

            if (verbose)
            {
                Console.WriteLine("[*] Generating RSA key pair...");
                Stopwatch.Restart();
            }
            var newKey = EncryptionPairKey.New(keySize);
            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for generating new RSA key pair {Stopwatch.ElapsedMilliseconds} ms");
                Stopwatch.Start();
                if (!hasPasswd)
                    Console.WriteLine("[*] Exporting public key...");
            }
            if (!hasPasswd)
                newKey.ExportAsPEMFile(output, filename, false);

            if (verbose && !hasPasswd)
            {
                Console.WriteLine("[*] Exporting private key...");
            }
            if (!hasPasswd)
                newKey.ExportAsPEMFile(output, filename, true);
            if (hasPasswd)
            {
                Console.WriteLine("[*] Exporting encrypted key pair...");
                newKey.ExportAsPKCS8(passwd, output, filename);
            }

            Console.WriteLine($"[*] Key pair generated and exported to {output}...");
            if (!hasPasswd)
                Console.WriteLine($"[*] as pub.{filename}.pem and priv.{filename}.pem");
            else
                Console.WriteLine($"[*] as {filename}.pem...");
            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for export {Stopwatch.ElapsedMilliseconds}ms.");
            }
        }

        public static void Sign(string target, EncryptionPairKey privateKey, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));

            if (privateKey == null)
                throw new ArgumentNullException(
                    message: "In order to sign data, private key must not be null.",
                    paramName: nameof(privateKey));

            if (!File.Exists(target) || string.IsNullOrWhiteSpace(target))
                throw new ArgumentException(
                    message: "When signing target must be an existent file.",
                    paramName: nameof(target));

            if (privateKey.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to sign data using a public key.");

            string fileName = Path.GetFileNameWithoutExtension(target);
            string fileExt = Path.GetExtension(target);

            if (verbose)
                Console.WriteLine("[*] Storing file in memory...");

            FileManipulation.OpenFile(target, out var file);

            if (verbose)
            {
                Console.WriteLine("[*] File in memory...");
                Console.WriteLine("[*] Signing file...");
                Stopwatch.Restart();
            }
            var signedData = privateKey.SignData(file, hashalg);

            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for signing {Stopwatch.ElapsedMilliseconds} ms");
                Console.WriteLine("[*] Saving file...");
            }

            FileManipulation.SaveFile(signedData, output, $"{fileName}.{hashalg}{fileExt}", true);
            Console.WriteLine($"[*] File saved as \"{fileName}.{hashalg}{fileExt}\" at {output}");
        }

        public static void VerifySignature(string dataPath, string signaturePath, EncryptionPairKey publicKey, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(dataPath))
                throw new ArgumentNullException(
                    message: "Data path cannot be null.",
                    paramName: nameof(dataPath));

            if (string.IsNullOrWhiteSpace(signaturePath))
                throw new ArgumentNullException(
                    message: "Signed data path cannot be null.",
                    paramName: nameof(signaturePath));

            if (publicKey == null)
                throw new NullReferenceException(
                    message: "In order to verify signature, public key must not be null.");

            if (!File.Exists(dataPath) || !File.Exists(signaturePath))
                throw new ArgumentException(message: "Both files must exists.");

            if (verbose)
                Console.WriteLine("[*] Storing original data in memory...");

            FileManipulation.OpenFile(dataPath, out var originalData);

            if (verbose)
            {
                Console.WriteLine("[*] Original data stored...");
                Console.WriteLine("[*] Storing signed data in memory...");
            }

            FileManipulation.OpenFile(signaturePath, out var signedData);

            if (verbose)
                Console.WriteLine("[*] Signed data stored...");

            string fileName = Path.GetFileName(dataPath);

            if (verbose)
                Stopwatch.Restart();

            bool validSignature = publicKey.VerifySignedData(originalData, signedData, hashalg);

            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time for verifying signature {Stopwatch.ElapsedMilliseconds} ms");
            }

            if (validSignature)
                Console.WriteLine($"[*] The file \"{fileName}\" contains a valid {hashalg} signature.");
            else
                Console.WriteLine($"[*] The file \"{fileName}\" do not contains a valid {hashalg} signature.");
        }

        public static void DecryptOption(string target, EncryptionPairKey decryptionKey, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (decryptionKey == null)
                throw new ArgumentNullException(
                    message: "In order to decrypt data, private key must not be null.",
                    paramName: nameof(decryptionKey));

            if (decryptionKey.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to decrypt data using a public key.");

            if (File.Exists(target))
            {
                Console.WriteLine("[*] Decrypting 1 out of 1 file(s).");
                Decrypt(target, decryptionKey, output, verbose);
            }
            else if (Directory.Exists(target))
            {
                var pathFiles = Directory.GetFiles(target, "*encryp*");
                for (int i = 0; i < pathFiles.Length; i++)
                {
                    Console.WriteLine($"[*] Decrypting {i + 1} out of {pathFiles.Length} file(s).");
                    Decrypt(pathFiles[i], decryptionKey, output, verbose);
                }
            }
            else
            {
                throw new ArgumentException(message: "Target path is non-existent.");
            }
        }

        public static void EncryptOption(string target, EncryptionPairKey ecnryptionKey, bool verbose, string output)
        {
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (ecnryptionKey == null)
                throw new ArgumentNullException(
                    message: "In order to encrypt data, public key must not be null.",
                    paramName: nameof(ecnryptionKey));

            if (File.Exists(target))
            {
                Console.WriteLine($"[*] Encrypting 1 out of 1 file(s).");
                Encrypt(target, ecnryptionKey, verbose, output);
            }
            else if (Directory.Exists(target))
            {
                var pathFiles = Directory.GetFiles(target);
                for (int i = 0; i < pathFiles.Length; i++)
                {
                    Console.WriteLine($"[*] Encrypting {i + 1} out of {pathFiles.Length} file(s).");

                    Encrypt(pathFiles[i], ecnryptionKey, verbose, output);
                }
            }
            else
            {
                throw new ArgumentException(message: "Target path is non-existent.");
            }
        }

        public static string MergeSignatureAndData(string targetPath, string signaturePath, string output, EncryptionPairKey publicKey, bool verbose = false)
        {
            if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
                throw new ArgumentException(
                    message: "Target file must exists.",
                    paramName: nameof(targetPath));
            if (string.IsNullOrWhiteSpace(signaturePath) || !File.Exists(signaturePath))
                throw new ArgumentException(
                    message: "Signature path must exists.",
                    paramName: nameof(signaturePath));
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));
            if (publicKey == null)
                throw new NullReferenceException(
                    message: "Key must not be null.");

            if (verbose)
            {
                Console.WriteLine("[*] Storing data in memory...");
                Console.WriteLine("[*] Storing signature in memory...");
                Stopwatch.Restart();
            }

            string fileName = Path.GetFileNameWithoutExtension(targetPath);
            string fileExt = Path.GetExtension(targetPath);

            FileManipulation.OpenFile(targetPath, out var data);
            FileManipulation.OpenFile(signaturePath, out var signature);
            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time to store files {Stopwatch.ElapsedMilliseconds} ms");
            }

            byte[] mergedFile = new byte[signature.Length + data.Length];
            using (var ms = new MemoryStream(mergedFile))
            {
                ms.Write(signature, 0, signature.Length);
                ms.Write(data, 0, data.Length);
            }

            if (!publicKey.VerifySignedData(data, signature, hashalg))
                throw new InvalidDataException(
                    message: "Signature is invalid for this key.");

            Console.WriteLine($"[*] Merged file saved at: {output}\\{fileName}.merged{fileExt}");
            FileManipulation.SaveFile(mergedFile, output, fileName + $".merged{fileExt}", true);
            return $"{output}\\{fileName}.merged{fileExt}";
        }

        public static void UnmergeSignatureAndData(string targetPath, string output, EncryptionPairKey publicSignatureKey, string hashalg, bool verbose = false)
        {
            if (!File.Exists(targetPath) || string.IsNullOrWhiteSpace(targetPath))
                throw new ArgumentException(
                    message: "Target file must exists.",
                    paramName: nameof(targetPath));
            if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid output path.",
                    paramName: nameof(output));
            if (publicSignatureKey == null)
                throw new NullReferenceException(
                    message: "Key must not be null.");

            var rnd = new Random();
            byte[] b = new byte[4];
            rnd.NextBytes(b);

            // getting signature size based on key size
            // (not sure if correct)
            int signatureSize = EncryptionPairKey.New(publicSignatureKey.KeySize).SignData(b, hashalg).Length;

            if (verbose)
            {
                Console.WriteLine("[*] Storing file into memory...");
                Console.WriteLine("[*] Spliting signature and data...");
                Stopwatch.Restart();
            }

            FileManipulation.OpenFile(targetPath, out var file);

            byte[] signature = new byte[signatureSize];
            byte[] data = new byte[file.Length - signatureSize];

            using (var ms = new MemoryStream(file))
            {
                ms.Read(signature, 0, signatureSize);
                ms.Read(data, 0, data.Length);
            }

            if (!publicSignatureKey.VerifySignedData(data, signature, hashalg))
                throw new InvalidDataException(
                    message: "Signature is not valid or do not exist for this file.");

            if (verbose)
            {
                Stopwatch.Stop();
                Console.WriteLine($"[*] Elapsed time {Stopwatch.ElapsedMilliseconds} ms");
            }

            string fileName = Path.GetFileNameWithoutExtension(targetPath).Replace(".merged","");
            string fileExt = Path.GetExtension(targetPath);
            string signatureFileName = $"unmerged.{fileName}.{hashalg}";
            string dataFileName = $"unmerged.{fileName}{fileExt}";

            Console.WriteLine($"[*] Saving signature as: {output}\\{signatureFileName}");
            Console.WriteLine($"[*] Saving data as: {output}\\{dataFileName}");
            FileManipulation.SaveFile(signature, output, signatureFileName);
            FileManipulation.SaveFile(data, output, dataFileName);
        }

        public static void ShowHelp(OptionSet opts)
        {
            Console.WriteLine($"Usage: {exeName} [OPTIONS]");
            Console.WriteLine("Encrypts, decrypts, sign and verifies signature from files.");
            Console.WriteLine("Note: When encrypting or decrypting --target can be used to specify a directory");
            Console.WriteLine($"Note: If no output is specified, the default output path is {Environment.CurrentDirectory}.");
            Console.WriteLine("Note: Recommendation is that files are no larger than 10mb, cause it'll take longer");
            Console.WriteLine("Note: When using decrypt on a directory it searches for files that contains .encrypted on it's name.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            opts.WriteOptionDescriptions(Console.Out);
        }

        public static void ShowExamples(OptionSet opts)
        {
            ShowHelp(opts);
            Console.Write("\n\n");
            Console.WriteLine("Examples:\n");
            Console.WriteLine($" Encrypting: [{exeName} -e -t=.\\myfile.pdf -k=.\\pub.key.pem]\n\tEncrypts target data using default output.");
            Console.WriteLine($" Decrypting: [{exeName} -d -t=.\\myfile.encrypted.pdf -o=.\\ -k=.\\priv.key.pem --verbose]\n\tDecrypts specified file on specified output using selected key with increase verbosity");
            Console.WriteLine($" Generating new key with chosen size and name: [{exeName} -n --keysize=1024 --keyfilename=my_1024_key -o=.]\\\n\tGenerates a new key with specified name and size at selected path");
            Console.WriteLine($" Generating new encrypted key: [{exeName} -n -p]\n\tGenerates a new encrypted key using default values.");
            Console.WriteLine($" Signing: [{exeName} -s -t=.\\myfile.docx -k=.\\priv.key.pem]\n\tSigns the specified file using default output with specified private key");
            Console.WriteLine($" Verifying signature: [{exeName} -v -t=.\\myfile.txt --signaturefile=.\\myfile.signature.txt -k=.\\pub.key.pem]\n\tChecks if signature file is valid");
        }
    }
}
