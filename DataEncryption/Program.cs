using Mono.Options;
using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace RSAEncryption
{
    class Program
    {
        static readonly Stopwatch Stopwatch = new Stopwatch();
        static readonly string exeName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
        static string hashalg = "SHA256";

        static void Main(string[] args)
        {
            bool verbose = false;
            bool help = false;
            bool examples = false;
            bool encrypt = false;
            bool decrypt = false;
            bool sign = false;
            bool verifySignature = false;
            bool version = false;
            int newKey = -1;
            var argsValue = new Dictionary<string, string>();

            var opts = new OptionSet
            {
                { "e|encrypt", "encrypts the data",
                    v => encrypt = v != null },
                { "d|decrypt", "decrypts the encrypted data, requires private key",
                    v => decrypt = v != null },
                { "h|help", "show this message and exit",
                    v => help = v != null },
                { "o|output=", "path to output encrypted files",
                    v => argsValue.Add("output",v) },
                { "s|sign", "signs the encrypted data, requires private key",
                    v => sign = v != null },
                { "t|target=", "file or directory to be encrypted, decrypted or to verify its signature if directory encrypts all file from that directory",
                    v => argsValue.Add("target",v) },
                { "v|verifysignature", "verify if signed data is trustworthy",
                    v => verifySignature = v != null },
                { "x|examples", "show specific examples",
                    v => examples = v != null },
                { "hashalg=", "type of hashing algorithm, examples: SHA1, SHA256. default value is SHA256",
                    v => hashalg = v },
                { "newkey=", "generates a new RSA Key with specified key size, default size is 2048bits, exports public and private separetly",
                   (int v) => newKey = v },
                { "publickey=", "path where public key is stored (.pem file)",
                    v => argsValue.Add("publickey",v) },
                { "privatekey=", "path where private key is stored (.pem file)",
                    v => argsValue.Add("privatekey",v) },
                { "signaturefile=", "signature file generated along side with its encryption",
                    v => argsValue.Add("signaturefile", v) },
                { "verbose", "increase debug message verbosity",
                    v => verbose = v != null },
                { "version", "shows version",
                    v => version = v != null },
            };
            var extra = new List<string>();
            try
            {
                extra = opts.Parse(args);
                if (help || args == null || extra.Count > 0)
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

                var output = argsValue.ContainsKey("output") ? argsValue["output"] : Environment.CurrentDirectory;
                bool isPublic = argsValue.ContainsKey("publickey");
                var pathKey = isPublic ? argsValue["publickey"] : argsValue.ContainsKey("privatekey") ? argsValue["privatekey"] : "";
                var key = !string.IsNullOrWhiteSpace(pathKey) ? EncryptionPairKey.ImportFromFile(pathKey, !isPublic) : null;
                
                hashalg = string.IsNullOrWhiteSpace(hashalg) ? "SHA256" : hashalg.ToUpper();

                Console.WriteLine($"[*] Starting {exeName}...");
                if (encrypt)
                {
                    Encrypt(argsValue["target"], sign, key, verbose, output);
                    return;
                }
                if (sign && !encrypt)
                {
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
                    Decrypt(argsValue["target"], key, output, verbose);
                    return;
                }
                if (newKey != -1)
                {
                    if (newKey < 0)
                        throw new ArgumentException(
                            message: "Key size must not be negative.",
                            paramName: nameof(newKey));

                    if (verbose)
                    {
                        Console.WriteLine("[*] Generating RSA key...");
                        Stopwatch.Restart();
                    }
                    var keyNew = EncryptionPairKey.New(newKey);
                    if (verbose)
                    {
                        Stopwatch.Stop();
                        Console.WriteLine($"[*] Elapsed time for generating new RSA key {Stopwatch.ElapsedMilliseconds} ms");
                        Console.WriteLine("[*] Exporting public key...");
                    }
                    keyNew.ExportToFile(output, false);
                    if (verbose)
                        Console.WriteLine("[*] Exporting private key...");
                    keyNew.ExportToFile(output, true);

                    Console.WriteLine($"[*] Key generated and exported to {output}");
                    Console.WriteLine("[*] as pubkey.pem and privkey.pem");
                }
            }
            catch (OptionException e)
            {
                Console.Write($"{exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ?  e.InnerException.Message :  e.Message);
                Console.WriteLine($"Try '{exeName} --help' for more information or --examples");
                return;
            }
            catch (Exception e)
            {
                Console.Write($"[*] {exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
                Console.WriteLine($"[*] Try '{exeName} --help' for more information or --examples");
                return;
            }
        }

        static void Sign(string target, EncryptionPairKey key, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output))
                output = Environment.CurrentDirectory;
            else if (!Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid directory path.",
                    paramName: nameof(output));

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (key.Private == null)
                throw new ArgumentNullException(
                    message: "In order to decrypt data, private key must not be null.",
                    paramName: nameof(key));

            Console.WriteLine("[*] Warning: Target file must be the encrypted and not the original to sign correctly");

            if (File.Exists(target))
            {
                string fileName = Path.GetFileNameWithoutExtension(target);
                fileName = fileName.Replace(".encrypted", "");
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
                var signedData = RSAMethods.SignData(file, key, hashalg);

                if (verbose)
                {
                    Stopwatch.Stop();
                    Console.WriteLine($"[*] Elapsed time for signing {Stopwatch.ElapsedMilliseconds} ms");
                    Console.WriteLine("[*] Saving file...");
                }

                FileManipulation.SaveFile(signedData, output, $"{fileName}.signature{fileExt}", true);
                Console.WriteLine($"[*] File saved as \"{fileName}.signature{fileExt}\" at {output}");
            }
            else
            {
                throw new ArgumentException(message: "Target path is non-existent.");
            }
        }

        static void Decrypt(string target, EncryptionPairKey key, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output))
                output = Environment.CurrentDirectory;
            else if (!Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid directory path.",
                    paramName: nameof(output));

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (key.Private == null)
                throw new ArgumentNullException(
                    message: "In order to decrypt data, private key must not be null.",
                    paramName: nameof(key));
            else
            {
                if (File.Exists(target))
                {
                    string fileName = Path.GetFileNameWithoutExtension(target);
                    fileName = fileName.Replace(".encrypted", "");
                    string fileExt = Path.GetExtension(target);

                    if (verbose)
                    {
                        Console.WriteLine("[*] Decrypting 1 out of 1 file(s).");
                        Console.WriteLine("[*] Storing file in memory...");
                    }

                    FileManipulation.OpenFile(target, out var file);
                    if (verbose)
                    {
                        Console.WriteLine("[*] File in memory...");
                        Console.WriteLine("[*] Starting decryption...");
                        Stopwatch.Restart();
                    }
                    var decrypted = RSAMethods.DecryptFile(file, key);
                    if (verbose)
                    {
                        Stopwatch.Stop();
                        Console.WriteLine($"[*] Elapsed time for decryption {Stopwatch.ElapsedMilliseconds} ms");
                        Console.WriteLine("[*] Saving file...");
                    }

                    FileManipulation.SaveFile(decrypted, output, $"{fileName}.decrypted{fileExt}", true);
                    Console.WriteLine($"[*] File saved as \"{fileName}.decrypted{fileExt}\" at {output}");
                }
                else if (Directory.Exists(target))
                {
                    var files = Directory.GetFiles(target);
                    foreach (var pathFile in files)
                    {
                        string fileName = Path.GetFileNameWithoutExtension(pathFile);
                        fileName = fileName.Replace(".encrypted", "");
                        string fileExt = Path.GetExtension(pathFile);

                        if (verbose)
                        {
                            Console.WriteLine("[*] Decrypting 1 out of 1 file(s).");
                            Console.WriteLine("[*] Storing file in memory...");
                        }

                        FileManipulation.OpenFile(target, out var file);
                        if (verbose)
                        {
                            Console.WriteLine("[*] File in memory...");
                            Console.WriteLine("[*] Starting decryption...");
                            Stopwatch.Restart();
                        }
                        var decrypted = RSAMethods.DecryptFile(file, key);
                        if (verbose)
                        {
                            Stopwatch.Stop();
                            Console.WriteLine($"[*] Elapsed time for decryption {Stopwatch.ElapsedMilliseconds} ms");
                            Console.WriteLine("[*] Saving file...");
                        }

                        FileManipulation.SaveFile(decrypted, output, $"{fileName}.decrypted{fileExt}", true);
                        Console.WriteLine($"[*] File saved as \"{fileName}.decrypted{fileExt}\" at {output}");
                    }
                }
                else
                {
                    throw new ArgumentException(message: "Target path is non-existent.");
                }
            }
        }

        static void VerifySignature(string originalDataPath, string signedDataPath, EncryptionPairKey key, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(originalDataPath))
                throw new ArgumentNullException(
                    message: "Original data path cannot be null.",
                    paramName: nameof(originalDataPath));
            if (string.IsNullOrWhiteSpace(signedDataPath))
                throw new ArgumentNullException(
                    message: "Signed data path cannot be null.",
                    paramName: nameof(signedDataPath));

            if (key.Public == null)
                throw new ArgumentNullException(
                    message: "In order to verify signature, public key must not be null.",
                    paramName: nameof(key));

            if (!File.Exists(originalDataPath) && !File.Exists(signedDataPath))
                throw new ArgumentException(message: "Both of paths must exists.");

            if (verbose)
                Console.WriteLine("[*] Storing original data in memory...");
            FileManipulation.OpenFile(originalDataPath, out var originalData);
            if (verbose)
            {
                Console.WriteLine("[*] Original data stored...");
                Console.WriteLine("[*] Storing signed data in memory...");
            }
            FileManipulation.OpenFile(signedDataPath, out var signedData);
            if (verbose)
                Console.WriteLine("[*] Signed data stored...");

            string fileName = Path.GetFileName(signedDataPath);

            if (verbose)
                Stopwatch.Restart();
            if (RSAMethods.VerifySignedData(originalData, signedData, key, hashalg))
            {
                if (verbose)
                {
                    Stopwatch.Stop();
                    Console.WriteLine($"[*] Elapsed time for verifying signature {Stopwatch.ElapsedMilliseconds} ms");
                }
                Console.WriteLine($"[*] The file \"{fileName}\" contains a valid {hashalg} signature.");
            }
            else
            {
                if (verbose)
                {
                    Stopwatch.Stop();
                    Console.WriteLine($"[*] Elapsed time for verifying signature {Stopwatch.ElapsedMilliseconds} ms");
                }
                Console.WriteLine($"[*] The file \"{fileName}\" do not contains a valid {hashalg} signature.");
            }
        }

        static void Encrypt(string target, bool sign, EncryptionPairKey key, bool verbose, string output)
        {
            if (!Directory.Exists(output))
                throw new ArgumentException(
                    message: "Invalid directory path.",
                    paramName: nameof(output));

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (key.Public == null)
                throw new ArgumentNullException(
                    message: "In order to encrypt data, public key must not be null.",
                    paramName: nameof(key));
            else
            {
                if (File.Exists(target))
                {
                    if (verbose)
                        Console.WriteLine($"[*] Encrypting 1 out of 1 file(s).");

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
                    var encrypted = RSAMethods.EncryptFile(file, key);
                    if (verbose)
                    {
                        Stopwatch.Stop();
                        Console.WriteLine($"[*] Elapsed time for encryption {Stopwatch.ElapsedMilliseconds} ms");
                    }

                    if (sign)
                    {
                        Sign(target, key, output, verbose);
                    }

                    if (verbose)
                        Console.WriteLine("[*] Saving file...");
                    FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
                    Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");
                }
                else if (Directory.Exists(target))
                {
                    var pathFiles = Directory.GetFiles(target);
                    for (int i = 0; i < pathFiles.Length; i++)
                    {
                        if (verbose)
                            Console.WriteLine($"[*] Encrypting {i + 1} out of {pathFiles.Length} file(s).");

                        string fileName = Path.GetFileNameWithoutExtension(pathFiles[i]);
                        string fileExt = Path.GetExtension(pathFiles[i]);

                        if (verbose)
                            Console.WriteLine("[*] Storing file in memory...");
                        FileManipulation.OpenFile(pathFiles[i], out var file);
                        if (verbose)
                        {
                            Console.WriteLine("[*] File in memory...");
                            Console.WriteLine("[*] Starting encryption...");
                            Stopwatch.Restart();
                        }
                        var encrypted = RSAMethods.EncryptFile(file, key);
                        if (verbose)
                        {
                            Stopwatch.Stop();
                            Console.WriteLine($"[*] Elapsed time for encryption {Stopwatch.ElapsedMilliseconds} ms");
                        }

                        if (verbose)
                            Console.WriteLine("[*] Saving file...");
                        FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
                        Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");

                        if (sign)
                        {
                            Sign(pathFiles[i], key, output, verbose);
                        }
                    }
                }
                else
                {
                    throw new ArgumentException(message: "Target path is non-existent.");
                }
            }
        }

        static void ShowHelp(OptionSet opts)
        {
            Console.WriteLine($"Usage: {exeName} [OPTIONS]");
            Console.WriteLine("Encrypts, decrypts, sign and verifies signature from files.");
            Console.WriteLine("Note: When encrypting or decrypting --target can be used to specify a directory");
            Console.WriteLine($"Note: If no output is specified, the default output path is {Environment.CurrentDirectory}.");
            Console.WriteLine("Note: Recommendation is that files are no larger than 10mb, cause it'll take longer");
            Console.WriteLine();
            Console.WriteLine("Options:");
            opts.WriteOptionDescriptions(Console.Out);
        }

        static void ShowExamples(OptionSet opts)
        {
            ShowHelp(opts);
            Console.Write("\n\n");
            Console.WriteLine("Examples:\n");
            Console.WriteLine($" Encrypting and signing: {exeName} -e -s --target=.\\myfile.pdf --publickey=.\\pubkey.pem\n\tEncrypts and sign the specified file using default output with specified public key");
            Console.WriteLine($" Decrypting: {exeName} -d --target=.\\myfile.encrypted.pdf --output=.\\ --privatekey=.\\privkey.pem --verbose\n\tDecrypts specified file on specified output using selected key with increase verbosity");
            Console.WriteLine($" Generating new key: {exeName} --newkey=4096 -o=.\\\n\tGenerates a new key with chosen size at selected path");
            Console.WriteLine($" Signing only: {exeName} --sign --target=.\\myfile.encrypted.docx --privatekey=.\\privkey.pem\n\tSigns the specified file using default output with specified private key");
            Console.WriteLine($" Verifying signature: {exeName} -vs --target=.\\myfile.encrypted.txt --signaturefile=.\\myfile.signature.txt --publickey=.\\pubkey.pem\n\tChecks if signature file is valid");
        }
    }
}
