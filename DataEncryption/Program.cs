using Mono.Options;
using RSAEncryption.Encryption;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;

namespace RSAEncryption
{
    public static class Program
    {
        static readonly Stopwatch Stopwatch = new Stopwatch();
        static readonly string exeName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
        static string hashalg = "SHA256";

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
            int newKey = -1;
            var argsValue = new Dictionary<string, string>();

            var opts = new OptionSet
            {
                // action
                { "e|encrypt", "encrypts the data \n[ACTION]",
                    v => { encrypt = v != null; action = true; } },
                // action
                { "d|decrypt", "decrypts the encrypted data, requires private key \n[ACTION]",
                    v => { decrypt = v != null; action = true; } },
                // action
                { "h|help", "show this message and exit \n[ACTION]",
                    v => { help = v != null; action = true; } },
                { "o|output=", "path to output encrypted files",
                    v => argsValue.Add("output",v) },
                // action
                { "s|sign", "signs the encrypted data, requires private key \n[ACTION]",
                    v => { sign = v != null; action = true; } },
                { "t|target=", "file or directory to be encrypted, decrypted or to verify its signature if directory encrypts all file from that directory",
                    v => argsValue.Add("target",v) },
                // action
                { "v|verifysignature", "verify if signed data is trustworthy \n[ACTION]",
                    v => { verifySignature = v != null; action = true; } },
                { "x|examples", "show specific examples \n[ACTION]",
                    v => { examples = v != null; action = true; } },
                { "hashalg=", "type of hashing algorithm, examples: SHA1, SHA256. default value is SHA256",
                    v => hashalg = v },
                { "keyfilename=", "when generating a new key use this to choose file name, default is \"key\"",
                    v => argsValue.Add("keyfilename",v) },
                // action
                { "newkey=", "generates a new RSA Key with specified key size, default size is 2048bits, exports public and private separetly \n[ACTION]",
                   (int v) => { newKey = v; action = true; } },
                { "publickey=", "path where public key is stored (.pem file)",
                    v => argsValue.Add("publickey",v) },
                { "privatekey=", "path where private key is stored (.pem file)",
                    v => argsValue.Add("privatekey",v) },
                { "signaturefile=", "signature file generated along side with its encryption",
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

                // show help when no args, not defined opts
                // missing action option, show help
                if (help || args == null || extra.Count > 0 || !action)
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
                var key = !string.IsNullOrWhiteSpace(pathKey) ? EncryptionPairKey.FromPEMFile(pathKey, !isPublic) : null;

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
                    if (argsValue.ContainsKey("keyfilename"))
                        GenerateKey(newKey, verbose, output, argsValue["keyfilename"]);
                    else
                        GenerateKey(newKey, verbose, output);
                    return;
                }
            }
            catch (OptionException e)
            {
                Console.Write($"{exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
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

        public static void GenerateKey(int newKey, bool verbose, string output, string filename = "key")
        {
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
            keyNew.ToPEMFile(output, filename, false);
            if (verbose)
                Console.WriteLine("[*] Exporting private key...");
            keyNew.ToPEMFile(output, filename, true);

            Console.WriteLine($"[*] Key generated and exported to {output}");
            Console.WriteLine($"[*] as pub.{filename}.pem and pub.{filename}.pem");
        }

        public static void Sign(string target, EncryptionPairKey key, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output))
                output = Environment.CurrentDirectory;

            if (key == null)
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

        public static void Decrypt(string target, EncryptionPairKey key, string output, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(output))
                output = Environment.CurrentDirectory;

            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (key == null)
                throw new ArgumentNullException(
                    message: "In order to decrypt data, private key must not be null.",
                    paramName: nameof(key));

            if (key.PublicOnly)
                throw new InvalidOperationException(
                    message: "Impossible to decrypt data using a public key.");

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
                var pathFiles = Directory.GetFiles(target, "*encryp*");
                for (int i = 0; i < pathFiles.Length; i++)
                {
                    string fileName = Path.GetFileNameWithoutExtension(pathFiles[i]);

                    fileName = fileName.Replace(".encrypted", "");
                    string fileExt = Path.GetExtension(pathFiles[i]);

                    if (verbose)
                    {
                        Console.WriteLine($"[*] Decrypting {i + 1} out of {pathFiles.Length} file(s).");
                        Console.WriteLine("[*] Storing file in memory...");
                    }

                    FileManipulation.OpenFile(pathFiles[i], out var file);
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

        public static void VerifySignature(string originalDataPath, string signedDataPath, EncryptionPairKey key, bool verbose)
        {
            if (string.IsNullOrWhiteSpace(originalDataPath))
                throw new ArgumentNullException(
                    message: "Original data path cannot be null.",
                    paramName: nameof(originalDataPath));

            if (string.IsNullOrWhiteSpace(signedDataPath))
                throw new ArgumentNullException(
                    message: "Signed data path cannot be null.",
                    paramName: nameof(signedDataPath));

            if (key == null)
                throw new ArgumentNullException(
                    message: "In order to verify signature, public key must not be null.",
                    paramName: nameof(key));

            if (!File.Exists(originalDataPath) && !File.Exists(signedDataPath))
                throw new ArgumentException(message: "Both files must exists.");

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
            bool validSignature = RSAMethods.VerifySignedData(originalData, signedData, key, hashalg);
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

        public static void Encrypt(string target, bool sign, EncryptionPairKey key, bool verbose, string output)
        {
            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(
                    message: "Target cannot be null.",
                    paramName: nameof(target));

            if (sign && key?.PublicOnly == true)
                throw new InvalidOperationException(
                    message: "Signing flag is enabled, must use private key.");

            if (key == null)
                throw new ArgumentNullException(
                    message: "In order to encrypt data, public key must not be null.",
                    paramName: nameof(key));

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

                if (verbose)
                    Console.WriteLine("[*] Saving file...");

                FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
                Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");

                if (sign)
                {
                    Sign($@"{output}\{fileName}.encrypted{fileExt}", key, output, verbose);
                }
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
                        Sign($@"{output}\{fileName}.encrypted{fileExt}", key, output, verbose);
                    }
                }
            }
            else
            {
                throw new ArgumentException(message: "Target path is non-existent.");
            }
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
            Console.WriteLine($" Encrypting and signing: {exeName} -e -s --target=.\\myfile.pdf --publickey=.\\pubkey.pem\n\tEncrypts and sign the specified file using default output with specified public key");
            Console.WriteLine($" Decrypting: {exeName} -d --target=.\\myfile.encrypted.pdf --output=.\\ --privatekey=.\\privkey.pem --verbose\n\tDecrypts specified file on specified output using selected key with increase verbosity");
            Console.WriteLine($" Generating new key: {exeName} --newkey=4096 -o=.\\\n\tGenerates a new key with chosen size at selected path");
            Console.WriteLine($" Signing only: {exeName} --sign --target=.\\myfile.encrypted.docx --privatekey=.\\privkey.pem\n\tSigns the specified file using default output with specified private key");
            Console.WriteLine($" Verifying signature: {exeName} -vs --target=.\\myfile.encrypted.txt --signaturefile=.\\myfile.signature.txt --publickey=.\\pubkey.pem\n\tChecks if signature file is valid");
        }
    }
}
