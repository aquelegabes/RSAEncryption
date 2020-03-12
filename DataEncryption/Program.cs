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
        static Stopwatch Stopwatch = new Stopwatch();
        static readonly string exeName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
        static string hashalg = "SHA256";

        static void Main(string[] args)
        {
            bool verbose = false;
            bool help = false;
            bool encrypt = false;
            bool decrypt = false;
            bool sign = false;
            bool verifySignature = false;
            int newKey = -1;
            var argsValue = new Dictionary<string, string>();

            var opts = new OptionSet
            {
                { "nk|newkey=", "generates a new RSA Key with specified key size, default size is 2048bits",
                   (int v) => newKey = v },
                { "e|encrypt", "encrypts the data",
                    v => encrypt = v != null },
                { "d|decrypt", "decrypts the encrypted data, requires private key",
                    v => decrypt = v != null },
                { "s|sign", "signs the encrypted data, requires private key",
                    v => sign = v != null },
                { "vs|verifysignature", "verify if signed data is trustworthy",
                    v => verifySignature = v != null },
                { "sf|signaturefile=", "signature file generated along side with its encryption",
                    v => argsValue.Add("signaturefile", v) },
                { "t|target=", "file or directory to be encrypted, decrypted or to verify its signature if directory encrypts all file from that directory",
                    v => argsValue.Add("target",v) },
                { "o|output=", "path to output encrypted files",
                    v => argsValue.Add("output",v) },
                { "pbk|publickey=", "path where public key is stored (.pem file)",
                    v => argsValue.Add("publickey",v) },
                { "pvk|privatekey=", "path where private key is stored (.pem file)",
                    v => argsValue.Add("privatekey",v) },
                { "v|verbose", "increase debug message verbosity",
                    v => verbose = v != null },
                { "h|help", "show this message and exit",
                    v => help = v != null },
                { "hg|hashalg=", "type of hashing algorithm, examples: SHA1, SHA256. default value is SHA256",
                    v => hashalg = v },
            };
            var extra = new List<string>();
            try
            {
                extra = opts.Parse(args);

                var output = argsValue.ContainsKey("output") ? argsValue["output"] : Environment.CurrentDirectory;
                bool isPublic = argsValue.ContainsKey("publickey");
                var pathKey = isPublic ? argsValue["publickey"] : argsValue["privatekey"];
                var key = EncryptionPairKey.ImportFromFile(pathKey, !isPublic);
                hashalg = string.IsNullOrWhiteSpace(hashalg) ? "SHA256" : hashalg.ToUpper();

                if (help)
                {
                    ShowHelp(opts);
                    return;
                }
                if (encrypt)
                {
                    Encrypt(argsValue["target"], sign, key, verbose, output);
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
            }
            catch (OptionException e)
            {
                Console.Write($"{exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ?  e.InnerException.Message :  e.Message);
                Console.WriteLine($"Try '{exeName} --help' for more information");
                return;
            }
            catch (Exception e)
            {
                Console.Write($"[*] {exeName}: ");
                Console.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
                Console.WriteLine($"[*] Try '{exeName} --help' for more information");
                return;
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
                    var decrypted = RSAMethods.FileDecrypt(file, key);
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
                        var decrypted = RSAMethods.FileDecrypt(file, key);
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
                    var encrypted = RSAMethods.FileEncrypt(file, key);
                    if (verbose)
                    {
                        Stopwatch.Stop();
                        Console.WriteLine($"[*] Elapsed time for encryption {Stopwatch.ElapsedMilliseconds} ms");
                    }

                    if (sign)
                    {
                        if (verbose)
                        {
                            Console.WriteLine("[*] Signing encrypted data...");
                            Stopwatch.Restart();
                        }
                        var signedFile = RSAMethods.SignData(encrypted, key, hashalg);
                        if (verbose)
                        {
                            Stopwatch.Stop();
                            Console.WriteLine($"[*] Elapsed time for signing {Stopwatch.ElapsedMilliseconds} ms");
                            Console.WriteLine("[*] Saving signed file...");
                        }

                        FileManipulation.SaveFile(signedFile, output, $"{fileName}.signature{fileExt}");
                        Console.WriteLine("[*] Signature file saved as \"{fileName}.encrypted{fileExt}\" at {output}");
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
                        FileManipulation.OpenFile(target, out var file);
                        if (verbose)
                        {
                            Console.WriteLine("[*] File in memory...");
                            Console.WriteLine("[*] Starting encryption...");
                            Stopwatch.Restart();
                        }
                        var encrypted = RSAMethods.FileEncrypt(file, key);
                        if (verbose)
                        {
                            Stopwatch.Stop();
                            Console.WriteLine($"[*] Elapsed time for encryption {Stopwatch.ElapsedMilliseconds} ms");
                        }

                        if (sign)
                        {
                            if (verbose)
                            {
                                Console.WriteLine("[*] Signing encrypted data...");
                                Stopwatch.Restart();
                            }
                            var signedFile = RSAMethods.SignData(encrypted, key, hashalg);
                            if (verbose)
                            {
                                Stopwatch.Stop();
                                Console.WriteLine($"[*] Elapsed time for signing {Stopwatch.ElapsedMilliseconds} ms");
                                Console.WriteLine("[*] Saving signed file...");
                            }
                            FileManipulation.SaveFile(signedFile, output, $"{fileName}.signature{fileExt}");
                            Console.WriteLine("[*] Signature file saved as \"{fileName}.encrypted{fileExt}\" at {output}");
                        }

                        if (verbose)
                            Console.WriteLine("[*] Saving file...");
                        FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
                        Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");
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
            Console.WriteLine("Encrypts data from files or a specified directory.");
            Console.WriteLine($"If no output is specified, the default output path is {Environment.CurrentDirectory}.");
            Console.WriteLine("Recommendation is that files are no larger than 10mb");
            Console.WriteLine();
            Console.WriteLine($" Example 1: {exeName} -nk=4096 \n\t Generates a new RSAKey 4096 bits, outputs public and private key separetly to default output path");
            Console.WriteLine($" Example 2: {exeName} -e -s -t=C:\\myfile.txt -o=.\\ -pbk=C:\\mypubkey.pem \n\t Encrypts and sign the specified file on the specified output with specified public key");
            Console.WriteLine($" Example 3: {exeName} -d -t=C:\\myencryptedfile.txt -pvk=C:\\myprivatekey.pem \n\t Decrypts specified file using specified private key to default output path");
            Console.WriteLine();
            Console.WriteLine("Options:");
            opts.WriteOptionDescriptions(Console.Out);
        }
    }
}
