namespace RSAEncryption.Console;
public static class Program
{
    private static readonly Stopwatch _stopwatch = new Stopwatch();
    private static readonly string _exeName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);

    public static void Main(string[] args)
    {
        var cp = new ConsoleParameters();
        var opts = cp.GetOptions();

        try
        {
            List<string> extra = opts.Parse(args);
            string keyPath = cp.KeyFileName;

            // show help when no args, not defined opts
            //   missing action option, show help
            //   when key is null and is not newkey/merge
            if (help || args == null || extra?.Count > 0 || !action ||
                (string.IsNullOrWhiteSpace(keyPath) && !newKey && !merge))
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

            Console.WriteLine($"[*] Starting {_exeName}...");

            var output = argsValue.ContainsKey("output") ? argsValue["output"] : Environment.CurrentDirectory;
            _hashAlg = string.IsNullOrWhiteSpace(_hashAlg) ? "SHA256" : _hashAlg.ToUpper();

            EncryptionKeyPair key = default;

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
                key = EncryptionKeyPair.ImportPKCS8(passwd, keyPath);
            else
                key = EncryptionKeyPair.ImportPEMFile(keyPath);

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
                UnmergeSignatureAndData(argsValue["target"], output, key, _hashAlg, verbose);
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
            Console.Write($"[*] {_exeName}: ");
            Console.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
            Console.WriteLine($"[*] Try '{_exeName} --help' for more information or --examples");
            return;
        }
    }

    private static void Decrypt(string target, EncryptionKeyPair key, string output, bool verbose)
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
            _stopwatch.Restart();
        }

        var decrypted = key.DecryptRijndael(file);

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for decryption {_stopwatch.ElapsedMilliseconds} ms");
            Console.WriteLine("[*] Saving file...");
        }

        FileManipulation.SaveFile(decrypted, output, $"{fileName}.decrypted{fileExt}", true);
        Console.WriteLine($"[*] File saved as \"{fileName}.decrypted{fileExt}\" at {output}");
    }
    private static void Encrypt(string target, EncryptionKeyPair key, bool verbose, string output)
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
            _stopwatch.Restart();
        }

        var encrypted = key.EncryptRijndael(file);
        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for encryption {_stopwatch.ElapsedMilliseconds} ms");
        }

        if (verbose)
            Console.WriteLine("[*] Saving file...");

        FileManipulation.SaveFile(encrypted, output, $"{fileName}.encrypted{fileExt}", true);
        Console.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {output}");

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
            _stopwatch.Restart();
        }

        var newKey = EncryptionKeyPair.New(keySize);

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for generating new RSA key pair {_stopwatch.ElapsedMilliseconds} ms");
            _stopwatch.Start();
            Console.WriteLine("[*] Exporting public key...");
        }

        newKey.ExportAsPEMFile(output, filename, false);

        if (!hasPasswd)
        {
            if (verbose) Console.WriteLine("[*] Exporting private key...");
            newKey.ExportAsPEMFile(output, filename, true);
        }

        if (hasPasswd)
        {
            Console.WriteLine("[*] Exporting encrypted key pair...");
            newKey.ExportAsPKCS8(passwd, output, filename);
        }

        Console.WriteLine($"[*] Key pair generated and exported to {output}...");

        if (!hasPasswd) { Console.WriteLine($"[*] as pub.{filename}.pem and priv.{filename}.pem"); }
        else { Console.WriteLine($"[*] as pub.{filename}.pem and enc.{filename}.pem..."); }

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for export {_stopwatch.ElapsedMilliseconds}ms.");
        }
    }

    public static void Sign(string target, EncryptionKeyPair key, string output, bool verbose)
    {
        if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(output));

        if (key == null)
            throw new ArgumentNullException(
                message: "In order to sign data, private key must not be null.",
                paramName: nameof(key));

        if (!File.Exists(target) || string.IsNullOrWhiteSpace(target))
            throw new ArgumentException(
                message: "When signing target must be an existent file.",
                paramName: nameof(target));

        if (key.PublicOnly)
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
            _stopwatch.Restart();
        }
        var signedData = key.SignData(file, _hashAlg);

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for signing {_stopwatch.ElapsedMilliseconds} ms");
            Console.WriteLine("[*] Saving file...");
        }

        FileManipulation.SaveFile(signedData, output, $"{fileName}.{_hashAlg}{fileExt}", true);
        Console.WriteLine($"[*] File saved as \"{fileName}.{_hashAlg}{fileExt}\" at {output}");
    }

    public static void VerifySignature(string dataPath, string signaturePath, EncryptionKeyPair key, bool verbose)
    {
        if (string.IsNullOrWhiteSpace(dataPath))
            throw new ArgumentNullException(
                message: "Data path cannot be null.",
                paramName: nameof(dataPath));

        if (string.IsNullOrWhiteSpace(signaturePath))
            throw new ArgumentNullException(
                message: "Signed data path cannot be null.",
                paramName: nameof(signaturePath));

        if (key == null)
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
            _stopwatch.Restart();

        bool validSignature = key.VerifySignedData(originalData, signedData, _hashAlg);

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time for verifying signature {_stopwatch.ElapsedMilliseconds} ms");
        }

        if (validSignature)
            Console.WriteLine($"[*] The file \"{fileName}\" contains a valid {_hashAlg} signature.");
        else
            Console.WriteLine($"[*] The file \"{fileName}\" do not contains a valid {_hashAlg} signature.");
    }

    public static void DecryptOption(string target, EncryptionKeyPair key, string output, bool verbose)
    {
        if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(output));

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
            Console.WriteLine("[*] Decrypting 1 out of 1 file(s).");
            Decrypt(target, key, output, verbose);
        }
        else if (Directory.Exists(target))
        {
            var pathFiles = Directory.GetFiles(target, "*encryp*");
            for (int i = 0; i < pathFiles.Length; i++)
            {
                Console.WriteLine($"[*] Decrypting {i + 1} out of {pathFiles.Length} file(s).");
                Decrypt(pathFiles[i], key, output, verbose);
            }
        }
        else
        {
            throw new ArgumentException(message: "Target path is non-existent.");
        }
    }

    public static void EncryptOption(string target, EncryptionKeyPair key, bool verbose, string output)
    {
        if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(output));

        if (string.IsNullOrWhiteSpace(target))
            throw new ArgumentNullException(
                message: "Target cannot be null.",
                paramName: nameof(target));

        if (key == null)
            throw new ArgumentNullException(
                message: "In order to encrypt data, public key must not be null.",
                paramName: nameof(key));

        if (File.Exists(target))
        {
            Console.WriteLine($"[*] Encrypting 1 out of 1 file(s).");
            Encrypt(target, key, verbose, output);
        }
        else if (Directory.Exists(target))
        {
            var pathFiles = Directory.GetFiles(target);
            for (int i = 0; i < pathFiles.Length; i++)
            {
                Console.WriteLine($"[*] Encrypting {i + 1} out of {pathFiles.Length} file(s).");

                Encrypt(pathFiles[i], key, verbose, output);
            }
        }
        else
        {
            throw new ArgumentException(message: "Target path is non-existent.");
        }
    }

    public static string MergeSignatureAndData(string targetPath, string signaturePath, string output, EncryptionKeyPair key, bool verbose = false)
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
        if (key == null)
        {
            Console.WriteLine("[*] Warning: Key not set, application can't verify signature file.");
            Console.Write("[*] Do you want to continue? (y/n)");
            ConsoleKeyInfo cKey;
            do
            {
                cKey = Console.ReadKey(true);
                if (cKey.Key == ConsoleKey.N)
                    return "";
            }
            while (cKey.Key != ConsoleKey.Y && cKey.Key != ConsoleKey.N);
            Console.Write('\n');
        }

        if (verbose)
        {
            Console.WriteLine("[*] Storing data in memory...");
            Console.WriteLine("[*] Storing signature in memory...");
            _stopwatch.Restart();
        }

        string fileName = Path.GetFileNameWithoutExtension(targetPath);
        string fileExt = Path.GetExtension(targetPath);

        FileManipulation.OpenFile(targetPath, out var data);
        FileManipulation.OpenFile(signaturePath, out var signature);
        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time to store files {_stopwatch.ElapsedMilliseconds} ms");
        }

        byte[] mergedFile = new byte[signature.Length + data.Length];
        using (var ms = new MemoryStream(mergedFile))
        {
            ms.Write(signature, 0, signature.Length);
            ms.Write(data, 0, data.Length);
        }

        if (key?.VerifySignedData(data, signature, _hashAlg) == false)
        {
            throw new InvalidDataException(
                message: "Signature is invalid for this key.");
        }

        Console.WriteLine($"[*] Merged file saved at: {output}\\{fileName}.merged{fileExt}");
        FileManipulation.SaveFile(mergedFile, output, fileName + $".merged{fileExt}", true);
        return $"{output}\\{fileName}.merged{fileExt}";
    }

    public static void UnmergeSignatureAndData(string targetPath, string output, EncryptionKeyPair key, string hashalg, bool verbose = false)
    {
        if (!File.Exists(targetPath) || string.IsNullOrWhiteSpace(targetPath))
            throw new ArgumentException(
                message: "Target file must exists.",
                paramName: nameof(targetPath));
        if (string.IsNullOrWhiteSpace(output) || !Directory.Exists(output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(output));
        if (key == null)
            throw new NullReferenceException(
                message: "Key must not be null.");

        var rnd = new Random();
        byte[] b = new byte[4];
        rnd.NextBytes(b);

        // getting signature size based on key size
        // (not sure if correct)
        int signatureSize = EncryptionKeyPair.New(key.KeySize).SignData(b, hashalg).Length;

        if (verbose)
        {
            Console.WriteLine("[*] Storing file into memory...");
            Console.WriteLine("[*] Spliting signature and data...");
            _stopwatch.Restart();
        }

        FileManipulation.OpenFile(targetPath, out var file);

        byte[] signature = new byte[signatureSize];
        byte[] data = new byte[file.Length - signatureSize];

        using (var ms = new MemoryStream(file))
        {
            ms.Read(signature, 0, signatureSize);
            ms.Read(data, 0, data.Length);
        }

        if (!key.VerifySignedData(data, signature, hashalg))
            throw new InvalidDataException(
                message: "Signature is not valid or do not exist for this file.");
        else
            Console.WriteLine($"[*] Contains a valid {hashalg} signature.");

        if (verbose)
        {
            _stopwatch.Stop();
            Console.WriteLine($"[*] Elapsed time {_stopwatch.ElapsedMilliseconds} ms");
        }

        string fileName = Path.GetFileNameWithoutExtension(targetPath)
                .Replace(".merged", "");
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
        Console.WriteLine($"Usage: {_exeName} [OPTIONS]");
        Console.WriteLine("Generates key pair and encrypted key pair.");
        Console.WriteLine("Encrypts, decrypts, sign or verify signatures.");
        Console.WriteLine("Options:");
        opts.WriteOptionDescriptions(Console.Out);
    }

    public static void ShowExamples(OptionSet opts)
    {
        ShowHelp(opts);
        Console.Write("\n\n");
        Console.WriteLine("Examples:\n");
        Console.WriteLine($" Encrypting: [{_exeName} -e -t=.\\myfile.pdf -k=.\\pub.key.pem]\n\tEncrypts target data using default output.");
        Console.WriteLine($" Decrypting: [{_exeName} -d -t=.\\myfile.encrypted.pdf -o=.\\ -k=.\\priv.key.pem --verbose]\n\tDecrypts specified file on specified output using selected key with increase verbosity.");
        Console.WriteLine($" Generating new key with chosen size and name: [{_exeName} -n --keysize=1024 --keyfilename=my_1024_key -o=.]\\\n\tGenerates a new key with specified name and size at selected path.");
        Console.WriteLine($" Generating new encrypted key: [{_exeName} -n -p]\n\tGenerates a new encrypted key using default values.");
        Console.WriteLine($" Signing: [{_exeName} -s --hashalg=SHA512 -t=.\\myfile.docx -k=.\\priv.key.pem]\n\tSigns the selected file using default output with specified private key and chosen hashing algorithm. (if hash algorithm has not been default will be SHA256)");
        Console.WriteLine($" Verifying signature: [{_exeName} -v -t=.\\myfile.txt --signaturefile=.\\myfile.signature.txt -k=.\\pub.key.pem]\n\tChecks if signature file is valid. (if hash algorithm has not been chosen default will be SHA256)");
    }
}