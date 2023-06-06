namespace RSAEncryption.Console;
public static partial class Program
{
        static void Decrypt(ConsoleParameters cParams)
    {
        string fileName = Path.GetFileNameWithoutExtension(cParams.Target);
        fileName = fileName.Replace(".encrypted", "");
        string fileExt = Path.GetExtension(cParams.Target);

        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] Storing file in memory...");
        }

        FileManipulation.OpenFile(cParams.Target, out var file);
        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] File in memory...");
            Exec.WriteLine("[*] Starting decryption...");
            _stopwatch.Restart();
        }

        var decrypted = cParams.Key.Decrypt(file);

        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for decryption {_stopwatch.ElapsedMilliseconds} ms");
            Exec.WriteLine("[*] Saving file...");
        }

        FileManipulation.SaveFile(decrypted, cParams.Output, $"{fileName}.decrypted{fileExt}", true);
        Exec.WriteLine($"[*] File saved as \"{fileName}.decrypted{fileExt}\" at {cParams.Output}");
    }
    static void Encrypt(ConsoleParameters cParams)
    {
        string fileName = Path.GetFileNameWithoutExtension(cParams.Target);
        string fileExt = Path.GetExtension(cParams.Target);

        if (cParams.Verbose)
            Exec.WriteLine("[*] Storing file in memory...");
        FileManipulation.OpenFile(cParams.Target, out var file);
        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] File in memory...");
            Exec.WriteLine("[*] Starting encryption...");
            _stopwatch.Restart();
        }

        var encrypted = cParams.Key.Encrypt(file);
        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for encryption {_stopwatch.ElapsedMilliseconds} ms");
        }

        if (cParams.Verbose)
            Exec.WriteLine("[*] Saving file...");

        FileManipulation.SaveFile(encrypted, cParams.Output, $"{fileName}.encrypted{fileExt}", true);
        Exec.WriteLine($"[*] File saved as \"{fileName}.encrypted{fileExt}\" at {cParams.Output}");

    }
    static void GenerateKey(ConsoleParameters cParams)
    {
        if (string.IsNullOrWhiteSpace(cParams.Output) || !Directory.Exists(cParams.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParams.Output));

        bool hasPasswd = !string.IsNullOrWhiteSpace(cParams.Password);

        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] Generating RSA key pair...");
            _stopwatch.Restart();
        }

        var newKey = EncryptionKeyPair.New(cParams.KeySize);

        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for generating new RSA key pair {_stopwatch.ElapsedMilliseconds} ms");
            _stopwatch.Start();
            Exec.WriteLine("[*] Exporting key...");
        }

        newKey.ExportAsPEMFile(cParams.Output, cParams.KeyFileName, false);

        if (!hasPasswd)
        {
            if (cParams.Verbose) Exec.WriteLine("[*] Exporting private key...");
            newKey.ExportAsPEMFile(cParams.Output, cParams.KeyFileName, true);
        }

        if (hasPasswd)
        {
            Exec.WriteLine("[*] Exporting encrypted key pair...");
            newKey.ExportAsPKCS8(cParams.Password, cParams.Output, cParams.KeyFileName);
        }

        Exec.WriteLine($"[*] Key pair generated and exported to {cParams.Output}...");

        if (!hasPasswd) { Exec.WriteLine($"[*] as pub.{cParams.KeyFileName}.pem and priv.{cParams.KeyFileName}.pem"); }
        else { Exec.WriteLine($"[*] as pub.{cParams.KeyFileName}.pem and enc.{cParams.KeyFileName}.pem..."); }

        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for export {_stopwatch.ElapsedMilliseconds}ms.");
        }
    }
    static void Sign(ConsoleParameters cParams)
    {
        if (string.IsNullOrWhiteSpace(cParams.Output) || !Directory.Exists(cParams.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParams.Output));

        if (cParams.Key == null)
            throw new ArgumentNullException(
                message: "In order to sign data, private key must not be null.",
                paramName: nameof(cParams.Key));

        if (!File.Exists(cParams.Target) || string.IsNullOrWhiteSpace(cParams.Target))
            throw new ArgumentException(
                message: "When signing target must be an existent file.",
                paramName: nameof(cParams.Target));

        if (cParams.Key.PublicOnly)
            throw new InvalidOperationException(
                message: "Impossible to sign data using a public key.");

        string fileName = Path.GetFileNameWithoutExtension(cParams.Target);
        string fileExt = Path.GetExtension(cParams.Target);

        if (cParams.Verbose)
            Exec.WriteLine("[*] Storing file in memory...");

        FileManipulation.OpenFile(cParams.Target, out var file);

        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] File in memory...");
            Exec.WriteLine("[*] Signing file...");
            _stopwatch.Restart();
        }
        var signedData = cParams.Key.SignData(file, cParams.HashAlgorithm);

        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for signing {_stopwatch.ElapsedMilliseconds} ms");
            Exec.WriteLine("[*] Saving file...");
        }

        FileManipulation.SaveFile(signedData, cParams.Output, $"{fileName}.{cParams.HashAlgorithm}{fileExt}", true);
        Exec.WriteLine($"[*] File saved as \"{fileName}.{cParams.HashAlgorithm}{fileExt}\" at {cParams.Output}");
    }
    static void VerifySignature(ConsoleParameters cParams)
    {
        if (string.IsNullOrWhiteSpace(cParams.Target))
            throw new ArgumentNullException(
                message: "Data path cannot be null.",
                paramName: nameof(cParams.Target));

        if (string.IsNullOrWhiteSpace(cParams.SignatureFile))
            throw new ArgumentNullException(
                message: "Signed data path cannot be null.",
                paramName: nameof(cParams.SignatureFile));

        if (cParams.Key == null)
            throw new NullReferenceException(
                message: "In order to verify signature, key must not be null.");

        if (!File.Exists(cParams.Target) || !File.Exists(cParams.SignatureFile))
            throw new ArgumentException(message: "Both files must exists.");

        if (cParams.Verbose)
            Exec.WriteLine("[*] Storing original data in memory...");

        FileManipulation.OpenFile(cParams.Target, out var originalData);

        if (cParams.Verbose)
        {
            Exec.WriteLine("[*] Original data stored...");
            Exec.WriteLine("[*] Storing signed data in memory...");
        }

        FileManipulation.OpenFile(cParams.SignatureFile, out var signedData);

        if (cParams.Verbose)
            Exec.WriteLine("[*] Signed data stored...");

        string fileName = Path.GetFileName(cParams.Target);

        if (cParams.Verbose)
            _stopwatch.Restart();

        bool validSignature = cParams.Key.VerifySignedData(originalData, signedData, cParams.HashAlgorithm);

        if (cParams.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time for verifying signature {_stopwatch.ElapsedMilliseconds} ms");
        }

        if (validSignature)
            Exec.WriteLine($"[*] The file \"{fileName}\" contains a valid {cParams.HashAlgorithm} signature.");
        else
            Exec.WriteLine($"[*] The file \"{fileName}\" do not contains a valid {cParams.HashAlgorithm} signature.");
    }
    static void DecryptOption(ConsoleParameters cParameters)
    {
        if (string.IsNullOrWhiteSpace(cParameters.Output) || !Directory.Exists(cParameters.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParameters.Output));

        if (string.IsNullOrWhiteSpace(cParameters.Target))
            throw new ArgumentNullException(
                message: "Target cannot be null.",
                paramName: nameof(cParameters.Target));

        if (cParameters.Key == null)
            throw new ArgumentNullException(
                message: "In order to decrypt data, private key must not be null.",
                paramName: nameof(cParameters.Key));

        if (cParameters.Key.PublicOnly)
            throw new InvalidOperationException(
                message: "Impossible to decrypt data using a key.");

        if (File.Exists(cParameters.Target))
        {
            Exec.WriteLine("[*] Decrypting 1 out of 1 file(s).");
            Decrypt(cParameters);
        }
        else if (Directory.Exists(cParameters.Target))
        {
            var pathFiles = Directory.GetFiles(cParameters.Target, "*encrypt*");
            for (int i = 0; i < pathFiles.Length; i++)
            {
                Exec.WriteLine($"[*] Decrypting {i + 1} out of {pathFiles.Length} file(s).");
                Decrypt(cParameters);
            }
        }
        else
        {
            throw new ArgumentException(message: "Target path is non-existent.");
        }
    }
    static void EncryptOption(ConsoleParameters cParameters)
    {
        if (string.IsNullOrWhiteSpace(cParameters.Output) || !Directory.Exists(cParameters.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParameters.Output));

        if (string.IsNullOrWhiteSpace(cParameters.Target))
            throw new ArgumentNullException(
                message: "Target cannot be null.",
                paramName: nameof(cParameters.Target));

        if (cParameters.Key == null)
            throw new ArgumentNullException(
                message: "In order to encrypt data, key must not be null.",
                paramName: nameof(cParameters.Key));

        if (File.Exists(cParameters.Target))
        {
            Exec.WriteLine($"[*] Encrypting 1 out of 1 file(s).");
            Encrypt(cParameters);
        }
        else if (Directory.Exists(cParameters.Target))
        {
            var pathFiles = Directory.GetFiles(cParameters.Target);
            for (int i = 0; i < pathFiles.Length; i++)
            {
                Exec.WriteLine($"[*] Encrypting {i + 1} out of {pathFiles.Length} file(s).");

                Encrypt(cParameters);
            }
        }
        else
        {
            throw new ArgumentException(message: "Target path is non-existent.");
        }
    }
    static string MergeSignatureAndData(ConsoleParameters cParameters)
    {
        if (string.IsNullOrWhiteSpace(cParameters.Target) || !File.Exists(cParameters.Target))
            throw new ArgumentException(
                message: "Target file must exists.",
                paramName: nameof(cParameters.Target));
        if (string.IsNullOrWhiteSpace(cParameters.SignatureFile) || !File.Exists(cParameters.SignatureFile))
            throw new ArgumentException(
                message: "Signature path must exists.",
                paramName: nameof(cParameters.SignatureFile));
        if (string.IsNullOrWhiteSpace(cParameters.Output) || !Directory.Exists(cParameters.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParameters.Output));
        if (cParameters.Key == null)
        {
            Exec.WriteLine("[*] Warning: Key not set, application can't verify signature file.");
            Exec.Write("[*] Do you want to continue? (y/n)");
            ConsoleKeyInfo cKey;
            do
            {
                cKey = Exec.ReadKey(true);
                if (cKey.Key == ConsoleKey.N)
                    return "";
            }
            while (cKey.Key != ConsoleKey.Y && cKey.Key != ConsoleKey.N);
            Exec.Write('\n');
        }

        if (cParameters.Verbose)
        {
            Exec.WriteLine("[*] Storing data in memory...");
            Exec.WriteLine("[*] Storing signature in memory...");
            _stopwatch.Restart();
        }

        string fileName = Path.GetFileNameWithoutExtension(cParameters.Target);
        string fileExt = Path.GetExtension(cParameters.Target);

        FileManipulation.OpenFile(cParameters.Target, out var data);
        FileManipulation.OpenFile(cParameters.SignatureFile, out var signature);
        if (cParameters.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time to store files {_stopwatch.ElapsedMilliseconds} ms");
        }

        byte[] mergedFile = new byte[signature.Length + data.Length];
        using (var ms = new MemoryStream(mergedFile))
        {
            ms.Write(signature, 0, signature.Length);
            ms.Write(data, 0, data.Length);
        }

        if (cParameters.Key?.VerifySignedData(data, signature, cParameters.HashAlgorithm) == false)
        {
            throw new InvalidDataException(
                message: "Signature is invalid for this key.");
        }

        Exec.WriteLine($"[*] Merged file saved at: {cParameters.Output}\\{fileName}.merged{fileExt}");
        FileManipulation.SaveFile(mergedFile, cParameters.Output, fileName + $".merged{fileExt}", true);
        return $"{cParameters.Output}\\{fileName}.merged{fileExt}";
    }
    static void UnmergeSignatureAndData(ConsoleParameters cParameters)
    {
        if (!File.Exists(cParameters.Target) || string.IsNullOrWhiteSpace(cParameters.Target))
            throw new ArgumentException(
                message: "Target file must exists.",
                paramName: nameof(cParameters.Target));
        if (string.IsNullOrWhiteSpace(cParameters.Output) || !Directory.Exists(cParameters.Output))
            throw new ArgumentException(
                message: "Invalid output path.",
                paramName: nameof(cParameters.Output));
        if (cParameters.Key == null)
            throw new NullReferenceException(
                message: "Key must not be null.");

        var rnd = new Random();
        byte[] b = new byte[4];
        rnd.NextBytes(b);

        // getting signature size based on key size
        // (not sure if correct)
        int signatureSize = EncryptionKeyPair.New(cParameters.Key.KeySize).SignData(b, cParameters.HashAlgorithm).Length;

        if (cParameters.Verbose)
        {
            Exec.WriteLine("[*] Storing file into memory...");
            Exec.WriteLine("[*] Spliting signature and data...");
            _stopwatch.Restart();
        }

        FileManipulation.OpenFile(cParameters.Target, out var file);

        byte[] signature = new byte[signatureSize];
        byte[] data = new byte[file.Length - signatureSize];

        using (var ms = new MemoryStream(file))
        {
            ms.Read(signature, 0, signatureSize);
            ms.Read(data, 0, data.Length);
        }

        if (!cParameters.Key.VerifySignedData(data, signature, cParameters.HashAlgorithm))
            throw new InvalidDataException(
                message: "Signature is not valid or do not exist for this file.");
        else
            Exec.WriteLine($"[*] Contains a valid {cParameters.HashAlgorithm} signature.");

        if (cParameters.Verbose)
        {
            _stopwatch.Stop();
            Exec.WriteLine($"[*] Elapsed time {_stopwatch.ElapsedMilliseconds} ms");
        }

        string fileName = Path.GetFileNameWithoutExtension(cParameters.Target)
                .Replace(".merged", "");
        string fileExt = Path.GetExtension(cParameters.Target);
        string signatureFileName = $"unmerged.{fileName}.{cParameters.HashAlgorithm}";
        string dataFileName = $"unmerged.{fileName}{fileExt}";

        Exec.WriteLine($"[*] Saving signature as: {cParameters.Output}\\{signatureFileName}");
        Exec.WriteLine($"[*] Saving data as: {cParameters.Output}\\{dataFileName}");
        FileManipulation.SaveFile(signature, cParameters.Output, signatureFileName);
        FileManipulation.SaveFile(data, cParameters.Output, dataFileName);
    }


    static void ShowVersion()
    {
        var assembly = Assembly.GetEntryAssembly().GetName();
        Exec.WriteLine($"v{assembly.Version}");
        return;
    }

    static void ShowHelp(OptionSet opts)
    {
        Exec.WriteLine($"Usage: {_exeName} [OPTIONS]");
        Exec.WriteLine("Generates key pair and encrypted key pair.");
        Exec.WriteLine("Encrypts, decrypts, sign or verify signatures.");
        Exec.WriteLine("Options:");
        opts.WriteOptionDescriptions(Exec.Out);
    }

    static void ShowExamples(OptionSet opts)
    {
        ShowHelp(opts);
        Exec.Write("\n\n");
        Exec.WriteLine("Examples:\n");
        Exec.WriteLine($" Encrypting: [{_exeName} -e -t=.\\myfile.pdf -k=.\\pub.key.pem]\n\tEncrypts target data using default output.");
        Exec.WriteLine($" Decrypting: [{_exeName} -d -t=.\\myfile.encrypted.pdf -o=.\\ -k=.\\priv.key.pem --verbose]\n\tDecrypts specified file on specified output using selected key with increase verbosity.");
        Exec.WriteLine($" Generating new key with chosen size and name: [{_exeName} -n --keysize=1024 --keyfilename=my_1024_key -o=.]\\\n\tGenerates a new key with specified name and size at selected path.");
        Exec.WriteLine($" Generating new encrypted key: [{_exeName} -n -p]\n\tGenerates a new encrypted key using default values.");
        Exec.WriteLine($" Signing: [{_exeName} -s --hashalg=SHA512 -t=.\\myfile.docx -k=.\\priv.key.pem]\n\tSigns the selected file using default output with specified private key and chosen hashing algorithm. (if hash algorithm has not been default will be SHA256)");
        Exec.WriteLine($" Verifying signature: [{_exeName} -v -t=.\\myfile.txt --signaturefile=.\\myfile.signature.txt -k=.\\pub.key.pem]\n\tChecks if signature file is valid. (if hash algorithm has not been chosen default will be SHA256)");
    }
}