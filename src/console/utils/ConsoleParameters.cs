public class ConsoleParameters
{
    private EConsoleActions _action = EConsoleActions.None;

    public bool IsAction => _action != EConsoleActions.None;
    public bool IsGenerateKey => _action == EConsoleActions.GenerateNewKey;

    public bool Help { get => _action == EConsoleActions.Help; set => _action = EConsoleActions.Help; }
    public bool Encrypt { get => _action == EConsoleActions.Encrypt; set => _action = EConsoleActions.Encrypt; }
    public bool Decrypt { get => _action == EConsoleActions.Decrypt; set => _action = EConsoleActions.Decrypt; }
    public bool Merge { get => _action == EConsoleActions.Merge; set => _action = EConsoleActions.Merge; }
    public bool NewKey { get => _action == EConsoleActions.GenerateNewKey; set => _action = EConsoleActions.GenerateNewKey; }
    public bool Sign { get => _action == EConsoleActions.Sign; set => _action = EConsoleActions.Sign; }
    public bool Unmerge { get => _action == EConsoleActions.Unmerge; set => _action = EConsoleActions.Unmerge; }
    public bool VerifySignature { get => _action == EConsoleActions.VerifySignature; set => _action = EConsoleActions.VerifySignature; }
    public bool Examples { get => _action == EConsoleActions.Examples; set => _action = EConsoleActions.Examples; }
    public bool Version { get => _action == EConsoleActions.Version; set => _action = EConsoleActions.Version; }
    
    public string Output { get; set; }
        = Environment.CurrentDirectory;
    public bool Password { get; set; } = false;
    public string Target { get; set; }
        = Path.Combine(Environment.CurrentDirectory, "sample");
    public string HashAlgorithm { get; set; } = "SHA256";
    public string KeyFileName { get; set; } = "sample.key";
    public int KeySize { get; set; } = 2048;
    public string SignatureFile { get; set; } = "";
    public bool Verbose { get; set; } = false;
    public bool PasswordProtected { get; set; } = false;

    public OptionSet GetOptions()
    {
        return new OptionSet
        {
            { "d|decrypt", "decrypts the encrypted data, requires private key \n[ACTION]",
                v => this.Decrypt = v != null },
            { "e|encrypt", "encrypts the data, if used with -s merge signature to encrypted file \n[ACTION]",
                v => this.Encrypt = v != null },
            { "h|help", "show this message and exit \n[ACTION]",
                v => this.Help = v != null },
            { "k|key=", "key to use",
                v => this.KeyFileName = v },
            { "m|merge", "merge signature with another file, use --signaturefile, warns if no key was specified\n[ACTION]",
                v => this.Merge = true },
            { "n|newkey", "generates a new RSA Key, default size is 2048bits, exports as .pem files by default \n[ACTION]",
                v => this.NewKey = true },
            { "o|output=", "path to output encrypted files",
                v => this.Output = v },
            { "p|password", "when generating/using a new key use this flag to set password. when using this flag must always be a private key.",
                v => this.PasswordProtected = true
            },
            { "s|sign", "signs data, requires private key \n[ACTION]",
                v => this.Sign = v != null },
            { "t|target=", "file or directory to be encrypted, decrypted or to verify its signature if directory encrypts all file from that directory",
                v => this.Target = v },
            { "u|unmerge", "unmerge signature from file, requires public key used in signature, use --hashalg to identify wich hashing algorithm was used and verify signature (if none was specified uses default: SHA256)\n[ACTION]",
                v => this.Unmerge = true },
            { "v|verifysignature", "verify if signed data is trustworthy \n[ACTION], use --target for signed data and --signaturefile for signature file",
                v => this.VerifySignature = v != null },
            { "x|examples", "show specific examples \n[ACTION]",
                v => this.Examples = v != null },
            { "hashalg=", "type of hashing algorithm, examples: SHA1, SHA256. default value is SHA256",
                v => this.HashAlgorithm = v },
            { "keyfilename=", "when generating a new key use this to choose file name, default is \"key\"",
                v => this.KeyFileName = v) },
            { "keysize=", "when generating key use this to choose its size, minimum size is 384 and maximum is 16384, key size must be in increments of 8 bits.",
                (int v) => this.KeySize = v },
            { "signaturefile=", "signature file generated based on encrypted file",
                v => this.SignatureFile = v },
            { "verbose", "increase debug message verbosity",
                v => this.Verbose = v != null },
            { "version", "shows version \n[ACTION]",
                v => this.Version = v != null },
        };
    }
}