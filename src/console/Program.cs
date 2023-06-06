namespace RSAEncryption.Console;
public static partial class Program
{
    private static readonly Stopwatch _stopwatch = new Stopwatch();
    private static readonly string _exeName =
        Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);

    public static void Main(string[] args)
    {
        Exec.WriteLine($"[*] Starting {_exeName}...");

        var cParams = new ConsoleParameters();
        var opts = cParams.GetOptions();

        try
        {
            List<string> extra = opts.Parse(args);

            // show help when no args, not defined opts
            //   missing action option, show help
            //   when key is null and is not newkey/merge
            if (cParams.Help || args == null || extra?.Count > 0 || !cParams.IsAction ||
                (string.IsNullOrWhiteSpace(cParams.KeyFileName)))
            {
                ShowHelp(opts);
                return;
            }

            if (cParams.GetCurrentAction() == EConsoleActions.Examples)
            {
                ShowExamples(opts);
                return;
            }

            if (cParams.GetCurrentAction() == EConsoleActions.Version)
            {
                ShowVersion();
                return;
            }

            if (cParams.PasswordProtected)
            {
                Exec.Write("[*] Encrypted Key Password: ");
                while (true)
                {
                    var cKey = Exec.ReadKey(true);
                    if (cKey.Key != ConsoleKey.Backspace && cKey.Key != ConsoleKey.Enter &&
                        cKey.Key != ConsoleKey.Escape && cKey.KeyChar != '\0')
                    {
                        cParams.Password += cKey.KeyChar;
                    }
                    else if (cKey.Key == ConsoleKey.Backspace && cParams.Password.Length > 0)
                    {
                        cParams.Password = cParams.Password[0..^1];
                    }
                    else if (cKey.Key == ConsoleKey.Enter)
                    {
                        Exec.Write('\n');
                        break;
                    }
                }
            }
            
            if (cParams.PasswordProtected)
                cParams.Key = EncryptionKeyPair.ImportPKCS8(cParams.Password, cParams.KeyFileName);
            else
                cParams.Key = EncryptionKeyPair.ImportPEMFile(cParams.KeyFileName);

            if (cParams.GetCurrentAction() == EConsoleActions.Encrypt)
            {
                EncryptOption(cParams);
                return;
            }
            if (cParams.Sign)
            {
                Exec.WriteLine("[*] Warning: Some hashing algorithms may have issues depending on the key size");
                Sign(cParams);
                return;
            }
            if (cParams.VerifySignature)
            {
                VerifySignature(cParams);
                return;
            }
            if (cParams.Decrypt)
            {
                DecryptOption(cParams);
                return;
            }
            if (cParams.Merge)
            {
                MergeSignatureAndData(cParams);
                return;
            }
            if (cParams.Unmerge)
            {
                UnmergeSignatureAndData(cParams);
                return;
            }
            if (cParams.NewKey)
            {
                GenerateKey(cParams);
                return;
            }
        }
        catch (Exception e)
        {
            Exec.Write($"[*] {_exeName}: ");
            Exec.WriteLine(e.Message.Contains("inner") ? e.InnerException.Message : e.Message);
            Exec.WriteLine($"[*] Try '{_exeName} --help' for more information or --examples");
            return;
        }
    }
}