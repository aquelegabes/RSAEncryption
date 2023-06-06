public class DecryptingTests
{
    [Fact]
    public void Main_Decrypting_SingleFile_Verbosity_OK()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string outputFilePath = Path.Combine(
            path1: testFolders["decrypted"],
            path2: Path.GetFileNameWithoutExtension(originalFilePath) + ".decrypted.txt");
        string targetFilePath = Path.Combine(
            path1: testFolders["encrypted"],
            path2: Path.GetFileNameWithoutExtension(originalFilePath) + ".encrypted.txt");

        string[] args =
        {
            "-d", "--verbose",
            $@"--key={Setup.AbsolutePath}\priv.key.pem",
            $"--output={testFolders["decrypted"]}",
            $"--target={targetFilePath}",
        };

        Program.Main(args);

        Assert.True(File.Exists(outputFilePath));

        FileManipulation.OpenFile(outputFilePath, out var outputFile);
        Assert.NotNull(outputFile);

        FileManipulation.OpenFile(originalFilePath, out var originalFile);
        Assert.NotNull(originalFile);

        Assert.Equal(outputFile.Length, originalFile.Length);
        Assert.Equal(outputFile, originalFile);
    }

    [Fact]
    public void Main_Decrypting_MultipleFile_Verbosity_OK()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders, true);

        string[] originalFilesPath = Directory.GetFiles(testFolders["original"]);
        string[] targetFilesPath = Directory.GetFiles(testFolders["encrypted"], "*encrypt*");

        Array.Sort(targetFilesPath);

        string[] args =
        {
            "-d", "--verbose",
            $@"--key={Setup.AbsolutePath}\priv.key.pem",
            $"--output={testFolders["decrypted"]}",
            $"--target={testFolders["encrypted"]}",
        };

        Program.Main(args);

        string[] outputFilesPath = Directory.GetFiles(testFolders["decrypted"]);
        Array.Sort(outputFilesPath);

        Assert.Equal(outputFilesPath.Length, originalFilesPath.Length);

        for (int i = 0; i < targetFilesPath.Length; i++)
        {
            FileManipulation.OpenFile(outputFilesPath[i], out var outputFile);
            Assert.NotNull(outputFile);

            FileManipulation.OpenFile(originalFilesPath[i], out var originalFile);
            Assert.NotNull(originalFile);

            Assert.Equal(outputFile.Length, originalFile.Length);
            Assert.Equal(outputFile, originalFile);
        }
    }

    [Fact]
    public void Decrypting_NonExistentTarget_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        string targetFilePath = $@"{testFolders["original"]}\nonexisting.txt";

        var cParams = new ConsoleParameters()
        {
            Target = targetFilePath,
            Key = Setup.PrivateKey,
            Output = testFolders["encrypted"],
            Verbose = false
        };


        Assert.Throws<ArgumentException>(()
            => Program.DecryptOption(cParams));
    }

    [Fact]
    public void Decrypting_OutputInvalid_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        string targetFilePath = Directory.GetFiles(testFolders["encrypted"])[0];

        var cParams = new ConsoleParameters()
        {
            Target = targetFilePath,
            Key = Setup.PrivateKey,
            Output = @$"{Setup.AbsolutePath}\invalidpath",
            Verbose = false
        };

        Assert.Throws<ArgumentException>(()
            => Program.DecryptOption(cParams));
    }

    [Fact]
    public void Decrypting_TargetNull_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        var cParams = new ConsoleParameters()
        {
            Target = "",
            Key = Setup.PrivateKey,
            Output = testFolders["encrypted"],
            Verbose = false
        };

        Assert.Throws<ArgumentNullException>(()
            => Program.DecryptOption(cParams));
    }

    [Fact]
    public void Decrypting_NullKey_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        string targetFilePath = Directory.GetFiles(testFolders["encrypted"])[0];

        var cParams = new ConsoleParameters()
        {
            Target = targetFilePath,
            Key = null,
            Output = testFolders["encrypted"],
            Verbose = false
        };

        Assert.Throws<ArgumentNullException>(()
            => Program.DecryptOption(cParams));
    }

    [Fact]
    public void Decrypting_UsingPublicKey_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetEncryptedFiles(testFolders);

        string targetFilePath = Directory.GetFiles(testFolders["encrypted"])[0];
        var key = EncryptionKeyPair.ImportPEMFile($@"{Setup.AbsolutePath}\pub.key.pem");

        var cParams = new ConsoleParameters()
        {
            Target = targetFilePath,
            Key = Setup.PublicKey,
            Output = testFolders["decrypted"],
            Verbose = false
        };

        Assert.NotNull(key);

        Assert.Throws<InvalidOperationException>(()
            => Program.DecryptOption(cParams));
    }
}