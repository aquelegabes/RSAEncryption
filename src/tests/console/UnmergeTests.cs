namespace RSAEncryption.Console.Test; 
public class UnmergeTests
{
    [Fact]
    public void Unmerge_ArgumentExc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetMergedFile(testFolders, hashalg);

        string output = testFolders["encrypted"];
        string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], "*merge*")[0];

        var cParams1 = new ConsoleParameters()
        {
            Target = null,
            Key = Setup.PrivateKey,
            Output = output,
            HashAlgorithm = hashalg
        };
        var cParams2 = new ConsoleParameters()
        {
            Target = mergedFilePath,
            Key = Setup.PrivateKey,
            Output = null,
            HashAlgorithm = hashalg
        };

        // invalid target
        Assert.Throws<ArgumentException>(()
            => Program.UnmergeSignatureAndData(cParams1));

        // invalid output
        Assert.Throws<ArgumentException>(()
            => Program.UnmergeSignatureAndData(cParams2));
    }

    [Fact]
    public void Unmerge_NullKey_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetMergedFile(testFolders, hashalg);

        string output = testFolders["encrypted"];
        string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], $"*merge*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = mergedFilePath,
            Key = null,
            Output = output,
            HashAlgorithm = hashalg
        };

        // using public key
        Assert.Throws<NullReferenceException>(()
            => Program.UnmergeSignatureAndData(cParams));
    }

    [Fact]
    public void Unmerge_InvalidSignature_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetMergedFile(testFolders, hashalg);

        string output = testFolders["encrypted"];
        // not a merged file
        string mergedFilePath = Directory.GetFiles(testFolders["encrypted"])[0];

        var cParams = new ConsoleParameters()
        {
            Target = mergedFilePath,
            Key = Setup.PrivateKey,
            Output = output,
            HashAlgorithm = hashalg
        };

        Assert.Throws<InvalidDataException>(()
            => Program.UnmergeSignatureAndData(cParams));
    }

    [Fact]
    public void Main_Unmerge_Verbosity_OK()
    {
        const string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetMergedFile(testFolders, hashalg);

        string output = testFolders["encrypted"];
        string keyPath = $"{Setup.AbsolutePath}\\pub.key.pem";
        string mergedFilePath = Directory.GetFiles(testFolders["encrypted"], "*merge*")[0];
        string mergedFileName = Path.GetFileNameWithoutExtension(mergedFilePath).Replace(".merged","");

        var args = new string[]
        {
            "--unmerge", "--verbose",
            $"--output={output}",
            $"--hashalg={hashalg}",
            $"--target={mergedFilePath}",
            $"--key={keyPath}"
        };

        Program.Main(args);

        string outputDataFilePath = Directory.GetFiles(testFolders["encrypted"], $"unmerged.{mergedFileName}.txt")[0];
        string outputSignatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"unmerged.{mergedFileName}.{hashalg}*")[0];

        Assert.False(string.IsNullOrWhiteSpace(outputDataFilePath));
        Assert.False(string.IsNullOrWhiteSpace(outputSignatureFilePath));
    }
}