public class MergeTests
{
    [Fact]
    public void Merge_ArgumentExc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders);

        string output = testFolders["encrypted"];
        var pubKey = EncryptionKeyPair.ImportPEMFile($"{Setup.AbsolutePath}\\pub.key.pem");
        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams1 = new ConsoleParameters()
        {
            Target = null,
            SignatureFile = signatureFilePath,
            Key = pubKey,
            Output = output,
        };
        var cParams2 = new ConsoleParameters()
        {
            Target = originalFilePath,
            SignatureFile = null,
            Key = pubKey,
            Output = output,
        };
        var cParams3 = new ConsoleParameters()
        {
            Target = originalFilePath,
            SignatureFile = signatureFilePath,
            Key = pubKey,
            Output = null,
        };

        // invalid data path
        Assert.Throws<ArgumentException>(()
            => Program.MergeSignatureAndData(cParams1));

        // invalid signature path
        Assert.Throws<ArgumentException>(()
            => Program.MergeSignatureAndData(cParams2));

        // invalid output path
        Assert.Throws<ArgumentException>(()
            => Program.MergeSignatureAndData(cParams3));
    }

    [Fact]
    public void Merge_NullKey_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders);

        string output = testFolders["encrypted"];
        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = originalFilePath,
            SignatureFile = signatureFilePath,
            Key = null,
            Output = output,
        };

        Assert.Throws<NullReferenceException>(()
            => Program.MergeSignatureAndData(cParams));
    }

    [Fact]
    public void Merge_InvalidSignature_Exc()
    {
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders);

        string output = testFolders["encrypted"];
        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = originalFilePath,
            SignatureFile = originalFilePath,
            Key = Setup.PublicKey,
            Output = output,
        };

        Assert.Throws<InvalidDataException>(()
            => Program.MergeSignatureAndData(cParams));
    }

    [Fact]
    public void Main_Merge_Verbosity_OK()
    {
        const string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders);

        string output = testFolders["encrypted"];
        var publicKeyPath = $"{Setup.AbsolutePath}\\pub.key.pem";
        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["original"])[0]);
        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.{hashalg}*")[0];

        var args = new string[]
        {
            "--merge", "--verbose", $"--hashalg={hashalg}",
            $"--output={output}",
            $"--key={publicKeyPath}",
            $"--target={originalFilePath}",
            $"--signaturefile={signatureFilePath}",
        };

        Program.Main(args);

        string outputFilePath = Directory.GetFiles(output, "*merge*")[0];

        Assert.False(string.IsNullOrWhiteSpace(outputFilePath));
    }
}