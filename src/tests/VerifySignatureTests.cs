public class VerifySignatureTests
{
    [Fact]
    public void Main_VerifySignature_Verbosity_OK()
    {
        const string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string originalFilePath = Directory.GetFiles(testFolders["original"])[0];
        string fileName = Path.GetFileNameWithoutExtension(originalFilePath);
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.{hashalg}*")[0];

        string[] args =
        {
            "-v", $"--hashalg={hashalg}", "--verbose",
            $@"--key={Setup.AbsolutePath}\pub.key.pem",
            $"--target={originalFilePath}",
            $"--signaturefile={signatureFilePath}"
        };

        Program.Main(args);

        FileManipulation.OpenFile(originalFilePath, out var originalFile);
        FileManipulation.OpenFile(signatureFilePath, out var signatureFile);

        Assert.True(Setup.PublicKey.VerifySignedData(originalFile, signatureFile, hashalg));
    }

    [Fact]
    public void Main_VerifySignature_NotValidSignature_OK()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*")[0].Replace(".encrypted", ""));
        string originalFilePath = Directory.GetFiles(testFolders["original"]).Last();
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        string[] args =
        {
            "-v", $"--hashalg={hashalg}", "--verbose",
            $@"--key={Setup.AbsolutePath}\pub.key.pem",
            $"--target={originalFilePath}",
            $"--signaturefile={signatureFilePath}"
        };

        Program.Main(args);

        FileManipulation.OpenFile(originalFilePath, out var originalFile);
        FileManipulation.OpenFile(signatureFilePath, out var signatureFile);

        Assert.True(!Setup.PublicKey.VerifySignedData(originalFile, signatureFile, hashalg));
    }

    [Fact]
    public void VerifySignature_NullDataPath_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*")[0].Replace(".encrypted", ""));
        string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = "",
            Key = Setup.PublicKey,
            SignatureFile = signatureFilePath,
            Verbose = false
        };

        Assert.Throws<ArgumentNullException>(()
            => Program.VerifySignature(cParams));
    }

    [Fact]
    public void VerifySignature_NullSignedPath_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*")[0].Replace(".encrypted", ""));
        string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = originalFilePath,
            Key = Setup.PublicKey,
            SignatureFile = "",
            Verbose = false
        };

        Assert.Throws<ArgumentNullException>(()
            => Program.VerifySignature(cParams));
    }

    [Fact]
    public void VerifySignature_NullKey_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*")[0].Replace(".encrypted", ""));
        string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = originalFilePath,
            Key = null,
            SignatureFile = signatureFilePath,
            Verbose = false
        };

        Assert.Throws<NullReferenceException>(()
            => Program.VerifySignature(cParams));
    }

    [Fact]
    public void VerifySignature_FilesInexistent_Exc()
    {
        string hashalg = "SHA256";
        Setup.Initialize(out var testFolders);
        Setup.SetSignatureFile(testFolders, hashalg);

        string fileName = Path.GetFileNameWithoutExtension(Directory.GetFiles(testFolders["encrypted"], "*encrypt*")[0].Replace(".encrypted", ""));
        string originalFilePath = Directory.GetFiles(testFolders["original"], $"*{fileName}*").Last();
        string signatureFilePath = Directory.GetFiles(testFolders["encrypted"], $"*{fileName}.SHA256*")[0];

        var cParams = new ConsoleParameters()
        {
            Target = "inexistent",
            Key = Setup.PublicKey,
            SignatureFile = signatureFilePath,
            Verbose = false
        };

        Assert.Throws<ArgumentException>(()
            => Program.VerifySignature(cParams));
    }
}