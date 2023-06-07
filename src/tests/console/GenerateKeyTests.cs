namespace RSAEncryption.Console.Test;
public class GenerateKeyTests
{
    [Theory]
    [InlineData("key_2048", 2048)]
    [InlineData("key_4096", 4096)]
    public void Main_GenerateKey_CustomName_Verbosity_OK(string keyName, int keySize)
    {
        string privateKeyPath = Path.Combine(Setup.AbsolutePath, $"priv.{keyName}.pem");
        string publicKeyPath = Path.Combine(Setup.AbsolutePath, $"pub.{keyName}.pem");

        string[] args = new string[]
        {
            "--newkey",
            "--verbose",
            $"--keysize={keySize}",
            $"--keyfilename={keyName}",
            $"--output={Setup.AbsolutePath}"
        };

        Program.Main(args);

        Assert.True(File.Exists(privateKeyPath));
        Assert.True(File.Exists(publicKeyPath));
    }

    [Fact]
    public void GenerateKey_DefaultName_Verbosity_OK()
    {
        string privateKeyPath = Path.Combine(Setup.AbsolutePath, "priv.key.pem");
        string publicKeyPath = Path.Combine(Setup.AbsolutePath, "pub.key.pem");

        var cParams = new ConsoleParameters()
        {
            KeySize = 2048,
            Output = Setup.AbsolutePath,
            Verbose = true
        };

        Program.GenerateKey(cParams);

        Assert.True(File.Exists(privateKeyPath));
        Assert.True(File.Exists(publicKeyPath));
    }

    [Theory]
    [InlineData("2uto64", "enckey1")]
    [InlineData("10oik6", "enckey2")]
    public void GenerateKey_Encrypted_Verbosity_OK(string passwd, string keyName)
    {
        string encFile = Path.Combine(Setup.AbsolutePath, $"enc.{keyName}.pem");
        string pubFile = Path.Combine(Setup.AbsolutePath, $"pub.{keyName}.pem");

        var cParams = new ConsoleParameters()
        {
            KeySize = 2048,
            Output = Setup.AbsolutePath,
            Verbose = true,
            KeyFileName = keyName,
            Password = passwd
        };

        Program.GenerateKey(cParams);

        Assert.True(File.Exists(encFile));
        Assert.True(File.Exists(pubFile));
    }
}