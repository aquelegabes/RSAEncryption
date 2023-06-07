namespace RSAEncryption.Core.Tests;
public class KeyTests
{
    [Fact]
    public void PEM_AsByteArray()
    {
        var key = EncryptionKeyPair.New(2048);
        var fileContents = key.AsByteArray(EKeyType.PEM);

        Assert.True(fileContents is not null);
    }
}