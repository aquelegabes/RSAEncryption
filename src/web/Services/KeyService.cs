namespace RSAEncryption.Web.Services;

public class KeyService
{
    protected EncryptionKeyPair Key { get; private set; }
    protected ReadOnlyMemory<char> KeyPassword { get; private set;}

    public EncryptionKeyPair GetKey() => this.Key;
    public void NewKey(
        string keyPassword = "",
        int keySize = 2048)
    {
        this.Key = EncryptionKeyPair.New(keySize);
        this.KeyPassword = keyPassword.AsMemory();
    }
}