namespace RSAEncryption.Web.Services;

public class KeyService
{
    protected EncryptionKeyPair Key { get; private set; }

    protected byte[] PEMPublicKeyAsByteArray()
        => Key.AsByteArray(EKeyType.PEM);
    protected byte[] PEMPrivateKeyAsByteArray(ReadOnlySpan<char> keyPassword)
        => Key.AsByteArray(EKeyType.PEM, keyPassword);
    protected byte[] PKCSKeyAsByteArray(ReadOnlySpan<char> keyPassword)
        => Key.AsByteArray(EKeyType.PKCS8, keyPassword);
    protected byte[] BlobKeyAsByteArray()
        => Key.AsByteArray(EKeyType.BlobString);

    public void NewKey(
        ReadOnlySpan<char> keyPassword = default,
        int keySize = 2048)
    {
        this.Key = EncryptionKeyPair.New(keySize);
    }

    public void ImportKey(
        EKeyType keyType,
        byte[] keyContent,
        ReadOnlySpan<char> keyPassword = default,
        bool isPrivate = false
    )
    {
        this.Key = EncryptionKeyPair.ImportKey(keyType, keyContent, keyPassword);
    }

    public string GetKey(
        EKeyType keyType,
        ReadOnlySpan<char> keyPassword = default,
        bool includePrivate = false)
    {
        switch (keyType)
        {
            case EKeyType.BlobString:
            {
                return this.BlobKeyAsByteArray().AsEncodedString();
            }
            case EKeyType.PKCS8:
            {
                return this.PKCSKeyAsByteArray(keyPassword).AsEncodedString();
            }
            case EKeyType.PEM:
            {
                return includePrivate ?
                    this.PEMPrivateKeyAsByteArray(keyPassword).AsEncodedString()
                    : this.PEMPublicKeyAsByteArray().AsEncodedString();
            }
            default:
            {
                throw new ArgumentException(
                    paramName: nameof(keyType),
                    message: "A key type must be selected."
                );
            }
        }
    }
}