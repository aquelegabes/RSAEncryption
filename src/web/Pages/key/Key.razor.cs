namespace RSAEncryption.Web.Pages;
public partial class Key : ComponentBase
{
    public string KeyFileName { get; set; } = Guid.NewGuid().ToString();
    public string KeyPassword { get; set; } = "";
    public int KeySize { get; set; } = 2048;
    public string KeyAsBlob { get; set; } = "";

    [Inject]
    private KeyService _keyService { get; set; }

    public void GenerateNewKey() 
    {
        _keyService.NewKey(KeyPassword, KeySize);
        KeyAsBlob = _keyService.GetKey(EKeyType.BlobString, KeyPassword);
    }
}