namespace RSAEncryption.Web.Pages;
public partial class Key : ComponentBase
{
    public string KeyFileName { get; set; } = Guid.NewGuid().ToString();
    public string KeyPassword { get; set; } = "";
    public int KeySize { get; set; } = 2048;
    public string KeyContents { get; set; } = "";

    [Inject]
    private KeyService _keyService { get; set; }

    public void GenerateNewKey() 
    {
        _keyService.NewKey(KeyPassword, KeySize);
        KeyContents = _keyService.GetKey(EKeyType.PEM, KeyPassword);
    }
}