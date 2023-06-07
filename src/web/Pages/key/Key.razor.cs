namespace RSAEncryption.Web.Pages;
public partial class Key : ComponentBase
{
    public string KeyFileName { get; set; } = Guid.NewGuid().ToString();
    public string KeyPassword { get; set; } = "";
    public int KeySize { get; set; } = 2048;

    public async Task GenerateKey()
    {
        throw new NotImplementedException();
    }
}