namespace RSAEncryption.Console.Test;
public class EtcTests
{
    [Fact]
    public void Main_ShowHelp()
    {
        string[] args = new string[] { "--help" };

        try
        {
            Program.Main(args);
        }
        catch (Exception e)
        {
            throw new XunitException($"Expected no errors but got: {e.Message}");
        }
    }

    [Fact]
    public void Main_ShowVersion()
    {
        string[] args = new string[] { "--version" };

        try
        {
            Program.Main(args);
        }
        catch (Exception e)
        {
            throw new XunitException($"Expected no errors but got: {e.Message}");
        }
    }

    [Fact]
    public void Main_ShowExamples()
    {
        string[] args = new string[] { "--examples" };

        try
        {
            Program.Main(args);
        }
        catch (Exception e)
        {
            throw new XunitException($"Expected no errors but got: {e.Message}");
        }
    }
}