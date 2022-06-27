using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SwaggerUIwithJWTsupport;

public class AuthConfiguration
{
    private SymmetricSecurityKey Key { get; set; }
    private static AuthConfiguration? Instance { get; set; }
    private static string Issuer { get; set; }
    private static string Audience { get; set; }
    public AuthConfiguration()
    {
        Key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("z1kPaiRR77Lo4D1wGvL4nWqvNa5VB1sCbEbCDnO"));
        Issuer ="AuthApi";
        Audience = "https://localhost";
    }

    public AuthConfiguration GetInstance()
    {
        return Instance ?? new AuthConfiguration();
    }

    public SymmetricSecurityKey GetKey()
    {
        return Key;
    }
    public string GetIssuer()
    {
        return Issuer;
    }
    public string GetAudience()
    {
        return Audience;
    }
}