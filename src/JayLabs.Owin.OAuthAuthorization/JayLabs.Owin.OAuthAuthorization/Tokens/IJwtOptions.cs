namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public interface IJwtOptions
    {
        string JwtSigningKeyAsUtf8 { get; }
        string Issuer { get; }
        string Audience { get; }
        string JwtTokenHeader { get; }
    }
}