namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public class JwtOptions
    {
        public string JwtSigningKeyAsUtf8 { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string JwtTokenParameterName { get; set; }
        public string SupportedScope { get; set; }
    }
}