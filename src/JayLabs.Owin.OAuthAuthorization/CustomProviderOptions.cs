using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JayLabs.Owin.OAuthAuthorization.Tokens;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class CustomProviderOptions : IJwtOptions
    {
        Func<ClaimsPrincipal, Task<ClaimsIdentity>> _transformPrincipal;

        public CustomProviderOptions(IJwtOptions jwtOptions)
        {
            JwtSigningKeyAsUtf8 = jwtOptions.JwtSigningKeyAsUtf8;
            Issuer = jwtOptions.Issuer;
            Audience = jwtOptions.Audience;
            JwtTokenHeader = jwtOptions.JwtTokenHeader;
            SupportedScope = jwtOptions.SupportedScope;
        }
        
        public Func<ClaimsPrincipal, Task<ClaimsIdentity>> TransformPrincipal
        {
            get { return _transformPrincipal ?? (principal => Task.FromResult(principal.Identities.FirstOrDefault())); }
            set { _transformPrincipal = value; }
        }

        public string JwtSigningKeyAsUtf8 { get; private set; }
        public string Issuer { get; private set; }
        public string Audience { get; private set; }
        public string JwtTokenHeader { get; private set; }
        public string SupportedScope { get; private set; }

    }
}