using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JayLabs.Owin.OAuthAuthorization.Tokens;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class CustomProviderOptions
    {
        readonly JwtOptions _jwtOptions;
        readonly HandleConsentOptions _handleConsentOptions;
        Func<ClaimsPrincipal, Task<ClaimsIdentity>> _transformPrincipal;

        public CustomProviderOptions(JwtOptions jwtOptions, HandleConsentOptions handleConsentOptions)
        {
            if (jwtOptions == null)
            {
                throw new ArgumentNullException("jwtOptions");
            }

            if (handleConsentOptions == null)
            {
                throw new ArgumentNullException("handleConsentOptions");
            }

            _jwtOptions = jwtOptions;
            _handleConsentOptions = handleConsentOptions;
        }

        public Func<ClaimsPrincipal, Task<ClaimsIdentity>> TransformPrincipal
        {
            get { return _transformPrincipal ?? (principal => Task.FromResult(principal.Identities.FirstOrDefault())); }
            set { _transformPrincipal = value; }
        }

        public JwtOptions JwtOptions
        {
            get { return _jwtOptions; }
        }

        public HandleConsentOptions HandleConsentOptions
        {
            get { return _handleConsentOptions; }
        }
    }
}