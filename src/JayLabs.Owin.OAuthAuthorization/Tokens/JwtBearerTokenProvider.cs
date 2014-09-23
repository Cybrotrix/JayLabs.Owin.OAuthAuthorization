using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public class JwtBearerTokenProvider : AuthenticationTokenProvider
    {
        readonly JwtOptions _options;

        public JwtBearerTokenProvider(JwtOptions options)
        {
            _options = options;
        }

        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var tokenValidator = new TokenValidator();

            ClaimsPrincipal principal = tokenValidator.Validate(context.Token, _options);

            context.SetTicket(new AuthenticationTicket((ClaimsIdentity)principal.Identity,
                new AuthenticationProperties()));

            return base.ReceiveAsync(context);
        }
    }
}