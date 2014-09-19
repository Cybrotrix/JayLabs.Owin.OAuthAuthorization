using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JayLabs.Owin.OAuthAuthorization.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        readonly IJwtOptions _jwtOptions;
        readonly CustomProviderOptions _options;

        public CustomOAuthProvider(CustomProviderOptions options, IJwtOptions jwtOptions)
        {
            _options = options;
            _jwtOptions = jwtOptions;
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            Uri uri;
            if (Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out uri))
            {
                context.Validated();

                return Task.FromResult(0);
            }
            return base.ValidateClientRedirectUri(context);
        }

        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            string uri = context.Request.Uri.ToString();

            CheckScope(context, _options.SupportedScope);

            if (context.IsRequestCompleted)
            {
                return;
            }

            if (!context.Request.Method.Equals("POST", StringComparison.InvariantCultureIgnoreCase))
            {
                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = uri});
                return;
            }

            IFormCollection formCollection = await context.Request.ReadFormAsync();

            string externalWrappedJwtTokenAsBase64 = formCollection.Get(_jwtOptions.JwtTokenHeader);

            if (string.IsNullOrWhiteSpace(externalWrappedJwtTokenAsBase64))
            {
                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = uri});
                return;
            }

            bool accepted = "accepted".Equals((formCollection.Get("consent") ?? ""),
                StringComparison.InvariantCultureIgnoreCase);

            if (!accepted)
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "resource owner denied request");
                return;
            }

            var tokenValidator = new TokenValidator();
            ClaimsPrincipal principal = tokenValidator.Validate(externalWrappedJwtTokenAsBase64, _jwtOptions);

            if (!principal.Identity.IsAuthenticated)
            {
                return;
            }

            ClaimsIdentity claimsIdentity = await _options.TransformPrincipal(principal);

            if (!claimsIdentity.Claims.Any())
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "unauthorized user");

                return;
            }

            string appJwtTokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(claimsIdentity.Claims, _jwtOptions)
                    .CreateTokenAsBase64();

            var builder = new UriBuilder(context.AuthorizeRequest.RedirectUri);

            const string tokenType = "bearer";
            builder.Fragment = string.Format("access_token={0}&token_type={1}&state={2}&scope={3}",
                Uri.EscapeDataString(appJwtTokenAsBase64), Uri.EscapeDataString(tokenType),
                Uri.EscapeDataString(context.AuthorizeRequest.State),
                Uri.EscapeDataString(_options.SupportedScope));

            string redirectUri = builder.Uri.ToString();

            context.Response.Redirect(redirectUri);
            context.RequestCompleted();
        }

        void CheckScope(OAuthAuthorizeEndpointContext context, string supportedScope)
        {
            if (context.AuthorizeRequest.Scope.Any() &&
                !context.AuthorizeRequest.Scope.Any(scope => scope.Equals(supportedScope)))
            {
                string errorDescription = string.Format("only {0} scope is supported", supportedScope);
                Error(context, OAuthImplicitFlowError.Scope, errorDescription);
            }
        }

        void Error(OAuthAuthorizeEndpointContext context, OAuthImplicitFlowError error, string errorDescription)
        {
            var builder = new UriBuilder(context.AuthorizeRequest.RedirectUri);

            var fragmentBuilder = new StringBuilder();

            fragmentBuilder.AppendFormat("error={0}", Uri.EscapeDataString(error.InvariantName));

            if (!string.IsNullOrWhiteSpace(errorDescription))
            {
                fragmentBuilder.AppendFormat("&error_description={0}", Uri.EscapeDataString(errorDescription));
            }
            if (!string.IsNullOrWhiteSpace(context.AuthorizeRequest.State))
            {
                fragmentBuilder.AppendFormat("&state={0}", Uri.EscapeDataString(context.AuthorizeRequest.State));
            }

            builder.Fragment = fragmentBuilder.ToString();

            string redirectUriWithFragments = builder.Uri.ToString();

            context.Response.Redirect(redirectUriWithFragments);
            context.RequestCompleted();
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters.Get("client_id")))
            {
                return base.ValidateClientAuthentication(context);
            }
            return Task.FromResult(0);
        }
    }
}