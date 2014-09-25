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
        readonly CustomProviderOptions _options;

        public CustomOAuthProvider(CustomProviderOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            _options = options;
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

            if (string.IsNullOrWhiteSpace(_options.JwtOptions.SupportedScope))
            {
                Error(context, OAuthImplicitFlowError.ServerError, "no supported scope defined");
                return;
            }

            if (!HasSupportedScope(context, _options.JwtOptions.SupportedScope))
            {
                string errorDescription = string.Format("only {0} scope is supported",
                    _options.JwtOptions.SupportedScope);
                Error(context, OAuthImplicitFlowError.Scope, errorDescription);
                return;
            }

            string rawJwt = await TryGetRawJwtTokenAsync(context);

            if (string.IsNullOrWhiteSpace(rawJwt))
            {
                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = uri});
                return;
            }

            var tokenValidator = new TokenValidator();
            ClaimsPrincipal principal = tokenValidator.Validate(rawJwt, _options.JwtOptions);

            if (!principal.Identity.IsAuthenticated)
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "unauthorized user, unauthenticated");
                return;
            }

            ClaimsIdentity claimsIdentity = await _options.TransformPrincipal(principal);

            if (!claimsIdentity.Claims.Any())
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "unauthorized user");
                return;
            }

            ConsentAnswer consentAnswer = await TryGetConsentAnswerAsync(context.Request);

            if (consentAnswer == ConsentAnswer.Rejected)
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "resource owner denied request");
                return;
            }

            if (consentAnswer == ConsentAnswer.Missing)
            {
                Error(context, OAuthImplicitFlowError.ServerError,
                    "missing consent answer");
                return;
            }


            if (!(consentAnswer == ConsentAnswer.Accepted || consentAnswer == ConsentAnswer.Implicit))
            {
                Error(context, OAuthImplicitFlowError.ServerError,
                    string.Format("invalid consent answer '{0}'", consentAnswer.Display));
                return;
            }

            string appJwtTokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(claimsIdentity.Claims, _options.JwtOptions)
                    .CreateTokenAsBase64();

            var builder = new UriBuilder(context.AuthorizeRequest.RedirectUri);

            const string tokenType = "bearer";

            var fragmentStringBuilder = new StringBuilder();

            fragmentStringBuilder.AppendFormat("access_token={0}&token_type={1}&state={2}&scope={3}",
                Uri.EscapeDataString(appJwtTokenAsBase64), Uri.EscapeDataString(tokenType),
                Uri.EscapeDataString(context.AuthorizeRequest.State ?? ""),
                Uri.EscapeDataString(_options.JwtOptions.SupportedScope));

            if (consentAnswer == ConsentAnswer.Implicit)
            {
                fragmentStringBuilder.AppendFormat("&consent_type={0}", Uri.EscapeDataString(consentAnswer.Invariant));
            }

            builder.Fragment = fragmentStringBuilder.ToString();

            string redirectUri = builder.Uri.ToString();

            context.Response.Redirect(redirectUri);
            context.RequestCompleted();
        }

        async Task<ConsentAnswer> TryGetConsentAnswerAsync(IOwinRequest request)
        {
            ConsentAnswer consentAnswer;

            if (request.IsPost())
            {
                IFormCollection formCollection = await request.ReadFormAsync();

                string consent = formCollection.Get(_options.HandleConsentOptions.ConsentParameterName);

                consentAnswer = ConsentAnswer.TryParse(consent);
            }
            else if (request.IsGet())
            {
                string consent = request.Query.Get(_options.HandleConsentOptions.ConsentParameterName);

                consentAnswer = ConsentAnswer.TryParse(consent);
            }
            else
            {
                consentAnswer = ConsentAnswer.InvalidMethod;
            }

            return consentAnswer;
        }

        async Task<string> TryGetRawJwtTokenAsync(OAuthAuthorizeEndpointContext context)
        {
            string jwt;

            if (context.Request.IsPost())
            {
                IFormCollection formCollection = await context.Request.ReadFormAsync();

                jwt = formCollection.Get(_options.JwtOptions.JwtTokenParameterName);
            }
            else if (context.Request.IsGet())
            {
                jwt = context.Request.Query.Get(_options.JwtOptions.JwtTokenParameterName);
            }
            else
            {
                jwt = "";
            }

            return jwt;
        }

        bool HasSupportedScope(OAuthAuthorizeEndpointContext context, string supportedScope)
        {
            return !context.AuthorizeRequest.Scope.Any() ||
                   context.AuthorizeRequest.Scope.Any(scope => scope.Equals(supportedScope));
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