using System;
using System.Threading.Tasks;
using JayLabs.Owin.OAuthAuthorization.Tokens;
using Microsoft.Owin.Security.Notifications;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class ConsentBuilder
    {
        readonly HandleConsentOptions _consentHandlerOptions;
        readonly CreateConsentOptions _createConsentOptions;
        readonly JwtOptions _jwtOptions;

        public ConsentBuilder(CreateConsentOptions createConsentOptions, HandleConsentOptions consentHandlerOptions,
            JwtOptions jwtOptions)
        {
            if (jwtOptions == null)
            {
                throw new ArgumentNullException("jwtOptions");
            }

            _createConsentOptions = createConsentOptions;
            _consentHandlerOptions = consentHandlerOptions;
            _jwtOptions = jwtOptions;
        }

        public async Task HandleOpenIdAuthorizationCodeAsync(
            AuthorizationCodeReceivedNotification authorizationCodeReceived)
        {
            string tokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(authorizationCodeReceived.JwtSecurityToken.Claims,
                    _jwtOptions).CreateTokenAsBase64();

            authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri +=
                string.Format("&{0}={1}", _jwtOptions.JwtTokenParameterName, tokenAsBase64);

            if (_createConsentOptions.CreateConsentAsync != null)
            {
                await _createConsentOptions.CreateConsentAsync(authorizationCodeReceived.Response,
                    new Uri(authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri));

                authorizationCodeReceived.HandleResponse();
            }
            else
            {
                string implicitConsent = string.Format("&{0}={1}", _consentHandlerOptions.ConsentParameterName,
                    Uri.EscapeDataString("implicit"));
                authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri += implicitConsent;
            }

        }
    }
}