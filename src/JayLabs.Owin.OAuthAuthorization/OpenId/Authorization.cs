using System;
using System.Threading.Tasks;
using JayLabs.Owin.OAuthAuthorization.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;

namespace JayLabs.Owin.OAuthAuthorization.OpenId
{
    public static class Authorization
    {
        public static async Task HandleAsync(AuthorizationCodeReceivedNotification authorizationCodeReceived, IJwtOptions jwtOptions, Func<IOwinResponse, string, Task> createConsent)
        {
            string tokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(authorizationCodeReceived.JwtSecurityToken.Claims, jwtOptions).CreateTokenAsBase64();

            authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri +=
                string.Format("&{0}={1}", jwtOptions.JwtTokenHeader, tokenAsBase64);

            await createConsent(authorizationCodeReceived.Response, authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri);

            authorizationCodeReceived.HandleResponse();
        }
    }
}