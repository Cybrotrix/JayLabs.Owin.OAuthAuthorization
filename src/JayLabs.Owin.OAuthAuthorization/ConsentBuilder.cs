using System;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace JayLabs.Owin.OAuthAuthorization
{
    public static class ConsentBuilder
    {
        public static Task BuildConsentPageAsync(IOwinResponse response, string redirectUri)
        {
            var consentUrl = new Uri(string.Format("/consent?redirectUri={0}", Uri.EscapeDataString(redirectUri)),
                UriKind.Relative);

            response.Redirect(consentUrl.ToString());

            return Task.FromResult(0);
        }
    }
}