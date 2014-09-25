using System;
using Microsoft.Owin;

namespace JayLabs.Owin.OAuthAuthorization
{
    public static class RequestExtensions
    {
        public static bool IsPost(this IOwinRequest request)
        {
            return request.Method.Equals("POST", StringComparison.InvariantCultureIgnoreCase);
        }
        public static bool IsGet(this IOwinRequest request)
        {
            return request.Method.Equals("GET", StringComparison.InvariantCultureIgnoreCase);
        }
    }
}