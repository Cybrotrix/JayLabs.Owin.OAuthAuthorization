using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class ClaimAuthorizeAttribute : AuthorizeAttribute
    {
        readonly List<string> _claimTypes =new List<string>();  
        public ClaimAuthorizeAttribute(string requiredClaimType, params string[] requiredClaimTypes)
        {
            _claimTypes.Add(requiredClaimType);
            if (requiredClaimTypes != null)
            {
                _claimTypes.AddRange(requiredClaimTypes);
            }
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            ClaimsPrincipal claimsPrincipal = actionContext.Request.GetOwinContext().Authentication.User;

            if (claimsPrincipal == null || !claimsPrincipal.Identity.IsAuthenticated)
            {
                return false;
            }

            var hasAllClaims =
                _claimTypes.All(
                    type =>
                        claimsPrincipal.HasClaim(
                            claim => claim.Type.Equals(type, StringComparison.InvariantCultureIgnoreCase)));

            return hasAllClaims;
        }
    }
}