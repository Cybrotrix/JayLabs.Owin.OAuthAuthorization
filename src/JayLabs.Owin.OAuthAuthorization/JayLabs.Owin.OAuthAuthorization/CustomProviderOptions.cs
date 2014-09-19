using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class CustomProviderOptions
    {
        Func<ClaimsPrincipal, Task<ClaimsIdentity>> _transformPrincipal;
        

        public CustomProviderOptions()
        {
            
        }
        public string SupportedScope { get; set; }

        public Func<ClaimsPrincipal, Task<ClaimsIdentity>> TransformPrincipal
        {


            get { return _transformPrincipal ?? (principal => Task.FromResult(principal.Identities.FirstOrDefault())); }
            set { _transformPrincipal = value; }
        }
    }
}