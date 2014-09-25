using System;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class CreateConsentOptions
    {
        public Func<IOwinResponse, Uri, Task> CreateConsentAsync { get; set; }
    }
}