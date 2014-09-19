using System;
using System.Collections.Specialized;
using System.Net.Http;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class OAuthRequest
    {
        readonly string _clientId;
        readonly Uri _redirectUri;
        readonly string _jwt;
        readonly string _authorizeUri;
        readonly string _responseType;
        readonly string _state;
        readonly string _scope;

        OAuthRequest(string responseType, string clientId, string state, string scope, Uri redirectUri, string jwt, string authorizeUri)
        {
            _responseType = responseType;
            _clientId = clientId;
            _state = state;
            _scope = scope;
            _redirectUri = redirectUri;
            _jwt = jwt;
            _authorizeUri = authorizeUri;
        }

        public string ClientId
        {
            get { return _clientId; }
        }

        public Uri RedirectUri
        {
            get { return _redirectUri; }
        }

        public string ResponseType
        {
            get { return _responseType; }
        }

        public string State
        {
            get { return _state; }
        }

        public string Scope
        {
            get { return _scope; }
        }

        public string Jwt
        {
            get { return _jwt; }
        }

        public string AuthorizeUri
        {
            get { return _authorizeUri; }
        }

        public static OAuthRequest Parse(Uri uri)
        {
            NameValueCollection queryString = uri.ParseQueryString();
            string responseType = queryString.Get("response_type");
            string clientId = queryString.Get("client_id");
            string state = queryString.Get("state");
            string scope = queryString.Get("scope");
            string jwt = queryString.Get("jwt_token");
            var redirectUri = new Uri(queryString.Get("redirect_uri"), UriKind.Absolute);
            
            var originalUri = uri.ToString().Replace("&jwt_token=" + jwt, "");

            return new OAuthRequest(responseType, clientId, state, scope, redirectUri, jwt, originalUri);
        }
    }
}