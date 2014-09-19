namespace JayLabs.Owin.OAuthAuthorization
{
    internal class OAuthImplicitFlowError
    {
        public static readonly OAuthImplicitFlowError Scope = new OAuthImplicitFlowError("invalid_scope");
        public static readonly OAuthImplicitFlowError ServerError = new OAuthImplicitFlowError("server_error");
        public static readonly OAuthImplicitFlowError AccessDenied = new OAuthImplicitFlowError("access_denied");
        readonly string _invariantName;

        OAuthImplicitFlowError(string invariantName)
        {
            _invariantName = invariantName;
        }

        public string InvariantName
        {
            get { return _invariantName; }
        }

    }
}