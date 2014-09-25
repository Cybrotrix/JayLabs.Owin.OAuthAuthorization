namespace JayLabs.Owin.OAuthAuthorization
{
    public class HandleConsentOptions
    {
        readonly string _consentParameterName;

        public HandleConsentOptions(string consentParameterName)
        {
            _consentParameterName = consentParameterName;
        }

        public string ConsentParameterName
        {
            get { return _consentParameterName; }
        }
    }
}