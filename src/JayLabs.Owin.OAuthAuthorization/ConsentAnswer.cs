using System;
using System.Collections.Generic;
using System.Linq;

namespace JayLabs.Owin.OAuthAuthorization
{
    public class ConsentAnswer : IEquatable<ConsentAnswer>
    {
        public static readonly ConsentAnswer InvalidMethod = new ConsentAnswer("invalid method");
        public static readonly ConsentAnswer Accepted = new ConsentAnswer("accepted");
        public static readonly ConsentAnswer Implicit = new ConsentAnswer("implicit");
        public static readonly ConsentAnswer Rejected = new ConsentAnswer("rejected");
        public static readonly ConsentAnswer Missing = new ConsentAnswer("missing");
        public static readonly ConsentAnswer Invalid = new ConsentAnswer("invalid");
        readonly string _invariantAnswer;
        readonly string _userConsent;

        ConsentAnswer(string invariantAnswer, string userConsent = null)
        {
            if (string.IsNullOrWhiteSpace(invariantAnswer))
            {
                throw new ArgumentNullException("invariantAnswer");
            }

            _invariantAnswer = invariantAnswer;
            _userConsent = userConsent;
        }

        static IEnumerable<ConsentAnswer> All
        {
            get
            {
                yield return InvalidMethod;
                yield return Accepted;
                yield return Rejected;
                yield return Missing;
                yield return Implicit;
                yield return Invalid;
            }
        }

        public string UserAnswer
        {
            get { return _userConsent; }
        }

        public string Invariant
        {
            get { return _invariantAnswer; }
        }

        public string Display
        {
            get { return Invariant + (string.IsNullOrWhiteSpace(UserAnswer) ? "" : ", " + UserAnswer); }
        }

        public bool Equals(ConsentAnswer other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(Invariant, other.Invariant);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConsentAnswer) obj);
        }

        public override int GetHashCode()
        {
            return (Invariant != null ? Invariant.GetHashCode() : 0);
        }

        public static bool operator ==(ConsentAnswer left, ConsentAnswer right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(ConsentAnswer left, ConsentAnswer right)
        {
            return !Equals(left, right);
        }

        public static ConsentAnswer TryParse(string consentValue)
        {
            string value = string.IsNullOrWhiteSpace(consentValue) ? Missing.Invariant : consentValue;

            ConsentAnswer consentAnswer =
                All.SingleOrDefault(
                    consent => consent.Invariant.Equals(value, StringComparison.InvariantCultureIgnoreCase)) ??
                Invalid;

            return new ConsentAnswer(consentAnswer.Invariant, value);
        }
    }
}