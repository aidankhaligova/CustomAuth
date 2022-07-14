namespace CustomAuth.Auth
{
    public class AuthSchemeConstants
    {
        public const string MyAuthScheme = "Ninpo";
        public const string NToken = $"{MyAuthScheme} (?<token>.*)";
    }
}
