namespace CustomAuth.Auth;
public class AuthSchemeConstants
{
    public const string MyAuthScheme = "Bearer";
    public const string NToken = $"{MyAuthScheme} (?<token>.*)";
}