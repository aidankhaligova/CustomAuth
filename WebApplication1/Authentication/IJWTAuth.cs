namespace CustomAuth.Authentication
{
    public interface IJWTAuth
    {
        string GenerateToken(IEnumerable<Claim> claims);
        bool ValidatedToken(string incomingToken);
    }
}
