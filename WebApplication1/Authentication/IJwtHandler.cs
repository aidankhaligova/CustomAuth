namespace CustomAuth.Authentication;
public interface IJwtHandler
{
    JwtResponse CreateToken(JwtCustomClaims claims);
    bool ValidateToken(string token);
}
