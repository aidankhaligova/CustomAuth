namespace CustomAuth.Authentication;
public static class TypeConverterExtension
{
    public static byte[] ToByteArray(this string value) =>
           Convert.FromBase64String(value);
}
public class JwtHandler : IJwtHandler
{
    private readonly ExternalClientJsonConfiguration _settings;

    public JwtHandler(IOptions<ExternalClientJsonConfiguration> setting)
    {
        _settings = setting.Value;
    }

    public JwtResponse CreateToken(JwtCustomClaims claims)
    {
        var privateKey = _settings.RsaPrivateKey.ToByteArray();

        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var now = DateTime.Now;
        var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

        var jwt = new JwtSecurityToken(
            audience: _settings.Audience,
            issuer: _settings.Issuer,
            claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(nameof(claims.FirstName), claims.FirstName),
                    new Claim(nameof(claims.LastName), claims.LastName),
                    new Claim(nameof(claims.Email), claims.Email)
            },
            notBefore: now,
            expires: now.AddMinutes(30),
            signingCredentials: signingCredentials
        );

        string token = new JwtSecurityTokenHandler().WriteToken(jwt);

        return new JwtResponse
        {
            Token = token,
            ExpiresAt = unixTimeSeconds,
        };
    }
    public bool ValidateToken(string token)
    {
        var publicKey = _settings.RsaPublicKey.ToByteArray();

        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _settings.Issuer,
            ValidAudience = _settings.Audience,
            IssuerSigningKey = new RsaSecurityKey(rsa),
            CryptoProviderFactory = new CryptoProviderFactory()
            {
                CacheSignatureProviders = false
            }
        };

        try
        {
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
        }
        catch
        {
            return false;
        }

        return true;
    }
}