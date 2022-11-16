using CustomAuth.Helpers;

namespace CustomAuth.Auth;
public class MyAuthHandler
        : AuthenticationHandler<MyAuthSchemeOptions>
{
    private readonly IJwtHandler _jwtHandler;
    public MyAuthHandler(
        IJwtHandler jwtHandler,
        IOptionsMonitor<MyAuthSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _jwtHandler = jwtHandler;   
    }
    
    private const string publicKey = "w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ";
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        TokenModel model = new();

        if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
        {
            return Task.FromResult(AuthenticateResult.Fail("Header Not Found."));
        }

        var header = Request.Headers[HeaderNames.Authorization].ToString();
        var tokenMatch = Regex.Match(header, AuthSchemeConstants.NToken);

        if (tokenMatch.Success)
        {
            var token = tokenMatch.Groups["token"].Value;

            try
            {
                #region base64
                //byte[] fromBase64String = Convert.FromBase64String(token);
                //model = Deserialize(fromBase64String);
                #endregion

                #region jwt
                //var handler = new JwtSecurityTokenHandler();
                //if (handler.CanReadToken(token))
                //{
                //    var jsonToken = handler.ReadToken(token);
                //    var tokenS = jsonToken as JwtSecurityToken;
                //    model.UserId = Convert.ToInt32(tokenS.Claims.FirstOrDefault(x => x.Type == "nameid").Value);
                //    model.Name = tokenS.Claims.FirstOrDefault(x => x.Type == "unique_name").Value;
                //    model.Role = tokenS.Claims.FirstOrDefault(x => x.Type == "role").Value;
                //}
                //else
                //{
                //    return Task.FromResult(AuthenticateResult.Fail("TokenParseException"));
                //}
                #endregion

                #region rs256
                var con = _jwtHandler.ValidateToken(token);
                var data = DecodeRS256.Decode(token, publicKey, true);
                
                #endregion
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("Exception Occured while Deserializing: " + ex);
                return Task.FromResult(AuthenticateResult.Fail("TokenParseException"));
            }

            if (model != null)
            {
                var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, model.UserId.ToString()),
                new Claim(ClaimTypes.Role, "admin"),
                new Claim(ClaimTypes.Name, model.Name) };

                var claimsIdentity = new ClaimsIdentity(claims,
                            nameof(MyAuthHandler));

                bool isOk = CheckUser(model.UserId);
                if (!isOk)
                {
                    return Task.FromResult(AuthenticateResult.Fail("UnAuthorize"));
                }
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);

                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
        }
        return Task.FromResult(AuthenticateResult.Fail("Model is Empty"));
    }
    public bool CheckUser(int id) => id == 1;
    public static TokenModel Deserialize(byte[] data)
    {
        TokenModel result = new();
        using (MemoryStream m = new MemoryStream(data))
        {
            using (BinaryReader reader = new BinaryReader(m))
            {
                result.UserId = reader.ReadInt32();
                result.Name = reader.ReadString();
                result.Role = reader.ReadString();
            }
        }
        return result;
    }
}