using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json;
using System.IO;
using System.IdentityModel.Tokens.Jwt;

namespace CustomAuth.Auth
{
    public class MyAuthHandler
            : AuthenticationHandler<MyAuthSchemeOptions>
    {
        public MyAuthHandler(
            IOptionsMonitor<MyAuthSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            TokenModel model = new();

            // validation comes in here
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                return Task.FromResult(AuthenticateResult.Fail("Header Not Found."));
            }

            var header = Request.Headers[HeaderNames.Authorization].ToString();
            var tokenMatch = Regex.Match(header, AuthSchemeConstants.NToken);

            if (tokenMatch.Success)
            {
                // the token is captured in this group
                // as declared in the Regex
                var token = tokenMatch.Groups["token"].Value;

                try
                {
                    #region base64
                    //byte[] fromBase64String = Convert.FromBase64String(token);
                    //var parsedToken = Encoding.UTF8.GetString(fromBase64String);
                    //model = JsonConvert.DeserializeObject<TokenModel>(parsedToken);
                    //model = Deserialize(fromBase64String);
                    #endregion

                    var handler = new JwtSecurityTokenHandler();
                    if (handler.CanReadToken(token))
                    {
                        var jsonToken = handler.ReadToken(token);
                        var tokenS = jsonToken as JwtSecurityToken;
                        model.UserId = Convert.ToInt32(tokenS.Claims.FirstOrDefault(x => x.Type == "nameid").Value);
                        model.Name = tokenS.Claims.FirstOrDefault(x => x.Type == "unique_name").Value;
                        model.Role = tokenS.Claims.FirstOrDefault(x => x.Type == "role").Value;
                    }
                    else
                    {
                        return Task.FromResult(AuthenticateResult.Fail("TokenParseException"));
                    }
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine("Exception Occured while Deserializing: " + ex);
                    return Task.FromResult(AuthenticateResult.Fail("TokenParseException"));
                }

                // success branch
                // generate authTicket
                // authenticate the request
                if (model != null)
                {
                    // create claims array from the model
                    var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, model.UserId.ToString()),
           
                      new Claim(ClaimTypes.Role, "admin"),
                    new Claim(ClaimTypes.Name, model.Name) };

                    // generate claimsIdentity on the name of the class
                    var claimsIdentity = new ClaimsIdentity(claims,
                                nameof(MyAuthHandler));

                    bool isOk = CheckUser(model.UserId);
                    if (!isOk)
                    {
                        return Task.FromResult(AuthenticateResult.Fail("UnAuthorize"));
                    }
                    // generate AuthenticationTicket from the Identity
                    // and current authentication scheme
                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);

                    // pass on the ticket to the middleware
                    return Task.FromResult(AuthenticateResult.Success(ticket));
                }
            }

            // failure branch
            // return failure
            // with an optional message
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
}