using CustomAuth.Auth;
using CustomAuth.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CustomAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        //JWTAuth _auth;
       
        public AccountController(/*JWTAuth auth*/)
        {
           // _auth = auth;
        }

        [HttpPost]
        public IActionResult Login([FromBody] UserLoginDto uld)
        {
            if (!IsValid(uld.UserName,uld.Password))
            {
                return Unauthorized();
            }
            else
            {
                //var claims = new List<Claim>()
                //{
                //    new Claim(ClaimTypes.Name, uld.UserName),
                //    new Claim(ClaimTypes.Role, "standard_user"),
                //    new Claim(ClaimTypes.AuthenticationInstant, "passlogin")
                //};
                //var tokenString = GenerateToken(claims);

                TokenModel tokenModel = new()
                {
                    UserId=2,
                    Name="Aydan",
                    Role="admin"
                };
                var json=JsonSerializer.Serialize(tokenModel);
                var gg = Convert.ToBase64String(Serialize(tokenModel));
                return Ok(gg);
            }
        }
        private byte[] Serialize(TokenModel tokenModel)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(tokenModel.UserId);
                    writer.Write(tokenModel.Name);
                    writer.Write(tokenModel.Role);
                }
                return m.ToArray();
            }
        }
        private bool IsValid(string username, string pass) =>
            username == "aydan" && pass == "1";
    }
}
