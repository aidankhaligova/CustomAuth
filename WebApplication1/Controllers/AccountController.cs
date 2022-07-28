using CustomAuth.Auth;
using CustomAuth.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;

namespace CustomAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IJWTAuth _jwtAuth;
        public AccountController(IJWTAuth jwtAuth)
        {
            _jwtAuth = jwtAuth;
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
                TokenModel tokenModel = new()
                {
                    UserId=1,
                    Name="Aydan",
                    Role="admin"
                };
                var token = _jwtAuth.GenerateToken(new List<Claim>()
                {
                    new Claim(ClaimTypes.Name,tokenModel.Name),
                    new Claim(ClaimTypes.NameIdentifier,tokenModel.UserId.ToString()),
                    new Claim(ClaimTypes.Role,tokenModel.Role)
                });
                //var json=JsonSerializer.Serialize(tokenModel);
                //var gg = Convert.ToBase64String(Serialize(tokenModel));
                return Ok(token);
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
