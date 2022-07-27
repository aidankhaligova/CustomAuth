using System.Security.Claims;
using System.Text;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;

namespace CustomAuth.Authentication
{
    public class JWTAuth : IJWTAuth
    {
        private const string _privateKey = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";

        public string GenerateToken(IEnumerable<Claim> claims)
        {
            var key = Encoding.ASCII.GetBytes(_privateKey);
            var tokenHandler = new JwtSecurityTokenHandler();
            DateTime dateTime = DateTime.Now.AddMinutes(5);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = dateTime,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = "YourAudience",
                Issuer = "YourIssuer"
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }

        public bool ValidatedToken(string incomingToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = GetValidationParameters();
                var principal = tokenHandler.ValidateToken(incomingToken, validationParameters, out SecurityToken securityToken);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private TokenValidationParameters GetValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateLifetime = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidIssuer = "YourIssuer",
                ValidAudience = "YourAudience",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_privateKey)),
                ClockSkew = TimeSpan.FromMinutes(3),
                ValidateIssuerSigningKey = true
            };
        }
    }
}
