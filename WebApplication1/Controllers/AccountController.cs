namespace CustomAuth.Controllers;
[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IJwtHandler _jwtHandler;
    public AccountController(IJwtHandler jwtHandler)
    {
        _jwtHandler = jwtHandler;
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

            #region jwt
            //var token = _jwtAuth.GenerateToken(new List<Claim>()
            //{
            //    new Claim(ClaimTypes.Name,tokenModel.Name),
            //    new Claim(ClaimTypes.NameIdentifier,tokenModel.UserId.ToString()),
            //    new Claim(ClaimTypes.Role,tokenModel.Role)
            //});
            #endregion

            #region base64
            //var json=JsonSerializer.Serialize(tokenModel);
            //var gg = Convert.ToBase64String(Serialize(tokenModel));
            #endregion

            #region rs256
            var claims = new JwtCustomClaims
            {
                FirstName = "Vynn",
                LastName = "Durano",
                Email = "whatever@email.com"
            };
            var token = _jwtHandler.CreateToken(claims);
            #endregion

            return Ok(token);
        }
    }
    private bool IsValid(string username, string pass) =>
        username == "aydan" && pass == "1";
}