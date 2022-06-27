using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SwaggerUIwithJWTsupport.ViewModel;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace SwaggerUIwithJWTsupport.Controllers;

[Authorize]
[ApiController]
[Route("")]
public class LoginController : ControllerBase
{
    private readonly UserCurrent[] _users =
    {
        new UserCurrent {Password = "Senha123@", Email = "silvaam.guilherme@gmail.com", 
            FirstName = "Guilherme", Claim = new Claim("Home", "Default")},
        new UserCurrent { Email = "admin@admin.com", Password = "Admin123@", 
            FirstName = "Admin", Claim = new Claim("Home", "Admin")}
    };
    private AuthConfiguration _confAuth = new AuthConfiguration().GetInstance();
    [Authorize(Roles = "Admin")]
    [HttpGet("role-admin")]
    public ActionResult Admin()
    {
        return Ok();
    }
    [Authorize(Roles = "Default")]
    [HttpGet("role-default")]
    public ActionResult Default()
    {
        return Ok();
    }
    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult Login(LoginViewModel loginViewModel)
    {
        if (!_users.Any(a => a.Password == loginViewModel.Password &&
                            a.Email == loginViewModel.Email)) return BadRequest();
        var user = new UserCurrent
        {
            Email = loginViewModel.Email,
            Password = loginViewModel.Password,
        };
        return Ok(new
        {
            Success = true, 
            Token = GenerateToke(user).Result
        });

    }
    
    private async Task<string> GenerateToke(UserCurrent user)
    {
        var claims = new List<Claim>();
        
        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Email));
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        if (user.Email == "admin@admin.com")
        {
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
        }
        claims.Add(new Claim(ClaimTypes.Role, "Default"));
        claims.Add(user.Claim);
        var calimIdetity = new ClaimsIdentity(claims);
        var tokeHandler = new JwtSecurityTokenHandler();

        var token  = tokeHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _confAuth.GetIssuer(),
            Audience = _confAuth.GetAudience(),
            Subject = calimIdetity,
            Expires = DateTime.UtcNow.AddHours(2),
            SigningCredentials = 
                new SigningCredentials (_confAuth.GetKey(),
                    SecurityAlgorithms.HmacSha256Signature)
        });
        
        return await Task.FromResult(tokeHandler.WriteToken(token));
    }
}