using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    [Route("jwt")]
    [ApiController]
    public class JWTController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IJwtService _jwtService;

        public JWTController(IConfiguration configuration, DataContext dataContext, IJwtService jwtService)
        {
            _configuration = configuration;
            _jwtService = jwtService;
        }
        

        [HttpPost]
        [Route("verify")]
        public IActionResult VerifyToken([FromForm]string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(
                source: Convert.FromBase64String(_configuration["jwt:publickey"]),
                bytesRead: out int _
            );

            try
            {
                var claims = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = "localhost",
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKey = new RsaSecurityKey(rsa)
                }, out SecurityToken securityToken);
            }
            catch (Exception ex)
            {
                return BadRequest();
            }

            return Ok();
            
        }

        [HttpGet]
        [Route("Refresh")]
        public IActionResult RefreshToken()
        {
            string referer = Request.Headers["referer"];

            //Is the user is not authenticated, they can authenticate themselves and retrieve a new access_token and refresh_token
            if (!HttpContext.User.Identity.IsAuthenticated)
                return LocalRedirect("/authentication/login?returnurl=" + referer);

            string refresh_token = Request.Cookies["refresh_token"];

            TokenPair tokenPair = _jwtService.CheckRefreshToken(refresh_token, HttpContext);

            CookieOptions cookieOptions = new CookieOptions();
            cookieOptions.HttpOnly = true;

            if(tokenPair != null)
            {
                Response.Cookies.Append("access_token", tokenPair.access_token);
                Response.Cookies.Append("refresh_token", tokenPair.refresh_token, cookieOptions);

                return Redirect(referer);
            }

            return BadRequest(new {Errormessage = "Refresh token is invalid" });
        }

        [HttpGet]
        [Route("Key")]
        public IActionResult GetPublicSigningkey()
        {
            return Ok(new {key = _configuration["jwt:publickey"] });
        }
    }
}
