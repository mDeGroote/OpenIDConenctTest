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
            if(_jwtService.ReadIdToken(token) != null)
                return Ok();

            return BadRequest(new { Errormessage = "Invalid JWT token" });
        }

        [HttpGet]
        [Route("Refresh")]
        public IActionResult RefreshToken()
        {
            string referer = Request.Headers["referer"];

            //Is the user is not authenticated, they can authenticate themselves and retrieve a new id token and refresh token
            if (!HttpContext.User.Identity.IsAuthenticated)
                return LocalRedirect("/authentication?returnurl=" + referer);

            string refresh_token = Request.Cookies["refresh_token"];
            string id_token = Request.Cookies["id_token"];
            if(id_token == null)
                return BadRequest(new { Errormessage = "id_token was not present" });

            JwtSecurityToken token = _jwtService.ReadIdToken(id_token);
            if (token == null)
                return BadRequest(new { Errormessage = "invalid id_token" });

            TokenPair tokenPair = _jwtService.CheckRefreshToken(refresh_token,token.Audiences.ElementAt(0), HttpContext.User.Claims);

            CookieOptions cookieOptions = new CookieOptions();
            cookieOptions.HttpOnly = true;

            if(tokenPair != null)
            {
                Response.Cookies.Append("id_token", tokenPair.id_token);
                Response.Cookies.Append("refresh_token", tokenPair.refresh_token, cookieOptions);

                return Redirect(referer);
            }

            return BadRequest(new {Errormessage = "Refresh token is invalid" });
        }

        [HttpGet]
        [Route("Keys")]
        public IActionResult GetPublicSigningkey()
        {
            return Ok(new {Public_key = _configuration["jwt:publickey"] });
        }
    }
}
