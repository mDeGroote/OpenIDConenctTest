using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public interface IJwtService
    {
        public string CreateJwtToken(string audience, HttpContext httpContext);
        public RefreshToken CreateRefreshToken(HttpContext httpContext);
        public TokenPair CheckRefreshToken(string token, HttpContext httpContext);

    }

    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly DataContext _dataContext;

        public JwtService(IConfiguration configuration, DataContext dataContext)
        {
            _configuration = configuration;
            _dataContext = dataContext;
        }

        public string CreateJwtToken(string audience, HttpContext httpContext)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(
                source: Convert.FromBase64String(_configuration["jwt:privatekey"]),
                bytesRead: out int _
            );

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "localhost",
                Audience = audience,
                Expires = DateTime.UtcNow.AddMinutes(15),
                Subject = new System.Security.Claims.ClaimsIdentity(new List<System.Security.Claims.Claim> { httpContext.User.Claims.First(x => x.Type == "preferred_username") }),
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public RefreshToken CreateRefreshToken(HttpContext httpContext)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                RefreshToken refresh_token = new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(1),
                    Created = DateTime.UtcNow,
                    UserNameIdentifier = httpContext.User.Claims.First(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value
                };

                _dataContext.RefreshTokens.Add(refresh_token);
                _dataContext.SaveChanges();

                return refresh_token;
            }
        }

        public TokenPair CheckRefreshToken(string token, HttpContext httpContext)
        {
            RefreshToken refreshToken = _dataContext.RefreshTokens.SingleOrDefault(x => x.Token == token);

            if (refreshToken == null)
                return null;

            if (!refreshToken.IsActive)
                return null;

            if (httpContext.User.Claims.First(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value != refreshToken.UserNameIdentifier)
                return null;

            RefreshToken newRefreshToken = CreateRefreshToken(httpContext);
            string access_token = CreateJwtToken("", httpContext);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.ReplacedByToken = newRefreshToken.Token;

            _dataContext.Update(refreshToken);
            _dataContext.SaveChanges();

            return new TokenPair(access_token, newRefreshToken.Token);
        }
    }
}
