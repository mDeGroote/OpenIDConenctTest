using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Security.Claims;

namespace OpenIDConnectAuthentication
{
    public interface IJwtService
    {
        string CreateJwtToken(string audience, IEnumerable<Claim> userclaims, string identityProvider, string nonce = null);
        RefreshToken CreateRefreshToken(IEnumerable<Claim> userclaims, string identityProvider);
        TokenPair CheckRefreshToken(string token, string audience, IEnumerable<Claim> userclaims);
        RefreshToken HasExistingRefreshToken(IEnumerable<Claim> userclaims);
        void RevokeRefreshToken(string token);
        JwtSecurityToken ReadAccessToken(string token);
    }

    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly DataContext _dataContext;
        private readonly IClaimsMapper _claimsMapper;

        public JwtService(IConfiguration configuration, DataContext dataContext, IClaimsMapper claimsMapper)
        {
            _configuration = configuration;
            _dataContext = dataContext;
            _claimsMapper = claimsMapper;
        }

        public string CreateJwtToken(string audience, IEnumerable<Claim> userclaims, string identityProvider, string nonce = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(
                source: Convert.FromBase64String(_configuration["jwt:privatekey"]),
                bytesRead: out int _
            );

            Dictionary<string, object> claims = new Dictionary<string, object>();
            claims.Add("sub", userclaims.First(x => x.Type == _claimsMapper.GetClaim("UniqueIdentifier", identityProvider)).Value);
            claims.Add("name", userclaims.First(x => x.Type == _claimsMapper.GetClaim("Name", identityProvider)).Value);
            if(nonce != null)
                claims.Add("nonce", nonce);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddMinutes(15),
                Issuer = "localhost",
                Audience = audience,
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
                Claims = claims
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public RefreshToken CreateRefreshToken(IEnumerable<Claim> userclaims, string identityProvider)
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
                    UserNameIdentifier = userclaims.First(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value,
                    IdentityProvider = identityProvider
                };

                _dataContext.RefreshTokens.Add(refresh_token);
                _dataContext.SaveChanges();

                return refresh_token;
            }
        }

        public TokenPair CheckRefreshToken(string token, string audience, IEnumerable<Claim> userclaims)
        {
            RefreshToken refreshToken = _dataContext.RefreshTokens.FirstOrDefault(x => x.Token == token);

            if (refreshToken == null)
                return null;

            if (!refreshToken.IsActive)
                return null;

            if (userclaims.First(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value != refreshToken.UserNameIdentifier)
                return null;

            RefreshToken newRefreshToken = CreateRefreshToken(userclaims, refreshToken.IdentityProvider);
            string access_token = CreateJwtToken(audience, userclaims, refreshToken.IdentityProvider);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.ReplacedByToken = newRefreshToken.Token;

            _dataContext.Update(refreshToken);
            _dataContext.SaveChanges();

            return new TokenPair(access_token, newRefreshToken.Token);
        }

        public RefreshToken HasExistingRefreshToken(IEnumerable<Claim> userclaims)
        {
            string unqiueIdentifier = userclaims.First(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            RefreshToken refreshToken = _dataContext.RefreshTokens.FirstOrDefault(x => x.UserNameIdentifier == unqiueIdentifier && x.Revoked == null);

            if (refreshToken == null || !refreshToken.IsActive)
                return null;
            else
                return refreshToken;
        }

        public void RevokeRefreshToken(string token)
        {
            RefreshToken refreshToken = _dataContext.RefreshTokens.FirstOrDefault(x => x.Token == token && x.Revoked == null);

            if (refreshToken == null)
                return;

            refreshToken.Revoked = DateTime.UtcNow;

            _dataContext.Update(refreshToken);
            _dataContext.SaveChanges();
        }

        public JwtSecurityToken ReadAccessToken(string token)
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
                    ValidAlgorithms = new [] {"RS256"},
                    ValidateAudience = true,
                    ValidAudience = "localhost",
                    ValidateIssuer = true,
                    ValidIssuer = "localhost",
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKey = new RsaSecurityKey(rsa)
                }, out SecurityToken securityToken);
                return tokenHandler.ReadJwtToken(token);
            }
            catch (Exception ex)
            {
                return null;
            }

        }
    }
}
