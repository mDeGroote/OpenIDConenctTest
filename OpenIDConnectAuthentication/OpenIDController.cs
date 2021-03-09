using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenIDConnectAuthentication
{
    [Route("openid")]
    [ApiController]
    public class OpenIDController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public OpenIDController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "jwt")]
        public ActionResult TestJwt()
        {

            //var handler = new JwtSecurityTokenHandler();

            //var TokenDecryptionKey = new X509SecurityKey(new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\Users\maria\source\repos\OpenIDConnectAuthenticationTest\OpenIDConnectAuthentication\AuthSample.pfx", "password"));

            //var claimsprincipal = handler.ValidateToken(token, new TokenValidationParameters
            //{
            //    ValidAudience = "localhost",
            //    ValidIssuer = "localhost",
            //    RequireSignedTokens = false,
            //    TokenDecryptionKey = new RsaSecurityKey(new System.Security.Cryptography.X509Certificates.X509Certificate2("AuthSample.pfx", "password", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable).GetRSAPrivateKey().ExportParameters(true))

            //}, out SecurityToken securityToken);



            return Ok();
        }

        [HttpPost]
        public string GetCode([FromForm] string code)
        {
            using (WebClient wc = new WebClient())
            {
                wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                string id_token = "";
                try
                {
                    string response = wc.UploadString("https://login.live.com/oauth20_token.srf", $"client_id={_configuration["OpenIDconnect:Microsoft:client_id"]}&code={code}&client_secret={_configuration["OpenIDconnect:Microsoft:client_secret"]}&grant_type=authorization_code&redirect_uri=https://localhost:44336/openid");

                    JsonDocument jsonDocument = JsonDocument.Parse(response);
                    string access_token = jsonDocument.RootElement.EnumerateObject().ElementAt(3).Value.ToString();
                    id_token = jsonDocument.RootElement.EnumerateObject().ElementAt(4).Value.ToString();
                }
                catch(WebException ex)
                {
                    HttpWebResponse response = (HttpWebResponse)ex.Response;
                    using (StreamReader sr = new StreamReader(response.GetResponseStream()))
                    {
                        System.Diagnostics.Debug.Write(sr.ReadToEnd());
                    }
                }

                if(id_token != "")
                {
                    var handler = new JwtSecurityTokenHandler();
                    var token = handler.ReadJwtToken(id_token);

                    StringBuilder sb = new StringBuilder();
                    foreach (System.Security.Claims.Claim item in token.Claims)
                    {
                        sb.Append($"type: {item.Type}, value: {item.Value}, issuer: {item.Issuer} \n");
                    }

                    sb.Append($"actor: {token.Actor} \n");
                    sb.Append($"Valid to: {token.ValidTo} \n");

                    return $"{sb.ToString()}";
                }

                return "";
            }

        }
    }
}
