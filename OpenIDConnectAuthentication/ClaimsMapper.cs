using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public interface IClaimsMapper
    {
        public string GetClaim(string claim, string provider);
    }

    public class ClaimsMapper : IClaimsMapper
    {
        private readonly IConfiguration _configuration;

        public ClaimsMapper(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetClaim(string claim, string provider)
        {
            return _configuration[$"ClaimsMapper:{provider}:{claim}"];
        }
    }
}
