using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public class TokenExchange
    {
        [Key]
        public int Id { get; set; }
        public string Code { get; set; }
        public string Id_token { get; set; }
        public string Refresh_token { get; set; }

        public TokenExchange(string code, string id_token, string refresh_token)
        {
            Code = code;
            Id_token = id_token;
            Refresh_token = refresh_token;
        }
    }
}
