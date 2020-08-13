using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading;

namespace Owin
{
    public static class IdentityServerBearerTokenClaimsExtensions
    {


        /// <summary>
        /// IdSrv4 puts scopes in single space separated claim
        /// This methods detects if scopes are comma separated and puts each scope in separate claim, like IdSrv3 does
        /// </summary>
        public static IEnumerable<Claim> ConvertFromIdSrv4Format(this IEnumerable<Claim> claims) 
        {
            if (claims == null || !claims.Any())
                return claims;

            if (!claims.All(x => x.Type == "scope"))
                throw new InvalidOperationException("Only scope claims are accepted, claims must be filtered out first");

            var newClaims = claims.ToList();
            Convert(newClaims);

            return newClaims;
        }

        private static void Convert(List<Claim> claims)
        {
            var additionalScopes = claims.First().Value.Split(' ');
            if (additionalScopes.Length > 1)
            {
                claims.RemoveAt(0);
                foreach (var additionalScope in additionalScopes)
                {
                    claims.Add(new Claim("scope", additionalScope));
                }
            }
        }
    }
}