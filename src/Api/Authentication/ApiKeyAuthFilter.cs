using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;

namespace WebApi.Authentication
{
	public class ApiKeyAuthFilter : IAuthorizationFilter
	{
        private readonly IConfiguration _confiration;

		public ApiKeyAuthFilter(IConfiguration configuration)
		{
            _confiration = configuration;
		}

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(AuthConstants.AuthKeyHeaderName, out var extractedApiKey))
            {
                context.Result = new UnauthorizedObjectResult("API Key missing.");

                return;
            }

            var apiKey = _confiration.GetValue<string>(AuthConstants.ApyKeySectionName);

            if (!apiKey.Equals(extractedApiKey))
            {
                context.Result = new UnauthorizedObjectResult("API Key invalid.");
                return;
            }

        }
    }
}

