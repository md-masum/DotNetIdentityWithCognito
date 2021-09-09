using System.Security.Claims;
using DotNetIdentityWithCognito.Interface;
using Microsoft.AspNetCore.Http;

namespace DotNetIdentityWithCognito.Service
{
    public class CurrentUserService : ICurrentUserService
    {
        public CurrentUserService(IHttpContextAccessor httpContextAccessor)
        {
            UserId = httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            UserName = httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.Name);
            Email = httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.Email);
        }

        public string UserId { get; }
        public string UserName { get; }
        public string Email { get; }
    }
}
