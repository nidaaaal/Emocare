using Emocare.Domain.Interfaces.Helper.AiChat;
using Emocare.Shared.Helpers.Api;
using Microsoft.AspNetCore.Http;

namespace Emocare.Shared.Helpers.Chat
{
    public class UserFinder : IUserFinder
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserFinder(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public Guid GetId()
        {
            if (_httpContextAccessor.HttpContext?.Items["userId"] is Guid userId)
            {
                return userId;
            }

            throw new NotFoundException("No User found on The corresponding Id");
        }
    }
}