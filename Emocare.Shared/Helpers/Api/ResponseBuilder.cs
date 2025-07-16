
namespace Emocare.Shared.Helpers.Api
{
    public static class ResponseBuilder
    {
        public static ApiResponse<T> Success<T>(T data, string message = "", string? source = null, int status = 200)
        {
            return new ApiResponse<T>
            {
                Success = true,
                Message = message,
                Source = source,
                Data = data,
                StatusCode = status
            };
        }

        public static ApiResponse<T> Fail<T>(string message, string? source = null, int status = 400)
        {
            return new ApiResponse<T>
            {
                Success = false,
                Message = message,
                Source = source,
                Data = default,
                StatusCode = status
            };
        }
    }
}


