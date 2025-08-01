﻿

namespace Emocare.Shared.Helpers.Api
{
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Source { get; set; }
        public T? Data { get; set; }
        public int StatusCode { get; set; }
    }
}
