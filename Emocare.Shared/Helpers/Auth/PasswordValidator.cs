using Emocare.Domain.Interfaces.Helper.Auth;
using System.Text.RegularExpressions;

namespace Emocare.Shared.Helpers.Auth
{
    public class PasswordValidator:IPasswordValidator
    {
        public (bool isValid, string message) ValidatePassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "Password cannot be empty");

            password = password.Trim();

            if (password.Length < 8)
                return (false, "Password must be at least 8 characters long");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                return (false, "Password must contain at least one uppercase letter");

            if (!Regex.IsMatch(password, @"[a-z]"))
                return (false, "Password must contain at least one lowercase letter");

            if (!Regex.IsMatch(password, @"[0-9]"))
                return (false, "Password must contain at least one number");

            if (!Regex.IsMatch(password, @"[^a-zA-Z0-9]"))
                return (false, "Password must contain at least one special character");

            if (IsCommonPassword(password))
                return (false, "Password is too common or contains weak patterns like '12345'");

            return (true, "Password is valid");
        }

        private bool IsCommonPassword(string password)
        {
            var commonSubstrings = new List<string>
            {
                "password", "123", "1234", "12345", "123456", "admin","@1", "@123","welcome", "qwerty", "abc123","98765","9876543","9876"
            };

            return commonSubstrings.Any(p =>
                password.Contains(p, StringComparison.OrdinalIgnoreCase));
        }
    }
}
