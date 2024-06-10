using Microsoft.AspNetCore.Identity;

namespace EmailValidatorApp
{
    public class EmailValidator : IUserValidator<IdentityUser>
    {
        private static string[] AllowedDomains = new[]
        {
            "gmail.com",
            "hotmail.com",
            "outlook.com",
            "yahoo.com",
            "msn.com",
            "icloud.com",
        };

        private static IdentityError error
            = new IdentityError { Description = "Email address domain not allowed" };

        public EmailValidator(ILookupNormalizer normalizer)
        {
            Normalizer = normalizer;
        }

        private ILookupNormalizer Normalizer { get; set; }

        public async Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user)
        {
            string normalizedEmail = Normalizer.NormalizeEmail(user.Email);

            if (AllowedDomains.Any(domain =>
                    normalizedEmail.ToLower()
                                   .EndsWith($"@{domain}")))
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed(error);
        }
    }
}
