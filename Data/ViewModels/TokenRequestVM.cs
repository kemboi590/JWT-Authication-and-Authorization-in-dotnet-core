using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Data.ViewModels
{
    public class TokenRequestVM
    {
        [Required]
        public required string Token { get; set; }
        [Required]
        public required string RefreshToken { get; set; }
    }
}
