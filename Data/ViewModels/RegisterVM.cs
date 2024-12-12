using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Data.ViewModels
{
    public class RegisterVM
    {
        public string FirstName { get; set; }
      
        public string LastName { get; set; }
        [Required]
        public string Email { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
