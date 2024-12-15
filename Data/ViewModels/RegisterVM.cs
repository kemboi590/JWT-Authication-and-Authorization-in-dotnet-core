﻿using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Data.ViewModels
{
    public class RegisterVM
    {
        public required string FirstName { get; set; }
      
        public required string LastName { get; set; }
        [Required]
        public required string Email { get; set; }
        [Required]
        public required string UserName { get; set; }
        [Required]
        public required string Password { get; set; }
        [Required]
        public required string Role { get; set; }
    }
}
