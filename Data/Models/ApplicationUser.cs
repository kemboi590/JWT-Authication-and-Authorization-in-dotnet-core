using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Data.Models
{
    public class ApplicationUser: IdentityUser
    {
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public  string? Custom { get; set; } 
    }
}

/*
 Notes:
IdentityUser is a class provided by ASP.NET Core Identity. It represents a user in the identity system
and includes all the basic properties needed for user management, such as:
•	Username
•	Password
•	Email
•	Phone number
•	Security stamps (used for security purposes like password reset)

What is ApplicationUser?
ApplicationUser is a custom class that inherits from IdentityUser. By inheriting from IdentityUser, 
ApplicationUser automatically gets all the properties and methods of IdentityUser. This allows you to add additional properties specific to your application without losing the built-in functionalities.
 */