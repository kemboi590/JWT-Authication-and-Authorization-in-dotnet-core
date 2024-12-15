using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuth.Data.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        public required string Token { get; set; }
        public required string JwtId { get; set; }
        public bool  IsRevoked { get; set; }
        public DateTime DateAdded { get; set; }
        public DateTime DateExipire { get; set; }

        // Foreign Key
        public required string UserId { get; set; } // UserId is a foreign key that references the Id property of the ApplicationUser class
        [ForeignKey(nameof(UserId))] 
        public required ApplicationUser User { get; set; }
    }
}
