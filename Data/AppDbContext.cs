using JWTAuth.Data.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Data
{
    public class AppDbContext: IdentityDbContext<ApplicationUser>
    {
    // ctor
        public AppDbContext(DbContextOptions<AppDbContext> options): base(options)
        { 
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
