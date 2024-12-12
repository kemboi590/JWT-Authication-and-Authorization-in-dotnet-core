using JWTAuth.Data;
using JWTAuth.Data.Models;
using JWTAuth.Data.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, AppDbContext context, IConfiguration configuration, ILogger<AuthenticationController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody]RegisterVM registerVM)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest("Please, Provide all the required fields!");
            }

            var userExists = await _userManager.FindByEmailAsync(registerVM.Email);
            if (userExists != null)
            {
                return BadRequest($"User {registerVM.Email} already exists!");
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerVM.FirstName,
                LastName = registerVM.LastName,
                Email = registerVM.Email,
                UserName = registerVM.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
                Custom = "DefaultValue"
            };

            var result = await _userManager.CreateAsync(newUser, registerVM.Password);

            if (result.Succeeded) return Ok("User Created");

            // Log the errors
            foreach (var error in result.Errors)
            {
                _logger.LogError($"Error: {error.Description}");
            }

            return BadRequest("User could not be created, try again");
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginVM loginVM)
        {
           if (!ModelState.IsValid)
            {
                return BadRequest("Please, Provide all the required fields!");
            }

            var userExist = await _userManager.FindByEmailAsync(loginVM.Email);
            if (userExist != null && await _userManager.CheckPasswordAsync(userExist, loginVM.Password))
            {
                var tokenValue = await GenerateJWTToken(userExist);
                return Ok(tokenValue);
            }
            return Unauthorized("Please, Provide the correct credentials");
        }

        private async Task<AuthResultVM> GenerateJWTToken(ApplicationUser user)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));
        
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            var response = new AuthResultVM()
            {
                Token = jwtToken,
                ExpiresAt = token.ValidTo
            };
            return response;
        }
    }
}
