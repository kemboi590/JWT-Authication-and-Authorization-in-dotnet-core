using JWTAuth.Data;
using JWTAuth.Data.Helpers;
using JWTAuth.Data.Models;
using JWTAuth.Data.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
        private readonly TokenValidationParameters _tokenValidationParameters;


        public AuthenticationController(UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager, AppDbContext context, 
            IConfiguration configuration, ILogger<AuthenticationController> logger, 
            TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
            _logger = logger;
            _tokenValidationParameters = tokenValidationParameters;
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

            if (result.Succeeded)
            {
                //add user Role
                switch(registerVM.Role)
                {
                    case UserRoles.Manager:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Manager);
                        break;
                    case UserRoles.Student:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Student);
                        break;
                    default:
           
                        break;
                }


                return Ok("User Created");
            }

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
                var tokenValue = await GenerateJWTToken(userExist, null);
                return Ok(tokenValue);
            }
            return Unauthorized("Please, Provide the correct credentials");
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestVM tokenRequestVM)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please, Provide all the required fields!");
            }

            var result = await VerifyAndGenerateTokenAsyc(tokenRequestVM);
            return Ok(result);
        }

        private async Task<AuthResultVM> VerifyAndGenerateTokenAsyc(TokenRequestVM tokenRequestVM)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestVM.RefreshToken);
            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

            try
            {
                var tokenCheckResult = jwtTokenHandler.ValidateToken(tokenRequestVM.Token, _tokenValidationParameters,
                    out var validatedToken);
                return await GenerateJWTToken(dbUser, storedToken);
            }
            catch (SecurityTokenExpiredException)
            {
                if (storedToken.DateExipire < DateTime.UtcNow)
                {
                    return await GenerateJWTToken(dbUser, storedToken);
                }
                else
                {
                    return await GenerateJWTToken(dbUser, null);
                }
            }
        }

        private async Task<AuthResultVM> GenerateJWTToken(ApplicationUser user, RefreshToken rToken)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //Add user Role Claims
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));
        
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            if(rToken != null)
            {
                var rTokenResponse = new AuthResultVM()
                {
                    Token = jwtToken,
                    RefreshToken = rToken.Token,
                    ExpiresAt = token.ValidTo
                };
                return rTokenResponse;
            }

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                UserId = user.Id,
                IsRevoked = false,
                DateAdded = DateTime.UtcNow,
                DateExipire = DateTime.UtcNow.AddMonths(6),
                Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            var response = new AuthResultVM()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = token.ValidTo
            };
            return response;
        }
    }
}
