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
                Custom = "DefaultValue"  // Revisit this line
            };

            var result = await _userManager.CreateAsync(newUser, registerVM.Password); // used to create a new user in the database

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
            foreach (var error in result.Errors) // used to log the errors which occurred during the user creation process
            {
                _logger.LogError($"Error: {error.Description}"); //_logger.LogError() is used to log the error messages
            }

            return BadRequest("User could not be created, try again"); // used to return a bad request response if the user creation process fails
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginVM loginVM)
        {
           if (!ModelState.IsValid)
            {
                return BadRequest("Please, Provide all the required fields!");
            }

            var userExist = await _userManager.FindByEmailAsync(loginVM.Email); // returns the user with the specified email address
            if (userExist != null && await _userManager.CheckPasswordAsync(userExist, loginVM.Password)) 
            {
                var tokenValue = await GenerateJWTToken(userExist, null); // used to generate the JWT token, new RefreshToken() is used to generate a new refresh token
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

            var result = await VerifyAndGenerateTokenAsync(tokenRequestVM);
            return Ok(result);
        }

        private async Task<AuthResultVM> VerifyAndGenerateTokenAsync(TokenRequestVM tokenRequestVM)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestVM.RefreshToken);
           
            if (storedToken == null) //storedToken is the refresh token
            {
                throw new InvalidOperationException("Refresh token not found.");
            }

            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
            if (dbUser == null)
            {
                throw new InvalidOperationException("User not found.");
            }

            // Default response
            AuthResultVM authResult;

            try
            {
                // Validate the token
                jwtTokenHandler.ValidateToken(tokenRequestVM.Token, _tokenValidationParameters, out var validatedToken);

                // The token has not expired; generate a new JWT and return it
                authResult = await GenerateJWTToken(dbUser, storedToken);
            }
            catch (SecurityTokenExpiredException)
            {
                // Handle expiration of the access token
                if (storedToken.DateExipire >= DateTime.UtcNow)
                {
                    // The refresh token is still valid; generate a new JWT and return it
                    authResult = await GenerateJWTToken(dbUser, storedToken);
                }
                else
                {
                    // Refresh token has expired; generate a token and a new refresh token
                    authResult = await GenerateJWTToken(dbUser, null);
                }
            }

            return authResult;
        }

        private async Task<AuthResultVM> GenerateJWTToken(ApplicationUser user, RefreshToken? rToken)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName ?? string.Empty), // used to store the user name in the token. Name: "John Doe"
                new Claim(ClaimTypes.NameIdentifier, user.Id), // used to store the user id in the token 
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty), // used to store the user email in the token
                new Claim(JwtRegisteredClaimNames.Sub, user.Email ?? string.Empty), //  It is the subject meaning unique identifier of the user
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Jti in full is Jwt Id, it is used to store the unique identifier for the token
            };

            //Add user Role Claims
            var userRoles = await _userManager.GetRolesAsync(user); // GetRolesAsync is used to get the roles of the user
            foreach (var userRole in userRoles) // used to add the user role to the token, i.e Admin will be stored this way Role: "Admin"
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole)); // The role is known by the app because it is stored in the database
            }

            var jwtSecret = _configuration["JWT:Secret"];
            if (string.IsNullOrEmpty(jwtSecret))
            {
                throw new InvalidOperationException("JWT Secret is not configured properly.");
            }
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));                 

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddHours(1),
                claims: authClaims, // used to store the user information in the token
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)); 

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token); // used to write the token to a string value. JwtSecurityTokenHandler is used to handle the token creation and validation

            if (rToken != null) // means the token is not null, then we can return the token- this is the case when the token is not expired
            {
                var rTokenResponse = new AuthResultVM()
                {
                    Token = jwtToken, // Token is used to store the JWT token
                    RefreshToken = rToken.Token, // RefreshToken is used to store the refresh token
                    ExpiresAt = token.ValidTo // ExpiresAt is used to store the token expiration time
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
                Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString(),
                User = user // Set the required User property
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
