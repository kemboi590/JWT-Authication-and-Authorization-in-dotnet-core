using JWTAuth.Data.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize(Roles = UserRoles.Manager)]
    public class ManagementController : ControllerBase
    {
        public ManagementController()
        {
        }
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Hello World");
        }

    }
}
