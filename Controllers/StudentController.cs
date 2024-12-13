using JWTAuth.Data.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize(Roles =UserRoles.Student)]
    public class StudentController : ControllerBase
    {
        public StudentController()
        {
        }
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Hello World");
        }
    }
}
