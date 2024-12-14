using JWTAuth.Data.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize(Roles =UserRoles.Student+","+UserRoles.Manager)]
    public class HomeController : ControllerBase
    {
        public HomeController()
        {
        }
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Wecome to HomeController - Main");
        }

        [HttpGet("students")]
        [Authorize(Roles = UserRoles.Student)]
        public IActionResult GetStudent()
        {
            return Ok("Wecome to HomeController - Student");
        }

        [HttpGet("manager")]
        [Authorize(Roles = UserRoles.Manager)]
        public IActionResult GetManager()
        {
            return Ok("Wecome to HomeController - Manager");
        }

    }
}
