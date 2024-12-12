using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
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
