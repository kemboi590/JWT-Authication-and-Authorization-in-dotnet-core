using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
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
