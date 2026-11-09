using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Firma.Controllers;

[ApiController]
[Route("api/salud")]
public sealed class HealthController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet]
    public IActionResult Get() =>
        Ok(new
        {
            estado = "disponible",
            utc = DateTimeOffset.UtcNow
        });
}
