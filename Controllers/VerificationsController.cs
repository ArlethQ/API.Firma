using API.Firma.Services;
using API.Firma.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace API.Firma.Controllers;

[ApiController]
[Route("api/verificaciones")]
public sealed class VerificationsController(QrTokenService qrTokenService) : ControllerBase
{
    [AllowAnonymous]
    [EnableRateLimiting("verificacion")]
    [HttpGet("qr")]
    [Produces("application/json")]
    [ProducesResponseType<QrVerificationResult>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests)]
    public IActionResult VerifyQr([FromQuery] string token)
    {
        try
        {
            return Ok(qrTokenService.Verify(token));
        }
        catch (StampValidationException exception)
        {
            return Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "QR no válido",
                detail: exception.Message);
        }
    }
}
