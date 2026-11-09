using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace API.Firma.Models;

public sealed class ValidatePdfSignatureRequest
{
    [Required]
    [FromForm(Name = "pdf")]
    public IFormFile Pdf { get; init; } = null!;
}
