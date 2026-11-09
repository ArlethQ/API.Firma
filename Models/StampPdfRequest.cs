using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace API.Firma.Models;

public sealed class StampPdfRequest
{
    [Required]
    [FromForm(Name = "pdf")]
    public IFormFile Pdf { get; init; } = null!;

    [Required]
    [FromForm(Name = "certificado")]
    public IFormFile Certificado { get; init; } = null!;

    [Required]
    [StringLength(1024)]
    [FromForm(Name = "clave")]
    public string Clave { get; init; } = string.Empty;

    [FromForm(Name = "selloAvanzado")]
    public bool SelloAvanzado { get; init; }

    [StringLength(200)]
    [FromForm(Name = "razon")]
    public string? Razon { get; init; }

    [StringLength(200)]
    [FromForm(Name = "ubicacion")]
    public string? Ubicacion { get; init; }

    [StringLength(4000)]
    [FromForm(Name = "posiciones")]
    public string? Posiciones { get; init; }

    [Range(1, int.MaxValue)]
    [FromForm(Name = "pagina")]
    public int Pagina { get; init; } = 1;

    [Range(0, 2000, ErrorMessage = "X debe estar entre 0 y 2000 mm.")]
    [FromForm(Name = "xMm")]
    public double XMm { get; init; } = 10;

    [Range(0, 2000, ErrorMessage = "Y debe estar entre 0 y 2000 mm.")]
    [FromForm(Name = "yMm")]
    public double YMm { get; init; } = 10;

    [Range(40, 160)]
    [FromForm(Name = "anchoMm")]
    public double AnchoMm { get; init; } = 50.3;
}

public sealed record StampPlacement(
    int Pagina,
    double XMm,
    double YMm,
    double AnchoMm,
    int Rotacion = 0);
