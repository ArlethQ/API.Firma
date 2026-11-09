using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace API.Firma.Services;

public static class ApiValidationProblemFactory
{
    public static BadRequestObjectResult Create(
        HttpContext httpContext,
        ModelStateDictionary modelState,
        StampValidationException? exception = null)
    {
        var errors = modelState
            .Where(entry => entry.Value?.Errors.Count > 0)
            .ToDictionary(
                entry => entry.Key,
                entry => entry.Value!.Errors
                    .Select(error => string.IsNullOrWhiteSpace(error.ErrorMessage)
                        ? "El valor proporcionado no es válido."
                        : error.ErrorMessage)
                    .ToArray());

        var errorDetails = errors
            .SelectMany(entry => entry.Value.Select(message =>
                string.IsNullOrWhiteSpace(entry.Key)
                    ? message
                    : $"{entry.Key}: {message}"))
            .ToArray();

        var problem = new ValidationProblemDetails(errors)
        {
            Status = StatusCodes.Status400BadRequest,
            Title = "La solicitud contiene errores de validación.",
            Detail = $"Se encontraron {errorDetails.Length} error(es): "
                + string.Join(" | ", errorDetails),
            Instance = httpContext.Request.Path
        };
        problem.Extensions["requestId"] = httpContext.TraceIdentifier;
        problem.Extensions["errorCount"] = errorDetails.Length;
        if (!string.IsNullOrWhiteSpace(exception?.DiagnosticCode))
        {
            problem.Extensions["diagnosticCode"] = exception.DiagnosticCode;
        }

        if (!string.IsNullOrWhiteSpace(exception?.CryptographicErrorCode))
        {
            problem.Extensions["cryptographicErrorCode"] = exception.CryptographicErrorCode;
        }

        return new BadRequestObjectResult(problem)
        {
            ContentTypes = { "application/problem+json" }
        };
    }
}
