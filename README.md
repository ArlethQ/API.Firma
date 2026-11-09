# API.Firma

API ASP.NET Core para estampar códigos QR, firmar documentos PDF y validar firmas digitales.

## Ejecutar localmente

Requisitos: SDK de .NET 10.

```powershell
dotnet restore
dotnet run --launch-profile http
```

La API quedará disponible en `http://localhost:5029` y Swagger en
`http://localhost:5029/swagger`.

El entorno `Development` incluye claves locales de prueba para facilitar la
ejecución después de clonar. No deben utilizarse en producción.

## Configuración de producción

Configure los valores sensibles mediante variables de entorno o un proveedor
de secretos. ASP.NET Core representa las secciones anidadas con doble guion
bajo:

```text
ApiSecurity__ApiKey
QrSecurity__SigningKey
TimestampAuthority__Username
TimestampAuthority__Password
```

Las claves de API y QR deben tener al menos 32 caracteres. Si se activa la TSA,
también debe configurarse su usuario y contraseña.

## Pruebas

```powershell
dotnet test API.Firma.Tests/API.Firma.Tests.csproj
```
