using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using API.Firma.Models;
using System.IO.Compression;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.IO;
using SkiaSharp;

namespace API.Firma.Services;

internal static class IncrementalPdfSignatureAppender
{
    private const int ByteRangeDigits = 12;
    private const int MinimumReservedSignatureBytes = 16 * 1024;
    private const int TimestampedReservedSignatureBytes = 64 * 1024;
    private const double StampHeightRatio = 0.39;
    private const int PrintReadOnlyLockedAnnotationFlags = 4 | 64 | 128;
    private static readonly Oid Sha256Oid = new("2.16.840.1.101.3.4.2.1");
    private static readonly Regex ObjectRegex = new(
        @"(?m)(?<number>\d+)\s+(?<generation>\d+)\s+obj\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex ObjectWithBodyRegex = new(
        @"(?m)(?<start>^|\n)(?<number>\d+)\s+(?<generation>\d+)\s+obj\b(?<body>.*?)\bendobj\b",
        RegexOptions.CultureInvariant | RegexOptions.Singleline,
        TimeSpan.FromSeconds(2));
    private static readonly Regex RootRegex = new(
        @"/Root\s+(?<number>\d+)\s+(?<generation>\d+)\s+R\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex AcroFormRegex = new(
        @"/AcroForm\s+(?<number>\d+)\s+(?<generation>\d+)\s+R\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex FieldsReferenceRegex = new(
        @"/Fields\s+(?<number>\d+)\s+(?<generation>\d+)\s+R\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex AnnotsReferenceRegex = new(
        @"/Annots\s+(?<number>\d+)\s+(?<generation>\d+)\s+R\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex InlineFieldsRegex = new(
        @"/Fields\s*\[(?<items>[^\]]*)\]",
        RegexOptions.CultureInvariant | RegexOptions.Singleline,
        TimeSpan.FromSeconds(2));

    internal static void ValidateInput(byte[] originalPdf, int pageNumber)
    {
        var text = Encoding.Latin1.GetString(originalPdf);
        var rootMatch = RootRegex.Matches(text).LastOrDefault()
            ?? throw new InvalidOperationException("El PDF no contiene un catálogo raíz válido.");
        var rootNumber = int.Parse(rootMatch.Groups["number"].Value, CultureInfo.InvariantCulture);
        var rootGeneration = int.Parse(rootMatch.Groups["generation"].Value, CultureInfo.InvariantCulture);
        _ = FindPreviousXref(text);

        var rootObject = GetObject(text, rootNumber, rootGeneration);
        var page = FindPageObject(text, pageNumber);
        _ = GetPageBox(page.Body);

        if (!TryAddFieldToInlineAcroForm(rootObject.Body, 0, out _))
        {
            var acroFormMatch = AcroFormRegex.Match(rootObject.Body);
            if (acroFormMatch.Success)
            {
                var acroFormNumber = int.Parse(
                    acroFormMatch.Groups["number"].Value,
                    CultureInfo.InvariantCulture);
                var acroFormGeneration = int.Parse(
                    acroFormMatch.Groups["generation"].Value,
                    CultureInfo.InvariantCulture);
                var acroFormObject = GetObject(
                    text,
                    acroFormNumber,
                    acroFormGeneration);
                var fieldsReference = FieldsReferenceRegex.Match(acroFormObject.Body);
                if (fieldsReference.Success)
                {
                    var fieldsNumber = int.Parse(
                        fieldsReference.Groups["number"].Value,
                        CultureInfo.InvariantCulture);
                    var fieldsGeneration = int.Parse(
                        fieldsReference.Groups["generation"].Value,
                        CultureInfo.InvariantCulture);
                    var fieldsObject = GetObject(text, fieldsNumber, fieldsGeneration);
                    _ = AddReferenceToArray(fieldsObject.Body, 0, string.Empty);
                }
                else
                {
                    _ = AddReferenceToArray(
                        SetDictionaryEntry(acroFormObject.Body, "/SigFlags", "3"),
                        0,
                        "/Fields");
                }
            }
        }

        var annotsReference = AnnotsReferenceRegex.Match(page.Body);
        if (annotsReference.Success)
        {
            var annotsNumber = int.Parse(
                annotsReference.Groups["number"].Value,
                CultureInfo.InvariantCulture);
            var annotsGeneration = int.Parse(
                annotsReference.Groups["generation"].Value,
                CultureInfo.InvariantCulture);
            var annotsObject = GetObject(text, annotsNumber, annotsGeneration);
            _ = AddReferenceToArray(annotsObject.Body, 0, string.Empty);
        }
        else
        {
            _ = AddReferenceToArray(page.Body, 0, "/Annots");
        }
    }

    internal static void ValidatePdfSharpInput(byte[] originalPdf, IReadOnlyList<StampPlacement> placements)
    {
        _ = LoadPdfSharpStructure(originalPdf, placements);
    }

    public static async Task<byte[]> AppendAsync(
        byte[] originalPdf,
        X509Certificate2 signingCertificate,
        X509Certificate2Collection certificates,
        byte[] stampPng,
        IReadOnlyList<StampPlacement> placements,
        string? reason,
        string? location,
        Rfc3161TimestampService? timestampService,
        CancellationToken cancellationToken,
        bool usePdfSharpStructure = false)
    {
        var text = usePdfSharpStructure || placements.Count > 1
            ? LoadPdfSharpStructure(originalPdf, placements).SyntheticText
            : Encoding.Latin1.GetString(originalPdf);
        var rootMatch = RootRegex.Matches(text).LastOrDefault()
            ?? throw new InvalidOperationException("El PDF no contiene un catálogo raíz válido.");
        var rootNumber = int.Parse(rootMatch.Groups["number"].Value, CultureInfo.InvariantCulture);
        var rootGeneration = int.Parse(rootMatch.Groups["generation"].Value, CultureInfo.InvariantCulture);
        var previousXref = FindPreviousXref(text);
        var nextObjectNumber = ObjectRegex.Matches(text)
            .Select(match => int.Parse(match.Groups["number"].Value, CultureInfo.InvariantCulture))
            .DefaultIfEmpty(0)
            .Max() + 1;
        var signatureNumber = nextObjectNumber++;
        var fieldNumber = nextObjectNumber++;
        var imageNumber = nextObjectNumber++;
        var appearanceNumber = nextObjectNumber++;
        var updates = new List<PdfObjectUpdate>();
        var stampWidth = placements[0].AnchoMm * 72d / 25.4d;
        var image = CreateImageObject(stampPng);
        var appearance = CreateAppearanceObject(
            imageNumber,
            stampWidth,
            stampWidth * StampHeightRatio);

        var rootObject = GetObject(text, rootNumber, rootGeneration);
        if (TryAddFieldToInlineAcroForm(
                rootObject.Body,
                fieldNumber,
                out var updatedRootBody))
        {
            updates.Add(new PdfObjectUpdate(
                rootNumber,
                rootGeneration,
                updatedRootBody));
        }
        else
        {
            var acroFormMatch = AcroFormRegex.Match(rootObject.Body);
            if (acroFormMatch.Success)
            {
                var acroFormNumber = int.Parse(
                    acroFormMatch.Groups["number"].Value,
                    CultureInfo.InvariantCulture);
                var acroFormGeneration = int.Parse(
                    acroFormMatch.Groups["generation"].Value,
                    CultureInfo.InvariantCulture);
                var acroFormObject = GetObject(text, acroFormNumber, acroFormGeneration);
                var fieldsReference = FieldsReferenceRegex.Match(acroFormObject.Body);
                if (fieldsReference.Success)
                {
                    var fieldsNumber = int.Parse(
                        fieldsReference.Groups["number"].Value,
                        CultureInfo.InvariantCulture);
                    var fieldsGeneration = int.Parse(
                        fieldsReference.Groups["generation"].Value,
                        CultureInfo.InvariantCulture);
                    var fieldsObject = GetObject(text, fieldsNumber, fieldsGeneration);
                    updates.Add(new PdfObjectUpdate(
                        fieldsNumber,
                        fieldsGeneration,
                        AddReferenceToArray(fieldsObject.Body, fieldNumber, string.Empty)));
                }
                else
                {
                    updates.Add(new PdfObjectUpdate(
                        acroFormNumber,
                        acroFormGeneration,
                        AddReferenceToArray(
                            SetDictionaryEntry(acroFormObject.Body, "/SigFlags", "3"),
                            fieldNumber,
                            "/Fields")));
                }

                if (fieldsReference.Success)
                {
                    updates.Add(new PdfObjectUpdate(
                        acroFormNumber,
                        acroFormGeneration,
                        SetDictionaryEntry(acroFormObject.Body, "/SigFlags", "3")));
                }
            }
            else
            {
                var acroFormNumber = nextObjectNumber++;
                updates.Add(new PdfObjectUpdate(
                    rootNumber,
                    rootGeneration,
                    SetDictionaryEntry(rootObject.Body, "/AcroForm", acroFormNumber + " 0 R")));
                updates.Add(new PdfObjectUpdate(
                    acroFormNumber,
                    0,
                    "<< /Fields [" + fieldNumber + " 0 R] /SigFlags 3 >>"));
            }
        }

        var fieldName = "API.Firma-" + DateTime.UtcNow.ToString(
            "yyyyMMddHHmmssfff",
            CultureInfo.InvariantCulture);
        var signatureField = $"/Subtype /Widget /FT /Sig /T ({EscapePdfString(fieldName)}) /V {signatureNumber} 0 R /F 4 /Ff 1";
        var multiplePlacements = placements.Count > 1;
        updates.Add(new PdfObjectUpdate(imageNumber, 0, image));
        updates.Add(new PdfObjectUpdate(appearanceNumber, 0, appearance));

        for (var index = 0; index < placements.Count; index++)
        {
            var placement = placements[index];
            var page = FindPageObject(text, placement.Pagina);
            if (multiplePlacements && index == 0)
            {
                // Keep the signature field separate so PDF viewers draw both visible marks as stamps.
                updates.Add(new PdfObjectUpdate(
                    fieldNumber,
                    0,
                    $"<< /Type /Annot {signatureField} /Rect [0 0 0 0] /P {page.Number} {page.Generation} R >>"));
                AppendPageAnnotation(text, page, fieldNumber, updates);
            }

            var annotationNumber = multiplePlacements ? nextObjectNumber++ : fieldNumber;
            var entries = multiplePlacements
                ? $"/Subtype /Stamp /F {PrintReadOnlyLockedAnnotationFlags}"
                : signatureField;
            var annotation = CreateStampAnnotation(page, placement, appearanceNumber, entries);
            updates.Add(new PdfObjectUpdate(annotationNumber, 0, annotation));
            AppendPageAnnotation(text, page, annotationNumber, updates);
        }

        var signatureSize = timestampService?.IsEnabled == true
            ? TimestampedReservedSignatureBytes
            : Math.Max(
                MinimumReservedSignatureBytes,
                (await CreateSignature(
                    new byte[] { 0 },
                    signingCertificate,
                    certificates,
                    timestampService: null,
                    cancellationToken: cancellationToken)).Length + 2048);
        updates.Insert(
            0,
            new PdfObjectUpdate(
                signatureNumber,
                0,
                BuildSignatureObject(signatureSize, reason, location)));

        var suffix = BuildSuffix(
            originalPdf.Length,
            updates,
            nextObjectNumber,
            rootNumber,
            rootGeneration,
            previousXref);
        var preliminary = Combine(originalPdf, suffix.Bytes);
        var contentsHexStart = originalPdf.Length + suffix.ContentsHexStart;
        var contentsStart = contentsHexStart - 1;
        var contentsEnd = contentsHexStart + suffix.ContentsHexLength + 1;
        var byteRangeValues = new[]
        {
            0L,
            contentsStart,
            contentsEnd,
            preliminary.Length - contentsEnd
        };
        var byteRangeValue = string.Join(
            " ",
            byteRangeValues.Skip(1).Select(value =>
                value.ToString("D" + ByteRangeDigits, CultureInfo.InvariantCulture)));
        var byteRangePlaceholder =
            "[0 "
            + new string('0', ByteRangeDigits)
            + " "
            + new string('0', ByteRangeDigits)
            + " "
            + new string('0', ByteRangeDigits)
            + "]";
        var byteRangeReplacement = "[0 " + byteRangeValue + "]";
        ReplaceAscii(
            preliminary,
            originalPdf.Length + suffix.ByteRangeOffset,
            byteRangePlaceholder,
            byteRangeReplacement);

        var signedContent = new byte[preliminary.Length - (contentsEnd - contentsStart)];
        Buffer.BlockCopy(preliminary, 0, signedContent, 0, contentsStart);
        Buffer.BlockCopy(
            preliminary,
            contentsEnd,
            signedContent,
            contentsStart,
            preliminary.Length - contentsEnd);
        var cmsHex = Convert.ToHexString(
            await CreateSignature(
                signedContent,
                signingCertificate,
                certificates,
                timestampService,
                cancellationToken));
        if (cmsHex.Length > suffix.ContentsHexLength)
        {
            throw new InvalidOperationException("El espacio reservado para la firma CMS es insuficiente.");
        }

        Encoding.ASCII.GetBytes(cmsHex).CopyTo(preliminary, contentsHexStart);
        for (var index = contentsHexStart + cmsHex.Length;
             index < contentsHexStart + suffix.ContentsHexLength;
             index++)
        {
            preliminary[index] = (byte)'0';
        }

        return preliminary;
    }

    private static IncrementalSuffix BuildSuffix(
        int originalLength,
        IReadOnlyList<PdfObjectUpdate> updates,
        int nextObjectNumber,
        int rootNumber,
        int rootGeneration,
        long previousXref)
    {
        var builder = new StringBuilder("\n");
        var offsets = new Dictionary<int, int>();
        var byteRangeOffset = -1;
        var contentsHexStart = -1;
        var contentsHexLength = -1;
        foreach (var update in updates)
        {
            var builderOffset = Encoding.Latin1.GetByteCount(builder.ToString());
            offsets[update.Number] = originalLength + builderOffset;
            var objectText = update.Number
                + " "
                + update.Generation
                + " obj\n"
                + update.Body
                + "\nendobj\n";
            if (update.Number == updates[0].Number)
            {
                byteRangeOffset = builderOffset + objectText.IndexOf("[0 ", StringComparison.Ordinal);
                var contentsMarker = objectText.IndexOf(
                    "/Contents <",
                    StringComparison.Ordinal);
                var contentsStartInObject = contentsMarker + "/Contents <".Length;
                var contentsEndInObject = objectText.IndexOf(
                    '>',
                    contentsStartInObject);
                contentsHexStart = builderOffset + contentsStartInObject;
                contentsHexLength = contentsEndInObject - contentsStartInObject;
            }

            builder.Append(objectText);
        }

        var xrefOffset = Encoding.Latin1.GetByteCount(builder.ToString()) + originalLength;
        builder.Append("xref\n");
        foreach (var group in offsets.OrderBy(item => item.Key))
        {
            builder.Append(group.Key.ToString(CultureInfo.InvariantCulture));
            builder.Append(" 1\n");
            builder.Append(group.Value.ToString("D10", CultureInfo.InvariantCulture));
            builder.Append(" 00000 n \n");
        }

        builder.Append("trailer\n<<\n/Size ");
        builder.Append(nextObjectNumber.ToString(CultureInfo.InvariantCulture));
        builder.Append("\n/Root ");
        builder.Append(rootNumber.ToString(CultureInfo.InvariantCulture));
        builder.Append(' ');
        builder.Append(rootGeneration.ToString(CultureInfo.InvariantCulture));
        builder.Append(" R\n/Prev ");
        builder.Append(previousXref.ToString(CultureInfo.InvariantCulture));
        builder.Append("\n>>\nstartxref\n");
        builder.Append(xrefOffset.ToString(CultureInfo.InvariantCulture));
        builder.Append("\n%%EOF\n");

        return new IncrementalSuffix(
            Encoding.Latin1.GetBytes(builder.ToString()),
            byteRangeOffset,
            contentsHexStart,
            contentsHexLength);
    }

    private static string BuildSignatureObject(
        int reservedSignatureBytes,
        string? reason,
        string? location)
    {
        var contents = new string('0', reservedSignatureBytes * 2);
        var date = DateTime.UtcNow.ToString("yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture);
        return "<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n"
            + "/SubFilter /adbe.pkcs7.detached\n"
            + "/ByteRange [0 "
            + new string('0', ByteRangeDigits)
            + " "
            + new string('0', ByteRangeDigits)
            + " "
            + new string('0', ByteRangeDigits)
            + "]\n/Contents <"
            + contents
            + ">\n/M (D:"
            + date
            + ")\n/Reason ("
            + EscapePdfString(reason)
            + ")\n/Location ("
            + EscapePdfString(location)
            + ")\n>>";
    }

    private static async Task<byte[]> CreateSignature(
        byte[] content,
        X509Certificate2 signingCertificate,
        X509Certificate2Collection certificates,
        Rfc3161TimestampService? timestampService,
        CancellationToken cancellationToken)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var signer = new CmsSigner(
            SubjectIdentifierType.IssuerAndSerialNumber,
            signingCertificate)
        {
            DigestAlgorithm = Sha256Oid,
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
        foreach (var certificate in certificates)
        {
            if (!string.Equals(
                    certificate.Thumbprint,
                    signingCertificate.Thumbprint,
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(
                    certificate.Subject,
                    certificate.Issuer,
                    StringComparison.OrdinalIgnoreCase))
            {
                signer.Certificates.Add(certificate);
            }
        }

        cms.ComputeSignature(signer, silent: true);
        return timestampService is not null && timestampService.IsEnabled
            ? await timestampService.AddTimestampAsync(cms, cancellationToken)
            : cms.Encode();
    }

    private static PdfObject GetObject(string text, int number, int generation)
    {
        var matches = Regex.Matches(
            text,
            @"(?m)(?<start>^|\n)"
                + number
                + @"\s+"
                + generation
                + @"\s+obj\b(?<body>.*?)\bendobj\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            TimeSpan.FromSeconds(2));
        var match = matches.LastOrDefault();
        if (match is null)
        {
            throw new InvalidOperationException(
                "No se encontró el objeto PDF " + number + " " + generation + ".");
        }

        return new PdfObject(number, generation, match.Groups["body"].Value.Trim());
    }

    private static PdfSharpStructure LoadPdfSharpStructure(
        byte[] originalPdf,
        IReadOnlyList<StampPlacement> placements)
    {
        using var input = new MemoryStream(originalPdf, writable: false);
        using var document = PdfReader.Open(input, PdfDocumentOpenMode.Import);
        var catalog = document.Internals.Catalog
            ?? throw new InvalidOperationException("El PDF no contiene un catálogo raíz válido.");
        var rootReference = catalog.Reference
            ?? throw new InvalidOperationException("El catálogo raíz no tiene una referencia indirecta.");
        var records = new Dictionary<(int Number, int Generation), string>();

        AddPdfSharpObject(records, catalog);
        foreach (var documentPage in document.Pages)
        {
            AddPdfSharpObject(records, documentPage);
        }

        AddReferencedPdfSharpObject(records, catalog.Elements.GetValue("/AcroForm"));
        if (catalog.Elements.GetValue("/AcroForm") is PdfDictionary acroForm)
        {
            AddReferencedPdfSharpObject(records, acroForm.Elements.GetValue("/Fields"));
        }
        else if (catalog.Elements.GetReference("/AcroForm") is PdfReference acroFormReference
            && acroFormReference.Value is PdfDictionary referencedAcroForm)
        {
            AddPdfSharpObject(records, referencedAcroForm);
            AddReferencedPdfSharpObject(records, referencedAcroForm.Elements.GetValue("/Fields"));
        }

        foreach (var placement in placements)
        {
            if (placement.Pagina < 1 || placement.Pagina > document.PageCount)
            {
                throw new StampValidationException(
                    "posiciones",
                    $"El PDF tiene {document.PageCount} página(s); la página {placement.Pagina} no existe.");
            }

            var page = document.Pages[placement.Pagina - 1];
            if (page.Reference is null)
                throw new InvalidOperationException("La página seleccionada no tiene una referencia indirecta.");

            AddReferencedPdfSharpObject(records, page.Elements.GetValue("/Annots"));
        }

        var allObjectNumbers = document.Internals.GetAllObjects()
            .Select(item => item.Reference)
            .Where(reference => reference is not null && reference.ObjectNumber > 0)
            .Select(reference => (reference!.ObjectNumber, reference.GenerationNumber))
            .Distinct()
            .ToArray();
        var maxObjectNumber = allObjectNumbers
            .Select(item => item.ObjectNumber)
            .DefaultIfEmpty(rootReference.ObjectNumber)
            .Max();
        var previousXref = FindPreviousXref(Encoding.Latin1.GetString(originalPdf));
        var builder = new StringBuilder();
        foreach (var objectId in allObjectNumbers)
        {
            if (records.ContainsKey(objectId))
                continue;

            builder.Append(objectId.ObjectNumber.ToString(CultureInfo.InvariantCulture));
            builder.Append(' ');
            builder.Append(objectId.GenerationNumber.ToString(CultureInfo.InvariantCulture));
            builder.Append(" obj\n<<>>\nendobj\n");
        }

        foreach (var record in records)
        {
            builder.Append(record.Key.Number.ToString(CultureInfo.InvariantCulture));
            builder.Append(' ');
            builder.Append(record.Key.Generation.ToString(CultureInfo.InvariantCulture));
            builder.Append(" obj\n");
            builder.Append(record.Value);
            builder.Append("\nendobj\n");
        }

        builder.Append("trailer\n<< /Root ");
        builder.Append(rootReference.ObjectNumber.ToString(CultureInfo.InvariantCulture));
        builder.Append(' ');
        builder.Append(rootReference.GenerationNumber.ToString(CultureInfo.InvariantCulture));
        builder.Append(" R /Size ");
        builder.Append((maxObjectNumber + 1).ToString(CultureInfo.InvariantCulture));
        builder.Append(" >>\nstartxref\n");
        builder.Append(previousXref.ToString(CultureInfo.InvariantCulture));
        builder.Append("\n%%EOF\n");

        return new PdfSharpStructure(builder.ToString());
    }

    private static void AddReferencedPdfSharpObject(
        IDictionary<(int Number, int Generation), string> records,
        PdfItem? item)
    {
        if (item is PdfReference reference && reference.Value is PdfSharp.Pdf.PdfObject pdfObject)
        {
            AddPdfSharpObject(records, pdfObject);
        }
    }

    private static void AddPdfSharpObject(
        IDictionary<(int Number, int Generation), string> records,
        PdfSharp.Pdf.PdfObject pdfObject)
    {
        var reference = pdfObject.Reference;
        if (reference is not null)
        {
            records[(reference.ObjectNumber, reference.GenerationNumber)] =
                pdfObject.ToString() ?? string.Empty;
        }
    }

    private static PdfObject FindPageObject(string text, int pageNumber)
    {
        var objects = new Dictionary<(int Number, int Generation), PdfObject>();
        foreach (Match match in ObjectWithBodyRegex.Matches(text))
        {
            var number = int.Parse(
                match.Groups["number"].Value,
                CultureInfo.InvariantCulture);
            var generation = int.Parse(
                match.Groups["generation"].Value,
                CultureInfo.InvariantCulture);
            objects[(number, generation)] = new PdfObject(
                number,
                generation,
                match.Groups["body"].Value.Trim());
        }

        var pages = objects.Values
            .Where(page => Regex.IsMatch(page.Body, @"/Type\s*/Page\b"))
            .ToArray();
        if (pageNumber < 1 || pageNumber > pages.Length)
        {
            throw new InvalidOperationException(
                "No se encontró la página " + pageNumber + " para el estampado incremental.");
        }

        return pages[pageNumber - 1];
    }

    private static PageBox GetPageBox(string body)
    {
        var match = Regex.Match(
            body,
            @"/MediaBox\s*\[\s*(?<left>-?[\d.]+)\s+(?<bottom>-?[\d.]+)\s+(?<right>-?[\d.]+)\s+(?<top>-?[\d.]+)\s*\]",
            RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return new PageBox(612, 792);
        }

        var left = double.Parse(match.Groups["left"].Value, CultureInfo.InvariantCulture);
        var bottom = double.Parse(match.Groups["bottom"].Value, CultureInfo.InvariantCulture);
        var right = double.Parse(match.Groups["right"].Value, CultureInfo.InvariantCulture);
        var top = double.Parse(match.Groups["top"].Value, CultureInfo.InvariantCulture);
        return new PageBox(right - left, top - bottom);
    }

    private static string CreateImageObject(byte[] stampPng)
    {
        using var bitmap = SKBitmap.Decode(stampPng)
            ?? throw new InvalidOperationException("No se pudo preparar la imagen del estampado.");
        var rgb = new byte[bitmap.Width * bitmap.Height * 3];
        var offset = 0;
        for (var y = 0; y < bitmap.Height; y++)
        {
            for (var x = 0; x < bitmap.Width; x++)
            {
                var color = bitmap.GetPixel(x, y);
                rgb[offset++] = color.Red;
                rgb[offset++] = color.Green;
                rgb[offset++] = color.Blue;
            }
        }

        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
        {
            zlib.Write(rgb);
        }

        return "<< /Type /XObject /Subtype /Image /Width "
            + bitmap.Width
            + " /Height "
            + bitmap.Height
            + " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Mask [255 255 255 255 255 255] /Filter /FlateDecode /Length "
            + compressed.Length
            + " >>\nstream\n"
            + Encoding.Latin1.GetString(compressed.ToArray())
            + "\nendstream";
    }

    private static string CreateAppearanceObject(
        int imageNumber,
        double width,
        double height)
    {
        var content = "q\n"
            + FormatNumber(width)
            + " 0 0 "
            + FormatNumber(height)
            + " 0 0 cm\n/Im1 Do\nQ\n";
        return "<< /Type /XObject /Subtype /Form /BBox [0 0 "
            + FormatNumber(width)
            + " "
            + FormatNumber(height)
            + "] /Resources << /XObject << /Im1 "
            + imageNumber
            + " 0 R >> >> /Length "
            + Encoding.ASCII.GetByteCount(content)
            + " >>\nstream\n"
            + content
            + "endstream";
    }

    private static string CreateStampAnnotation(
        PdfObject page,
        StampPlacement placement,
        int appearanceNumber,
        string entries)
    {
        var width = placement.AnchoMm * 72d / 25.4d;
        var height = width * StampHeightRatio;
        var x = placement.XMm * 72d / 25.4d;
        var y = GetPageBox(page.Body).Height - (placement.YMm * 72d / 25.4d) - height;
        return $"<< /Type /Annot {entries} /Rect [{FormatNumber(x)} {FormatNumber(y)} "
            + $"{FormatNumber(x + width)} {FormatNumber(y + height)}] /P {page.Number} {page.Generation} R "
            + $"/AP << /N {appearanceNumber} 0 R >> >>";
    }

    private static void AppendPageAnnotation(
        string text,
        PdfObject page,
        int annotationNumber,
        List<PdfObjectUpdate> updates)
    {
        var container = page;
        var key = "/Annots";
        var annotsReference = AnnotsReferenceRegex.Match(page.Body);
        if (annotsReference.Success)
        {
            var annotsNumber = int.Parse(
                annotsReference.Groups["number"].Value,
                CultureInfo.InvariantCulture);
            var annotsGeneration = int.Parse(
                annotsReference.Groups["generation"].Value,
                CultureInfo.InvariantCulture);
            container = GetObject(text, annotsNumber, annotsGeneration);
            key = string.Empty;
        }

        var updateIndex = updates.FindIndex(update => update.Number == container.Number);
        var currentBody = updateIndex < 0 ? container.Body : updates[updateIndex].Body;
        var updated = new PdfObjectUpdate(
            container.Number,
            container.Generation,
            AddReferenceToArray(currentBody, annotationNumber, key));
        if (updateIndex < 0)
            updates.Add(updated);
        else
            updates[updateIndex] = updated;
    }

    private static string FormatNumber(double value) =>
        value.ToString("0.####", CultureInfo.InvariantCulture);

    private static string SetDictionaryEntry(string body, string key, string value)
    {
        var pattern = Regex.Escape(key)
            + @"\s+(?:\d+\s+\d+\s+R|\[[^\]]*\]|\d+)";
        if (Regex.IsMatch(body, pattern, RegexOptions.CultureInvariant))
        {
            return Regex.Replace(
                body,
                pattern,
                key + " " + value,
                RegexOptions.CultureInvariant);
        }

        var close = body.LastIndexOf(">>", StringComparison.Ordinal);
        if (close < 0)
        {
            throw new InvalidOperationException("El diccionario PDF no está correctamente formado.");
        }

        return body.Insert(close, "\n" + key + " " + value + "\n");
    }

    private static string AddReferenceToArray(string body, int objectNumber, string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            var arrayStart = body.IndexOf('[', StringComparison.Ordinal);
            var arrayEnd = body.IndexOf(']', arrayStart + 1);
            if (arrayStart < 0 || arrayEnd < 0)
            {
                throw new InvalidOperationException("El arreglo de campos PDF no está correctamente formado.");
            }

            return body.Insert(arrayEnd, " " + objectNumber + " 0 R");
        }

        var pattern = Regex.Escape(key) + @"\s*\[(?<items>[^\]]*)\]";
        var match = Regex.Match(
            body,
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.Singleline);
        if (match.Success)
        {
            return body.Remove(match.Index, match.Length)
                .Insert(
                    match.Index,
                    key
                        + " ["
                        + match.Groups["items"].Value.Trim()
                        + " "
                        + objectNumber
                        + " 0 R]");
        }

        var close = body.LastIndexOf(">>", StringComparison.Ordinal);
        if (close < 0)
        {
            throw new InvalidOperationException("El diccionario PDF no está correctamente formado.");
        }

        return body.Insert(close, "\n" + key + " [" + objectNumber + " 0 R]\n");
    }

    private static bool TryAddFieldToInlineAcroForm(
        string rootBody,
        int fieldNumber,
        out string updatedRootBody)
    {
        var acroFormIndex = rootBody.IndexOf("/AcroForm", StringComparison.Ordinal);
        if (acroFormIndex < 0)
        {
            updatedRootBody = rootBody;
            return false;
        }

        var dictionaryStart = rootBody.IndexOf("<<", acroFormIndex, StringComparison.Ordinal);
        if (dictionaryStart < 0)
        {
            updatedRootBody = rootBody;
            return false;
        }

        var fieldsMatch = InlineFieldsRegex.Match(rootBody, dictionaryStart);
        if (!fieldsMatch.Success)
        {
            updatedRootBody = rootBody;
            return false;
        }

        var items = fieldsMatch.Groups["items"].Value.Trim();
        var replacement = "/Fields ["
            + items
            + " "
            + fieldNumber
            + " 0 R]";
        updatedRootBody = rootBody.Remove(fieldsMatch.Index, fieldsMatch.Length)
            .Insert(fieldsMatch.Index, replacement);

        var duplicateAcroForm = AcroFormRegex.Match(
            updatedRootBody,
            fieldsMatch.Index + replacement.Length);
        if (duplicateAcroForm.Success)
        {
            updatedRootBody = updatedRootBody.Remove(
                duplicateAcroForm.Index,
                duplicateAcroForm.Length);
        }

        return true;
    }

    private static long FindPreviousXref(string text)
    {
        var matches = Regex.Matches(
            text,
            @"startxref\s+(?<offset>\d+)",
            RegexOptions.CultureInvariant);
        return matches.Count == 0
            ? throw new InvalidOperationException("El PDF no contiene una tabla xref válida.")
            : long.Parse(matches[^1].Groups["offset"].Value, CultureInfo.InvariantCulture);
    }

    private static string EscapePdfString(string? value) =>
        (value ?? string.Empty)
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("(", "\\(", StringComparison.Ordinal)
            .Replace(")", "\\)", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);

    private static byte[] Combine(byte[] original, byte[] suffix)
    {
        var result = new byte[original.Length + suffix.Length];
        Buffer.BlockCopy(original, 0, result, 0, original.Length);
        Buffer.BlockCopy(suffix, 0, result, original.Length, suffix.Length);
        return result;
    }

    private static void ReplaceAscii(
        byte[] target,
        int offset,
        string oldValue,
        string newValue)
    {
        if (oldValue.Length != newValue.Length)
        {
            throw new InvalidOperationException("La sustitución PDF alteraría el tamaño de la revisión.");
        }

        var oldBytes = Encoding.ASCII.GetBytes(oldValue);
        var newBytes = Encoding.ASCII.GetBytes(newValue);
        if (!target.AsSpan(offset, oldBytes.Length).SequenceEqual(oldBytes))
        {
            throw new InvalidOperationException("No se encontró el ByteRange reservado.");
        }

        newBytes.CopyTo(target, offset);
    }

    private sealed record PdfObject(int Number, int Generation, string Body);

    private sealed record PageBox(double Width, double Height);

    private sealed record PdfObjectUpdate(int Number, int Generation, string Body);

    private sealed record IncrementalSuffix(
        byte[] Bytes,
        int ByteRangeOffset,
        int ContentsHexStart,
        int ContentsHexLength);

    private sealed record PdfSharpStructure(string SyntheticText);
}
