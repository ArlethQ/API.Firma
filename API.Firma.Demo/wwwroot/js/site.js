(() => {
  const pdfInput = document.getElementById("Pdf");
  const canvas = document.getElementById("pdfCanvas");
  const stage = document.getElementById("pdfStage");
  const placeholder = document.getElementById("pdfPlaceholder");
  const footprint = document.getElementById("stampFootprint");
  const resizeHandle = document.getElementById("resizeHandle");
  const pageInput = document.getElementById("Pagina");
  const xInput = document.getElementById("XMm");
  const yInput = document.getElementById("YMm");
  const widthInput = document.getElementById("AnchoMm");
  const positionSelectedInput = document.getElementById("PosicionSeleccionada");
  const previousButton = document.getElementById("previousPage");
  const nextButton = document.getElementById("nextPage");
  const currentPageLabel = document.getElementById("currentPage");
  const pageCountLabel = document.getElementById("pageCount");
  const selectionStatus = document.getElementById("selectionStatus");
  const stampForm = document.getElementById("stampForm");
  const submitButton = document.getElementById("submitButton");
  const submitStatus = document.getElementById("submitStatus");
  const certificateInput = document.getElementById("CertificadoFirma");
  const certificatePasswordInput = document.getElementById("ClaveCertificado");

  if (!pdfInput || !canvas || !stage) {
    return;
  }

  let pdfDocument = null;
  let pdfPage = null;
  let pageWidthMm = 0;
  let pageHeightMm = 0;
  let renderTask = null;
  let selectedPosition = null;
  let drawingStart = null;
  let resizeStart = null;
  let pointerMoved = false;
  const minimumStampWidthMm = 50;
  const maximumStampWidthMm = 160;
  const stampHeightRatio = 0.42;

  const setStatus = (message, isError = false) => {
    selectionStatus.textContent = message;
    selectionStatus.classList.toggle("is-error", isError);
  };

  const setSubmitStatus = (message, isError = false) => {
    if (!submitStatus) {
      return;
    }

    submitStatus.textContent = message;
    submitStatus.classList.toggle("is-error", isError);
  };

  const updateNavigation = () => {
    const page = Number(pageInput.value) || 1;
    const total = pdfDocument?.numPages ?? 0;
    currentPageLabel.textContent = page.toString();
    pageCountLabel.textContent = total.toString();
    previousButton.disabled = !pdfDocument || page <= 1;
    nextButton.disabled = !pdfDocument || page >= total;
  };

  const updateFootprint = () => {
    if (!selectedPosition || !pdfPage) {
      footprint.hidden = true;
      return;
    }

    const displayedWidth = canvas.clientWidth;
    const displayedHeight = canvas.clientHeight;
    const stampWidthMm = Math.max(0, Number(widthInput.value) || 0);
    footprint.style.left = `${canvas.offsetLeft + (selectedPosition.xMm / pageWidthMm) * displayedWidth}px`;
    footprint.style.top = `${canvas.offsetTop + (selectedPosition.yMm / pageHeightMm) * displayedHeight}px`;
    footprint.style.width = `${(stampWidthMm / pageWidthMm) * displayedWidth}px`;
    footprint.style.height = `${((stampWidthMm * stampHeightRatio) / pageHeightMm) * displayedHeight}px`;
    footprint.hidden = false;
  };

  const getPagePoint = event => {
    const bounds = canvas.getBoundingClientRect();
    return {
      xMm: Math.max(
        0,
        Math.min(
          ((event.clientX - bounds.left) / bounds.width) * pageWidthMm,
          pageWidthMm)),
      yMm: Math.max(
        0,
        Math.min(
          ((event.clientY - bounds.top) / bounds.height) * pageHeightMm,
          pageHeightMm))
    };
  };

  const applySelection = (rawX, rawY, requestedWidth) => {
    const widthMm = Math.min(
      maximumStampWidthMm,
      pageWidthMm,
      pageHeightMm / stampHeightRatio,
      Math.max(minimumStampWidthMm, requestedWidth));
    const xMm = Math.max(0, Math.min(rawX, pageWidthMm - widthMm));
    const yMm = Math.max(
      0,
      Math.min(rawY, pageHeightMm - (widthMm * stampHeightRatio)));

    selectedPosition = {
      page: Number(pageInput.value),
      xMm,
      yMm
    };
    xInput.value = xMm.toFixed(2);
    yInput.value = yMm.toFixed(2);
    widthInput.value = widthMm.toFixed(2);
    positionSelectedInput.value = "true";
    updateFootprint();
    setStatus(
      `Posición: X ${xInput.value} mm · Y ${yInput.value} mm · Ancho ${widthInput.value} mm`);
  };

  const renderPage = async () => {
    if (!pdfDocument) {
      return;
    }

    const pageNumber = Math.min(
      pdfDocument.numPages,
      Math.max(1, Number(pageInput.value) || 1));
    pageInput.value = pageNumber.toString();
    updateNavigation();
    setStatus("Renderizando página…");

    if (renderTask) {
      renderTask.cancel();
    }

    pdfPage = await pdfDocument.getPage(pageNumber);
    const baseViewport = pdfPage.getViewport({ scale: 1 });
    const availableWidth = Math.max(280, Math.min(780, stage.clientWidth - 24));
    const scale = availableWidth / baseViewport.width;
    const viewport = pdfPage.getViewport({ scale });
    const outputScale = Math.min(window.devicePixelRatio || 1, 2);

    canvas.width = Math.floor(viewport.width * outputScale);
    canvas.height = Math.floor(viewport.height * outputScale);
    canvas.style.width = `${Math.floor(viewport.width)}px`;
    canvas.style.height = `${Math.floor(viewport.height)}px`;
    pageWidthMm = (baseViewport.width * 25.4) / 72;
    pageHeightMm = (baseViewport.height * 25.4) / 72;

    const context = canvas.getContext("2d", { alpha: false });
    renderTask = pdfPage.render({
      canvasContext: context,
      viewport,
      transform: outputScale === 1 ? null : [outputScale, 0, 0, outputScale, 0, 0]
    });

    try {
      await renderTask.promise;
      placeholder.hidden = true;
      canvas.hidden = false;
      selectedPosition = pageNumber === selectedPosition?.page
        ? selectedPosition
        : null;
      positionSelectedInput.value = selectedPosition ? "true" : "false";
      updateFootprint();
      setStatus("Haz clic para ubicar o arrastra para dibujar el sello.");
    } catch (error) {
      if (error?.name !== "RenderingCancelledException") {
        setStatus("No se pudo mostrar esta página.", true);
      }
    } finally {
      renderTask = null;
    }
  };

  pdfInput.addEventListener("change", async () => {
    const file = pdfInput.files?.[0];
    selectedPosition = null;
    footprint.hidden = true;
    positionSelectedInput.value = "false";

    if (!file) {
      return;
    }

    if (file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) {
      setStatus("Selecciona un archivo PDF válido.", true);
      return;
    }

    try {
      setStatus("Abriendo PDF…");
      const pdfjs = await import("/lib/pdfjs/pdf.min.mjs");
      pdfjs.GlobalWorkerOptions.workerSrc = "/lib/pdfjs/pdf.worker.min.mjs";
      pdfDocument = await pdfjs.getDocument({ data: await file.arrayBuffer() }).promise;
      pageInput.value = "1";
      pageInput.max = pdfDocument.numPages.toString();
      await renderPage();
    } catch {
      pdfDocument = null;
      canvas.hidden = true;
      placeholder.hidden = false;
      setStatus("No fue posible abrir el PDF.", true);
      updateNavigation();
    }
  });

  canvas.addEventListener("pointerdown", event => {
    if (!pdfPage || event.button !== 0) {
      return;
    }

    event.preventDefault();
    const point = getPagePoint(event);
    const currentWidth = Number(widthInput.value) || 80;
    applySelection(point.xMm, point.yMm, currentWidth);
    drawingStart = {
      pointerId: event.pointerId,
      xMm: selectedPosition.xMm,
      yMm: selectedPosition.yMm,
      clientX: event.clientX,
      clientY: event.clientY
    };
    pointerMoved = false;
    canvas.setPointerCapture(event.pointerId);
    stage.classList.add("is-drawing");
  });

  canvas.addEventListener("pointermove", event => {
    if (!drawingStart || drawingStart.pointerId !== event.pointerId) {
      return;
    }

    event.preventDefault();
    const point = getPagePoint(event);
    const deltaPixels = Math.hypot(
      event.clientX - drawingStart.clientX,
      event.clientY - drawingStart.clientY);
    pointerMoved ||= deltaPixels > 4;

    if (!pointerMoved) {
      return;
    }

    const requestedWidth = Math.max(
      minimumStampWidthMm,
      point.xMm - drawingStart.xMm,
      (point.yMm - drawingStart.yMm) / stampHeightRatio);
    applySelection(drawingStart.xMm, drawingStart.yMm, requestedWidth);
  });

  const finishDrawing = event => {
    if (!drawingStart || drawingStart.pointerId !== event.pointerId) {
      return;
    }

    if (canvas.hasPointerCapture(event.pointerId)) {
      canvas.releasePointerCapture(event.pointerId);
    }
    drawingStart = null;
    stage.classList.remove("is-drawing");
  };

  canvas.addEventListener("pointerup", finishDrawing);
  canvas.addEventListener("pointercancel", finishDrawing);

  resizeHandle.addEventListener("pointerdown", event => {
    if (!selectedPosition || event.button !== 0) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    resizeStart = {
      pointerId: event.pointerId,
      xMm: selectedPosition.xMm,
      yMm: selectedPosition.yMm
    };
    stage.classList.add("is-resizing");
    setStatus("Arrastra la esquina para cambiar el tamaño.");
  });

  window.addEventListener("pointermove", event => {
    if (!resizeStart || resizeStart.pointerId !== event.pointerId) {
      return;
    }

    event.preventDefault();
    const point = getPagePoint(event);
    const requestedWidth = Math.max(
      minimumStampWidthMm,
      point.xMm - resizeStart.xMm,
      (point.yMm - resizeStart.yMm) / stampHeightRatio);
    applySelection(resizeStart.xMm, resizeStart.yMm, requestedWidth);
  });

  const finishResize = event => {
    if (!resizeStart || resizeStart.pointerId !== event.pointerId) {
      return;
    }

    resizeStart = null;
    stage.classList.remove("is-resizing");
    if (selectedPosition) {
      setStatus(
        `Posición: X ${xInput.value} mm · Y ${yInput.value} mm · Ancho ${widthInput.value} mm`);
    }
  };

  window.addEventListener("pointerup", finishResize);
  window.addEventListener("pointercancel", finishResize);

  previousButton.addEventListener("click", async () => {
    pageInput.value = Math.max(1, Number(pageInput.value) - 1).toString();
    await renderPage();
  });

  nextButton.addEventListener("click", async () => {
    pageInput.value = Math.min(
      pdfDocument?.numPages ?? 1,
      Number(pageInput.value) + 1).toString();
    await renderPage();
  });

  pageInput.addEventListener("change", renderPage);
  widthInput.addEventListener("input", updateFootprint);
  widthInput.addEventListener("change", () => {
    if (selectedPosition) {
      applySelection(
        selectedPosition.xMm,
        selectedPosition.yMm,
        Number(widthInput.value) || minimumStampWidthMm);
    }
  });

  stampForm?.addEventListener("invalid", event => {
    const field = event.target;
    const label = field.labels?.[0]?.textContent?.trim() || field.name || "un campo";
    setSubmitStatus(`Revise ${label} antes de continuar.`, true);
    console.warn("[API.Firma.Demo] El navegador bloqueó el envío por un campo inválido.", {
      field: field.name
    });
  }, true);

  stampForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const jqueryValidationAvailable =
      window.jQuery && typeof window.jQuery.fn.valid === "function";
    const isValid = jqueryValidationAvailable
      ? window.jQuery(stampForm).valid()
      : stampForm.checkValidity();

    if (!isValid) {
      setSubmitStatus(
        "Hay campos pendientes. Revise los mensajes marcados en rojo.",
        true);
      const firstError = stampForm.querySelector(
        ".input-validation-error, :invalid");
      firstError?.focus();
      console.warn("[API.Firma.Demo] El formulario no se envió porque contiene errores.");
      return;
    }

    if (!positionSelectedInput.value
        || positionSelectedInput.value.toLowerCase() !== "true") {
      setSubmitStatus(
        "Seleccione la posición del sello haciendo clic sobre el PDF.",
        true);
      selectionStatus.scrollIntoView({ behavior: "smooth", block: "center" });
      console.warn("[API.Firma.Demo] El formulario no se envió porque falta la posición.");
      return;
    }

    const formData = new FormData(stampForm);
    const certificate = formData.get("CertificadoFirma");
    const certificatePassword = formData.get("ClaveCertificado");
    if (!(certificate instanceof File) || certificate.size === 0) {
      setSubmitStatus("No se pudo leer el certificado P12/PFX seleccionado.", true);
      certificateInput?.focus();
      return;
    }

    if (typeof certificatePassword !== "string"
        || certificatePassword.length === 0) {
      setSubmitStatus("No se pudo leer la clave del certificado.", true);
      certificatePasswordInput?.focus();
      return;
    }

    submitButton.disabled = true;
    submitButton.querySelector(".submit-label").hidden = true;
    submitButton.querySelector(".submit-loading").hidden = false;
    setSubmitStatus("Enviando archivos al API. Espere mientras se genera el PDF.");
    console.info("[API.Firma.Demo] Formulario enviado al servidor.", {
      certificateName: certificate.name,
      certificateBytes: certificate.size,
      passwordReceived: true
    });

    try {
      const response = await fetch(stampForm.action || window.location.href, {
        method: "POST",
        body: formData,
        credentials: "same-origin",
        headers: {
          "X-Requested-With": "XMLHttpRequest"
        }
      });
      const contentType = response.headers.get("Content-Type") || "";

      if (response.ok && contentType.toLowerCase().includes("application/pdf")) {
        const pdf = await response.blob();
        if (pdf.size < 5) {
          throw new Error("La respuesta PDF está vacía.");
        }

        const downloadUrl = URL.createObjectURL(pdf);
        const download = document.createElement("a");
        download.href = downloadUrl;
        download.download = "documento-estampado.pdf";
        document.body.appendChild(download);
        download.click();
        download.remove();
        window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
        setSubmitStatus(
          `PDF generado correctamente (${Math.ceil(pdf.size / 1024)} KB).`);
        console.info("[API.Firma.Demo] Descarga iniciada correctamente.", {
          bytes: pdf.size
        });
        return;
      }

      const html = await response.text();
      const parsed = new DOMParser().parseFromString(html, "text/html");
      const serverError = parsed.querySelector(
        ".error-panel, .validation-summary-errors");
      const message = serverError?.textContent?.replace(/\s+/g, " ").trim()
        || `El servidor respondió HTTP ${response.status} sin un PDF.`;
      setSubmitStatus(message, true);
      console.error("[API.Firma.Demo] El servidor no devolvió un PDF.", {
        status: response.status,
        contentType
      });
    } catch (error) {
      setSubmitStatus(
        "No fue posible completar la descarga. Revise los logs del Demo y del API.",
        true);
      console.error("[API.Firma.Demo] Error durante la descarga.", error);
    } finally {
      submitButton.disabled = false;
      submitButton.querySelector(".submit-label").hidden = false;
      submitButton.querySelector(".submit-loading").hidden = true;
    }
  });

  updateNavigation();
})();
