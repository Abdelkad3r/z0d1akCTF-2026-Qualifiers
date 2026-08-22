// Extracted from the client chunk loaded by /admin/products.
// This is the critical preview flow, rewritten with original identifiers made
// readable.  The real minified component fetches this context when the Preview
// dialog opens, stores it on window.__soilTelemetry, then renders the product
// description as raw HTML.

const telemetryKey = "__soilTelemetry";

async function loadPreviewContext(productId, previewToken) {
  const endpoint =
    `/api/admin/preview-context?productId=${encodeURIComponent(productId)}` +
    `&previewToken=${encodeURIComponent(previewToken)}`;

  const response = await fetch(endpoint, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`preview context request failed (${response.status})`);
  }

  const context = await response.json();
  window[telemetryKey] = context;
}

// Later in the same component:
//
// <div
//   className="prose prose-invert max-w-none text-[#f2efe9]"
//   dangerouslySetInnerHTML={{ __html: description }}
// />
