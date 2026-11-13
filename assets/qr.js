// Browser QR decoding: draw the image on a canvas and hand the pixels to jsQR.
export async function decodeQrBrowser(bytes, type) {
  if (typeof window.jsQR !== "function" || typeof createImageBitmap !== "function") return [];
  const bmp = await createImageBitmap(new Blob([bytes], { type: type || "image/png" }));
  const results = new Set();
  // Try the native size, then an upscaled copy (small QR images decode better when enlarged).
  for (const factor of [1, 2]) {
    let scale = Math.min(factor, 1600 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    const ctx = c.getContext("2d", { willReadFrequently: true });
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, w, h);
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(bmp, 0, 0, w, h);
    const d = ctx.getImageData(0, 0, w, h);
    const code = window.jsQR(d.data, w, h, { inversionAttempts: "attemptBoth" });
    if (code?.data) {
      results.add(code.data);
      break;
    }
  }
  bmp.close?.();
  return [...results];
}
