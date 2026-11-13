// QR decoding for the CLI (Node). The browser uses a <canvas> instead.
// Includes a tiny PNG decoder so the CLI stays dependency-free.
import { inflateSync } from "node:zlib";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const jsQR = require("../vendor/jsQR.js");

export function decodePng(bytes) {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (b.readUInt32BE(0) !== 0x89504e47) throw new Error("not a PNG");
  let p = 8;
  let w = 0, h = 0, depth = 0, color = 0, interlace = 0;
  let palette = null;
  let trns = null;
  const idat = [];
  while (p + 8 <= b.length) {
    const len = b.readUInt32BE(p);
    const type = b.toString("latin1", p + 4, p + 8);
    const data = b.subarray(p + 8, p + 8 + len);
    if (type === "IHDR") {
      w = data.readUInt32BE(0); h = data.readUInt32BE(4); depth = data[8]; color = data[9]; interlace = data[12];
    } else if (type === "PLTE") palette = data;
    else if (type === "tRNS") trns = data;
    else if (type === "IDAT") idat.push(data);
    else if (type === "IEND") break;
    p += 12 + len;
  }
  if (interlace) throw new Error("interlaced PNG not supported");
  if (w * h > 16e6) throw new Error("image too large");
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[color];
  const bpp = Math.max(1, (channels * depth) >> 3);
  const stride = Math.ceil((w * channels * depth) / 8);
  const raw = inflateSync(Buffer.concat(idat));
  const pix = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)];
    const src = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const out = pix.subarray(y * stride, (y + 1) * stride);
    const prev = y ? pix.subarray((y - 1) * stride, y * stride) : null;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? out[x - bpp] : 0;
      const up = prev ? prev[x] : 0;
      const c = prev && x >= bpp ? prev[x - bpp] : 0;
      let v = src[x];
      if (f === 1) v += a;
      else if (f === 2) v += up;
      else if (f === 3) v += (a + up) >> 1;
      else if (f === 4) {
        const pp = a + up - c;
        const pa = Math.abs(pp - a), pb = Math.abs(pp - up), pc = Math.abs(pp - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? up : c;
      }
      out[x] = v & 255;
    }
  }
  const rgba = new Uint8ClampedArray(w * h * 4);
  const sample = (row, i) => {
    if (depth === 8) return row[i];
    if (depth === 16) return row[i * 2];
    const perByte = 8 / depth;
    const byte = row[Math.floor(i / perByte)];
    const shift = 8 - depth * ((i % perByte) + 1);
    return (byte >> shift) & ((1 << depth) - 1);
  };
  const scale = depth < 8 ? 255 / ((1 << depth) - 1) : 1;
  for (let y = 0; y < h; y++) {
    const row = pix.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4;
      if (color === 0 || color === 4) {
        const g = color === 0 ? sample(row, x) * scale : sample(row, x * 2);
        rgba[o] = rgba[o + 1] = rgba[o + 2] = g;
        rgba[o + 3] = color === 4 ? sample(row, x * 2 + 1) : 255;
      } else if (color === 3) {
        const i = sample(row, x);
        rgba[o] = palette[i * 3]; rgba[o + 1] = palette[i * 3 + 1]; rgba[o + 2] = palette[i * 3 + 2];
        rgba[o + 3] = trns && i < trns.length ? trns[i] : 255;
      } else {
        const n = color === 2 ? 3 : 4;
        rgba[o] = sample(row, x * n); rgba[o + 1] = sample(row, x * n + 1); rgba[o + 2] = sample(row, x * n + 2);
        rgba[o + 3] = n === 4 ? sample(row, x * n + 3) : 255;
      }
    }
  }
  // flatten transparency onto white so QR modules stay readable
  for (let i = 0; i < rgba.length; i += 4) {
    const al = rgba[i + 3] / 255;
    for (let k = 0; k < 3; k++) rgba[i + k] = rgba[i + k] * al + 255 * (1 - al);
    rgba[i + 3] = 255;
  }
  return { width: w, height: h, data: rgba };
}

export async function decodeQrNode(bytes) {
  if (!(bytes[0] === 0x89 && bytes[1] === 0x50)) return []; // PNG only in the CLI
  try {
    const img = decodePng(bytes);
    const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
    return code?.data ? [code.data] : [];
  } catch {
    return [];
  }
}
