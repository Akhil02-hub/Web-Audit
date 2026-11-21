import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { deflateSync } from "node:zlib";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = resolve(root, "public");

const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n += 1) {
  let value = n;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  crcTable[n] = value >>> 0;
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const name = Buffer.from(type, "ascii");
  const size = Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([size, name, data, checksum]);
}

function makePng(size) {
  const background = [23, 77, 63, 255];
  const lime = [184, 237, 112, 255];
  const image = Array.from({ length: size }, () => Array.from({ length: size }, () => [0, 0, 0, 0]));
  const scale = size / 40;
  const radius = 12 * scale;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const nearestX = Math.max(radius, Math.min(size - radius - 1, x));
      const nearestY = Math.max(radius, Math.min(size - radius - 1, y));
      if ((x - nearestX) ** 2 + (y - nearestY) ** 2 <= radius ** 2) image[y][x] = background;
    }
  }

  for (const [x1, y1, x2, y2] of [[10, 12, 18, 20], [22, 12, 30, 20], [10, 24, 18, 32], [22, 24, 30, 32]]) {
    for (let y = Math.round(y1 * scale); y < Math.round(y2 * scale); y += 1) {
      for (let x = Math.round(x1 * scale); x < Math.round(x2 * scale); x += 1) image[y][x] = lime;
    }
  }

  const scanlines = Buffer.alloc(size * (1 + size * 4));
  for (let y = 0; y < size; y += 1) {
    const rowOffset = y * (1 + size * 4);
    scanlines[rowOffset] = 0;
    for (let x = 0; x < size; x += 1) image[y][x].forEach((channel, index) => { scanlines[rowOffset + 1 + x * 4 + index] = channel; });
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(scanlines)),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

const touchIcon = makePng(180);
const smallIcon = makePng(32);
const mediumIcon = makePng(192);
const largeIcon = makePng(512);
const icoHeader = Buffer.alloc(22);
icoHeader.writeUInt16LE(0, 0);
icoHeader.writeUInt16LE(1, 2);
icoHeader.writeUInt16LE(1, 4);
icoHeader[6] = 32;
icoHeader[7] = 32;
icoHeader[8] = 0;
icoHeader[9] = 0;
icoHeader.writeUInt16LE(1, 10);
icoHeader.writeUInt16LE(32, 12);
icoHeader.writeUInt32LE(smallIcon.length, 14);
icoHeader.writeUInt32LE(22, 18);

await Promise.all([
  writeFile(resolve(output, "apple-touch-icon.png"), touchIcon),
  writeFile(resolve(output, "favicon.ico"), Buffer.concat([icoHeader, smallIcon])),
  writeFile(resolve(output, "pwa-192.png"), mediumIcon),
  writeFile(resolve(output, "pwa-512.png"), largeIcon)
]);
console.log("Created favicon, Apple touch, and PWA icons");
