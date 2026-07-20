/**
 * Regenerates vectors.json from the current implementation.
 * Run with: npx tsx tests/fixtures/generate.ts
 *
 * The committed vectors.json was generated BEFORE the TypeScript style
 * refactor, so it locks in the behavior of the original Java translation.
 * Only regenerate if the cipher behavior is intentionally changed.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { KISA_SEED_CBC } from "../../src";

// Deterministic PRNG (LCG) so vectors are reproducible
let state = 42;
function nextByte(): number {
  state = (state * 1103515245 + 12345) & 0x7fffffff;
  return (state >> 16) & 0xff;
}
function bytes(n: number): Uint8Array {
  return Uint8Array.from({ length: n }, nextByte);
}
const b64 = (u8: Uint8Array) => Buffer.from(u8).toString("base64");

const sizes = [0, 1, 3, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 333, 1000];

const vectors = sizes.map((size) => {
  const key = bytes(16);
  const iv = bytes(16);
  const message = bytes(size);
  return {
    size,
    key: b64(key),
    iv: b64(iv),
    message: b64(message),
    cipher: KISA_SEED_CBC.encryptBytes(b64(key), b64(iv), message),
  };
});

// Offset variants exercise the message_offset/message_length slicing of the
// low-level SEED_CBC_Encrypt API
const offsetVectors = [7, 20, 100].map((size) => {
  const key = bytes(16);
  const iv = bytes(16);
  const buffer = bytes(size + 13);
  const offset = 5;
  const cipher = KISA_SEED_CBC.SEED_CBC_Encrypt(
    Buffer.from(b64(key), "base64"),
    Buffer.from(b64(iv), "base64"),
    buffer,
    offset,
    size
  );
  return {
    size,
    offset,
    key: b64(key),
    iv: b64(iv),
    buffer: b64(buffer),
    cipher: b64(cipher),
  };
});

writeFileSync(
  join(__dirname, "vectors.json"),
  JSON.stringify({ vectors, offsetVectors }, null, 2)
);
console.log(
  `wrote ${vectors.length} vectors + ${offsetVectors.length} offset vectors`
);
