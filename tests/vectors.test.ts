import { expect, test } from "vitest";
import { KISA_SEED_CBC } from "../src";
import fixtures from "./fixtures/vectors.json";

const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));

// These vectors were generated from the pre-refactor implementation
// (the direct Java translation). They lock in cipher behavior so the
// code can be restructured without any risk of changing output.

test.each(fixtures.vectors)(
  "known-answer vector: $size-byte message",
  ({ key, iv, message, cipher }) => {
    const messageBytes = fromB64(message);

    expect(KISA_SEED_CBC.encryptBytes(key, iv, messageBytes)).toBe(cipher);

    const decrypted = KISA_SEED_CBC.decryptBytes(key, iv, cipher);
    expect(Buffer.from(decrypted).equals(Buffer.from(messageBytes))).toBe(true);
  }
);

test.each(fixtures.offsetVectors)(
  "known-answer offset vector: $size bytes at offset $offset",
  ({ key, iv, buffer, offset, size, cipher }) => {
    const keyBytes = fromB64(key);
    const ivBytes = fromB64(iv);
    const bufferBytes = fromB64(buffer);
    const cipherBytes = fromB64(cipher);

    const enc = KISA_SEED_CBC.SEED_CBC_Encrypt(
      keyBytes,
      ivBytes,
      bufferBytes,
      offset,
      size
    );
    expect(Buffer.from(enc).equals(Buffer.from(cipherBytes))).toBe(true);

    const dec = KISA_SEED_CBC.SEED_CBC_Decrypt(
      keyBytes,
      ivBytes,
      cipherBytes,
      0,
      cipherBytes.length
    );
    const original = bufferBytes.slice(offset, offset + size);
    expect(Buffer.from(dec).equals(Buffer.from(original))).toBe(true);
  }
);
