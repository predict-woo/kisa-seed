import { expect, test } from "vitest";
import { KISA_SEED_CBC } from "../src";

test("encrpyt and decrypt", () => {
  const enc = KISA_SEED_CBC.encrypt(
    "gONPjwgQcPHp85Q3CtQFiQ==",
    "II1mpzCoGoFvutn6NhAlAQ==",
    "Hello World"
  );

  const pred_enc = "MWeccStERpJIdUKd5nesKA==";
  expect(enc).toBe(pred_enc);

  const dec = KISA_SEED_CBC.decrypt(
    "gONPjwgQcPHp85Q3CtQFiQ==",
    "II1mpzCoGoFvutn6NhAlAQ==",
    enc
  );

  const pred_dec = "Hello World";
  expect(dec).toBe(pred_dec);
});

function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder(); // TextEncoder encodes into UTF-8 by default
  const uint8Array = encoder.encode(str);
  return uint8Array;
}

function uint8ArrayToString(uint8Array: Uint8Array): string {
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(uint8Array);
}

function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

test("encrpyt and decrypt", () => {
  const pbUserKey = base64ToUint8Array("gONPjwgQcPHp85Q3CtQFiQ==");
  const bszIV = base64ToUint8Array("II1mpzCoGoFvutn6NhAlAQ==");
  const encStr = stringToUint8Array("Hello World");

  const enc = KISA_SEED_CBC.SEED_CBC_Encrypt(
    pbUserKey,
    bszIV,
    encStr,
    0,
    encStr.length
  );

  const dec = KISA_SEED_CBC.SEED_CBC_Decrypt(
    pbUserKey,
    bszIV,
    enc,
    0,
    enc.length
  );

  const decStr = uint8ArrayToString(dec);
  expect(decStr).toBe("Hello World");
});

// --- Issue #1: binary plaintext must survive the convenience API ---

const KEY = "gONPjwgQcPHp85Q3CtQFiQ==";
const IV = "II1mpzCoGoFvutn6NhAlAQ==";

test("encryptBytes/decryptBytes round-trips binary (non-UTF-8) data", () => {
  // DER-like bytes, deliberately invalid as UTF-8
  const binary = new Uint8Array([
    0x30, 0x82, 0x01, 0x0a, 0xc3, 0x28, 0xff, 0xfe, 0x80, 0x9f, 0x00, 0x41,
  ]);

  const enc = KISA_SEED_CBC.encryptBytes(KEY, IV, binary);
  const dec = KISA_SEED_CBC.decryptBytes(KEY, IV, enc);

  expect(Buffer.from(dec).equals(Buffer.from(binary))).toBe(true);
});

test("encryptBytes matches encrypt for UTF-8 input", () => {
  const bytes = new TextEncoder().encode("Hello World");
  expect(KISA_SEED_CBC.encryptBytes(KEY, IV, bytes)).toBe(
    "MWeccStERpJIdUKd5nesKA=="
  );
});

test("decrypt throws on binary plaintext instead of silently corrupting", () => {
  const binary = new Uint8Array([0x30, 0x82, 0xc3, 0x28, 0xff, 0xfe]);
  const enc = KISA_SEED_CBC.encryptBytes(KEY, IV, binary);

  expect(() => KISA_SEED_CBC.decrypt(KEY, IV, enc)).toThrow();
});

test("encrypt/decrypt handles large messages (500KB)", () => {
  const big = "x".repeat(500_000);
  const enc = KISA_SEED_CBC.encrypt(KEY, IV, big);
  expect(KISA_SEED_CBC.decrypt(KEY, IV, enc)).toBe(big);
});
