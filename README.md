# kisa-seed

Typescript implementation of the KISA SEED encryption and decryption

[KISA SEED Algorithm](https://seed.kisa.or.kr/kisa/algorithm/EgovSeedInfo.do)

This is a typescript conversion of the Java class mentioned in the above website.

Since it is almost a direct translation, it will not follow typescript standards and best practices.

## Installation
```
npm install kisa-seed
```

## Usage

You can use it in the following way.

```ts
import { KISA_SEED_CBC } from "../src";

const enc = KISA_SEED_CBC.encrypt(
  "gONPjwgQcPHp85Q3CtQFiQ==",
  "II1mpzCoGoFvutn6NhAlAQ==",
  "Hello World"
);

const dec = KISA_SEED_CBC.decrypt(
  "gONPjwgQcPHp85Q3CtQFiQ==",
  "II1mpzCoGoFvutn6NhAlAQ==",
  enc
);

console.log(dec);
```

You can also access an inner method if you want to directly encrypt/decrypt a Uint8Array

```ts
import { KISA_SEED_CBC } from "../src";

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

console.log(uint8ArrayToString(dec));
```
