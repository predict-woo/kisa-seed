# kisa-seed

Typescript implementation of the KISA SEED encryption and decryption

[KISA SEED Algorithm](https://seed.kisa.or.kr/kisa/algorithm/EgovSeedInfo.do)

This is a typescript conversion of the Java class mentioned in the above website.

Since it is almost a direct translation, it will not follow typescript standards and best practices.

You can use it in the following way.

```ts
import KISA_SEED_CBC from "./crypto";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i !== bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

const pbUserKey = hexToBytes("80E34F8F081070F1E9F394370AD40589");
const bszIV = hexToBytes("208D66A730A81A816FBAD9FA36102501");

// conver Hello world to byte array
const str = "Hello Worldflamsdfklamsdflmasldfmalsdkfmald";
const encStr = new TextEncoder().encode(str);

// encode Hello World
const enc = KISA_SEED_CBC.SEED_CBC_Encrypt(
  pbUserKey,
  bszIV,
  encStr,
  0,
  encStr.length
);

// print enc as hex
console.log(
  Array.from(enc)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
);

// base64 encode enc uint8array and print
// console.log(
//   Buffer.from(enc).toString("base64")
//   // new TextDecoder().decode(enc)
// );

console.log("##############################");

// decode Hello World
const dec = KISA_SEED_CBC.SEED_CBC_Decrypt(
  pbUserKey,
  bszIV,
  enc,
  0,
  enc.length
);
const decStr = new TextDecoder().decode(dec);
console.log(decStr);

// const enc = hexToBytes(
//   "B3F461152963A70AF8585144E01C6DA41E3C6E4D22122FE5D31509D71E5504ED7A525EA8EFEB2E99DFB01F830B10F220E07DB5CC94A8F1A60B5ADC89CC15832AF142FCD0A40F6F7A23DE61D9D3CA963EBB1049B955FA1DE5F8DEA51E51ECD982AE8F75467636A7B7A12F39BD0703959EAE69271C476FF3A93D2D615955449014AAF1FAE4C2058838E5C5630968ACD3461E033B7098B1F2C90044B08AD520C7C2CE795D6EA3A6AF72408B8ACE85A2CACC3923A658C324E47965D444B10CE204B8E818FF50FC05730D9C5B59022593336C823983F262E1E0DC143C42CC794BCDCCF98E0935ED4934C2797E55FD2921B1A36B4CCD6A12C9E1AA81802C1B0BFEDD840EB36DAFC7F86800E2C95D740EE3B949351FCC558015CD26ECE4BFB73DBF0F9B7A0DBFE3E582E0F6EDF3FD9940C3F7CD1D21751728F6FCC536B2750C8487AF17699C6C5EBCD98AD9C62D09813265305C6183A32AF64F9E5F89FD8CF301F114579D9BB9B8B348B8C18ED5AC0CB5E735919EEA5168D12437C215425EA68818EE9B546BAF5A04F4B37FB58340059DD0F9CB56131E47FDEC04EA4BF2B34E9101CB29C9A4B22AF6F5394F7807C764565C2563EF39FEAD38D5CF4076CA3CD1D80963B815EECFCCDCA100F0FF5FA1EA98BC695C8B3562393E68B0805CC1CEC3D72C79607CB64859C744DBAAB9344332569C6484"
// );

// let dec = KISA_SEED_CBC.SEED_CBC_Decrypt(pbUserKey, bszIV, enc, 0, enc.length);
// let decStr = new TextDecoder().decode(dec);
// console.log(decStr);
```
