import KISA_SEED_CBC from "../src";

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
