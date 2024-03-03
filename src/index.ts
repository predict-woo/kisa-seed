import Common from "./common";
import { defaults } from "./defaults";
import { KISA_ENC_DEC, KISA_SEED_INFO, KISA_SEED_KEY } from "./util";

export class KISA_SEED_CBC {
  private static ENDIAN: number = Common.BIG_ENDIAN;

  private static readonly BLOCK_SIZE_SEED: number = 16;
  private static readonly BLOCK_SIZE_SEED_INT: number = 4;

  private static Subst(A: number): number {
    return (
      defaults.SS0[A & 0x0ff] ^
      defaults.SS1[(A >> 8) & 0x0ff] ^
      defaults.SS2[(A >> 16) & 0x0ff] ^
      defaults.SS3[(A >> 24) & 0x0ff]
    );
  }

  private static SeedRound(
    T: number[],
    LR: number[],
    L0: number,
    L1: number,
    R0: number,
    R1: number,
    K: number[],
    K_offset: number
  ): void {
    T[0] = LR[R0] ^ K[K_offset + 0];
    T[1] = LR[R1] ^ K[K_offset + 1];
    T[1] ^= T[0];
    T[1] = KISA_SEED_CBC.Subst(T[1]);
    T[0] += T[1];
    T[0] = KISA_SEED_CBC.Subst(T[0]);
    T[1] += T[0];
    T[1] = KISA_SEED_CBC.Subst(T[1]);
    T[0] += T[1];
    LR[L0] ^= T[0];
    LR[L1] ^= T[1];
  }

  private static EndianChange(dwS: number): number {
    return (
      (((dwS << 8) | ((dwS >> (32 - 8)) & 0x000000ff)) & 0x00ff00ff) |
      (((dwS << 24) | ((dwS >> (32 - 24)) & 0x00ffffff)) & 0xff00ff00)
    );
  }

  private static RoundKeyUpdate0(
    T: number[],
    K: number[],
    K_offset: number,
    ABCD: number[],
    KC: number
  ): void {
    T[0] = ABCD[0] + ABCD[2] - KC;
    T[1] = ABCD[1] + KC - ABCD[3];
    K[K_offset + 0] = KISA_SEED_CBC.Subst(T[0]);
    K[K_offset + 1] = KISA_SEED_CBC.Subst(T[1]);
    T[0] = ABCD[0];
    ABCD[0] = ((ABCD[0] >> 8) & 0x00ffffff) ^ (ABCD[1] << 24);
    ABCD[1] = ((ABCD[1] >> 8) & 0x00ffffff) ^ (T[0] << 24);
  }

  private static RoundKeyUpdate1(
    T: number[],
    K: number[],
    K_offset: number,
    ABCD: number[],
    KC: number
  ): void {
    T[0] = ABCD[0] + ABCD[2] - KC;
    T[1] = ABCD[1] + KC - ABCD[3];
    K[K_offset + 0] = KISA_SEED_CBC.Subst(T[0]);
    K[K_offset + 1] = KISA_SEED_CBC.Subst(T[1]);
    T[0] = ABCD[2];
    ABCD[2] = (ABCD[2] << 8) ^ ((ABCD[3] >> 24) & 0x000000ff);
    ABCD[3] = (ABCD[3] << 8) ^ ((T[0] >> 24) & 0x000000ff);
  }

  private static BLOCK_XOR_CBC(
    OUT_VALUE: number[],
    out_value_offset: number,
    IN_VALUE1: number[],
    in_value1_offset: number,
    IN_VALUE2: number[],
    in_value2_offset: number
  ): void {
    OUT_VALUE[out_value_offset + 0] =
      (in_value1_offset < IN_VALUE1.length
        ? IN_VALUE1[in_value1_offset + 0]
        : 0) ^
      (in_value2_offset < IN_VALUE2.length
        ? IN_VALUE2[in_value2_offset + 0]
        : 0);
    OUT_VALUE[out_value_offset + 1] =
      (in_value1_offset + 1 < IN_VALUE1.length
        ? IN_VALUE1[in_value1_offset + 1]
        : 0) ^
      (in_value2_offset + 1 < IN_VALUE2.length
        ? IN_VALUE2[in_value2_offset + 1]
        : 0);
    OUT_VALUE[out_value_offset + 2] =
      (in_value1_offset + 2 < IN_VALUE1.length
        ? IN_VALUE1[in_value1_offset + 2]
        : 0) ^
      (in_value2_offset + 2 < IN_VALUE2.length
        ? IN_VALUE2[in_value2_offset + 2]
        : 0);
    OUT_VALUE[out_value_offset + 3] =
      (in_value1_offset + 3 < IN_VALUE1.length
        ? IN_VALUE1[in_value1_offset + 3]
        : 0) ^
      (in_value2_offset + 3 < IN_VALUE2.length
        ? IN_VALUE2[in_value2_offset + 3]
        : 0);
  }

  private static readonly LR_L0: number = 0;
  private static readonly LR_L1: number = 1;
  private static readonly LR_R0: number = 2;
  private static readonly LR_R1: number = 3;

  public static KISA_SEED_Encrypt_Block_forCBC(
    inData: number[],
    in_offset: number,
    outData: number[],
    out_offset: number,
    ks: KISA_SEED_KEY
  ): void {
    let LR: number[] = new Array(4); // Input/output values at each rounds
    let T: number[] = new Array(2); // Temporary variables for round function F
    let K: number[] = ks.key_data; // Pointer of round keys

    // Set up input values for first round
    LR[KISA_SEED_CBC.LR_L0] = inData[in_offset + 0];
    LR[KISA_SEED_CBC.LR_L1] = inData[in_offset + 1];
    LR[KISA_SEED_CBC.LR_R0] = inData[in_offset + 2];
    LR[KISA_SEED_CBC.LR_R1] = inData[in_offset + 3];

    // Reorder for big endian
    // Assuming Common.BIG_ENDIAN and ENDIAN are defined elsewhere or need to be adapted based on your application's requirements
    if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
      LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L0]
      );
      LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L1]
      );
      LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R0]
      );
      LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R1]
      );
    }

    // Rounds 1 through 16
    for (let i = 0; i < 16; i++) {
      KISA_SEED_CBC.SeedRound(
        T,
        LR,
        i % 2 === 0 ? KISA_SEED_CBC.LR_L0 : KISA_SEED_CBC.LR_R0,
        i % 2 === 0 ? KISA_SEED_CBC.LR_L1 : KISA_SEED_CBC.LR_R1,
        i % 2 === 0 ? KISA_SEED_CBC.LR_R0 : KISA_SEED_CBC.LR_L0,
        i % 2 === 0 ? KISA_SEED_CBC.LR_R1 : KISA_SEED_CBC.LR_L1,
        K,
        i * 2
      );
    }

    // Reorder for big endian again for output
    if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
      LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L0]
      );
      LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L1]
      );
      LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R0]
      );
      LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R1]
      );
    }

    // Copying output values from last round to outData
    outData[out_offset + 0] = LR[KISA_SEED_CBC.LR_R0];
    outData[out_offset + 1] = LR[KISA_SEED_CBC.LR_R1];
    outData[out_offset + 2] = LR[KISA_SEED_CBC.LR_L0];
    outData[out_offset + 3] = LR[KISA_SEED_CBC.LR_L1];
  }

  public static KISA_SEED_Decrypt_Block_forCBC(
    input: number[],
    in_offset: number,
    outData: number[],
    out_offset: number,
    ks: KISA_SEED_KEY
  ): void {
    let LR: number[] = new Array(4); // Input/output values at each rounds
    let T: number[] = new Array(2); // Temporary variables for round function F
    let K: number[] = ks.key_data; // Pointer of round keys

    // Set up input values for first round
    LR[KISA_SEED_CBC.LR_L0] = input[in_offset + 0];
    LR[KISA_SEED_CBC.LR_L1] = input[in_offset + 1];
    LR[KISA_SEED_CBC.LR_R0] = input[in_offset + 2];
    LR[KISA_SEED_CBC.LR_R1] = input[in_offset + 3];

    // Reorder for big endian
    // Assuming Common.BIG_ENDIAN and ENDIAN are defined elsewhere or need to be adapted based on your application's requirements
    if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
      LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L0]
      );
      LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L1]
      );
      LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R0]
      );
      LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R1]
      );
    }

    // Rounds 16 through 1, note the reversed index for decryption
    for (let i = 15; i >= 0; i--) {
      KISA_SEED_CBC.SeedRound(
        T,
        LR,
        i % 2 === 1 ? KISA_SEED_CBC.LR_L0 : KISA_SEED_CBC.LR_R0,
        i % 2 === 1 ? KISA_SEED_CBC.LR_L1 : KISA_SEED_CBC.LR_R1,
        i % 2 === 1 ? KISA_SEED_CBC.LR_R0 : KISA_SEED_CBC.LR_L0,
        i % 2 === 1 ? KISA_SEED_CBC.LR_R1 : KISA_SEED_CBC.LR_L1,
        K,
        i * 2
      );
    }

    // Reorder for big endian again for output
    if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
      LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L0]
      );
      LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_L1]
      );
      LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R0]
      );
      LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(
        LR[KISA_SEED_CBC.LR_R1]
      );
    }

    // Copying output values from last round to outData
    outData[out_offset + 0] = LR[KISA_SEED_CBC.LR_R0];
    outData[out_offset + 1] = LR[KISA_SEED_CBC.LR_R1];
    outData[out_offset + 2] = LR[KISA_SEED_CBC.LR_L0];
    outData[out_offset + 3] = LR[KISA_SEED_CBC.LR_L1];
  }

  public static chartoint32_for_SEED_CBC(
    input: Uint8Array,
    inLen: number
  ): number[] {
    let len: number;

    if (inLen % 4 > 0) {
      len = Math.floor(inLen / 4) + 1;
    } else {
      len = inLen / 4;
    }

    let data: number[] = new Array(len).fill(0);

    for (let i = 0; i < len; i++) {
      Common.byte_to_int(data, i, input, i * 4, Common.ENDIAN);
    }

    return data;
  }

  public static int32tochar_for_SEED_CBC(
    input: number[],
    inLen: number
  ): Uint8Array {
    let data: Uint8Array = new Uint8Array(inLen * 4);

    if (Common.ENDIAN !== Common.BIG_ENDIAN) {
      for (let i = 0; i < data.length; i++) {
        data[i] = (input[Math.floor(i / 4)] >> ((i % 4) * 8)) & 0xff;
      }
    } else {
      for (let i = 0; i < data.length; i++) {
        data[i] = (input[Math.floor(i / 4)] >> ((3 - (i % 4)) * 8)) & 0xff;
      }
    }

    return data;
  }

  public static SEED_CBC_init(
    pInfo: KISA_SEED_INFO,
    enc: KISA_ENC_DEC,
    pbszUserKey: Uint8Array,
    pbszIV: Uint8Array
  ) {
    let ABCD: number[] = new Array(4);
    let T: number[] = new Array(2);
    let K: number[];

    if (!pInfo || !pbszUserKey || !pbszIV) return 0;

    K = pInfo.seed_key.key_data;
    pInfo.encrypt = enc.value;
    Common.memcpy(pInfo.ivec, pbszIV, 16, KISA_SEED_CBC.ENDIAN);
    pInfo.last_block_flag = pInfo.buffer_length = 0;

    ABCD[0] = Common.byte_to_int(pbszUserKey, 0 * 4, KISA_SEED_CBC.ENDIAN);
    ABCD[1] = Common.byte_to_int(pbszUserKey, 1 * 4, KISA_SEED_CBC.ENDIAN);
    ABCD[2] = Common.byte_to_int(pbszUserKey, 2 * 4, KISA_SEED_CBC.ENDIAN);
    ABCD[3] = Common.byte_to_int(pbszUserKey, 3 * 4, KISA_SEED_CBC.ENDIAN);

    // Reorder for big endian
    if (Common.BIG_ENDIAN != KISA_SEED_CBC.ENDIAN) {
      ABCD[0] = KISA_SEED_CBC.EndianChange(ABCD[0]);
      ABCD[1] = KISA_SEED_CBC.EndianChange(ABCD[1]);
      ABCD[2] = KISA_SEED_CBC.EndianChange(ABCD[2]);
      ABCD[3] = KISA_SEED_CBC.EndianChange(ABCD[3]);
    }

    for (let i = 0; i < 15; i++) {
      if (i % 2 === 0) {
        KISA_SEED_CBC.RoundKeyUpdate0(T, K, i * 2, ABCD, defaults.KC[i]);
      } else {
        KISA_SEED_CBC.RoundKeyUpdate1(T, K, i * 2, ABCD, defaults.KC[i]);
      }
    }

    T[0] = ABCD[0] + ABCD[2] - defaults.KC[15];
    T[1] = ABCD[1] - ABCD[3] + defaults.KC[15];

    K[30] = KISA_SEED_CBC.Subst(T[0]);
    K[31] = KISA_SEED_CBC.Subst(T[1]);
    return 1;
  }

  public static SEED_CBC_Process(
    pInfo: KISA_SEED_INFO,
    input: number[],
    inLen: number,
    output: number[],
    outLen: number[]
  ): number {
    let nCurrentCount = KISA_SEED_CBC.BLOCK_SIZE_SEED;
    let pdwXOR: number[];
    let in_offset = 0;
    let out_offset = 0;
    let pdwXOR_offset = 0;

    if (!pInfo || !input || !output || inLen < 0) return 0;

    if (KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt) {
      pdwXOR = pInfo.ivec;
      in_offset = 0;
      out_offset = 0;
      pdwXOR_offset = 0;

      while (nCurrentCount <= inLen) {
        KISA_SEED_CBC.BLOCK_XOR_CBC(
          output,
          out_offset,
          input,
          in_offset,
          pdwXOR,
          pdwXOR_offset
        );

        KISA_SEED_CBC.KISA_SEED_Encrypt_Block_forCBC(
          output,
          out_offset,
          output,
          out_offset,
          pInfo.seed_key
        );

        pdwXOR = output;
        pdwXOR_offset = out_offset;

        nCurrentCount += KISA_SEED_CBC.BLOCK_SIZE_SEED;
        in_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
        out_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
      }

      outLen[0] = nCurrentCount - KISA_SEED_CBC.BLOCK_SIZE_SEED;
      pInfo.buffer_length = inLen - outLen[0];

      Common.memcpy(
        pInfo.ivec,
        pdwXOR,
        KISA_SEED_CBC.BLOCK_SIZE_SEED,
        pdwXOR_offset
      );

      Common.memcpy(pInfo.cbc_buffer, input, pInfo.buffer_length, in_offset);
    } else {
      pdwXOR = pInfo.ivec;
      in_offset = 0;
      out_offset = 0;
      pdwXOR_offset = 0;

      while (nCurrentCount <= inLen) {
        KISA_SEED_CBC.KISA_SEED_Decrypt_Block_forCBC(
          input,
          in_offset,
          output,
          out_offset,
          pInfo.seed_key
        );

        KISA_SEED_CBC.BLOCK_XOR_CBC(
          output,
          out_offset,
          output,
          out_offset,
          pdwXOR,
          pdwXOR_offset
        );

        pdwXOR = input;
        pdwXOR_offset = in_offset;

        nCurrentCount += KISA_SEED_CBC.BLOCK_SIZE_SEED;
        in_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
        out_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
      }

      outLen[0] = nCurrentCount - KISA_SEED_CBC.BLOCK_SIZE_SEED;

      Common.memcpy(
        pInfo.ivec,
        pdwXOR,
        KISA_SEED_CBC.BLOCK_SIZE_SEED,
        pdwXOR_offset
      );

      Common.memcpy(
        pInfo.cbc_last_block,
        output,
        KISA_SEED_CBC.BLOCK_SIZE_SEED,
        out_offset - KISA_SEED_CBC.BLOCK_SIZE_SEED_INT
      );
    }

    return 1;
  }

  public static SEED_CBC_Close(
    pInfo: KISA_SEED_INFO,
    output: number[],
    out_offset: number,
    outLen: number[]
  ): number {
    let nPaddngLeng: number;
    let i: number;

    outLen[0] = 0;

    if (null == output) return 0;

    if (KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt) {
      nPaddngLeng = KISA_SEED_CBC.BLOCK_SIZE_SEED - pInfo.buffer_length;

      for (i = pInfo.buffer_length; i < KISA_SEED_CBC.BLOCK_SIZE_SEED; i++) {
        Common.set_byte_for_int(
          pInfo.cbc_buffer,
          i,
          nPaddngLeng & 0xff,
          KISA_SEED_CBC.ENDIAN
        );
      }
      KISA_SEED_CBC.BLOCK_XOR_CBC(
        pInfo.cbc_buffer,
        0,
        pInfo.cbc_buffer,
        0,
        pInfo.ivec,
        0
      );

      KISA_SEED_CBC.KISA_SEED_Encrypt_Block_forCBC(
        pInfo.cbc_buffer,
        0,
        output,
        out_offset,
        pInfo.seed_key
      );

      outLen[0] = KISA_SEED_CBC.BLOCK_SIZE_SEED;

      return 1;
    } else {
      nPaddngLeng = Common.get_byte_for_int(
        pInfo.cbc_last_block,
        KISA_SEED_CBC.BLOCK_SIZE_SEED - 1,
        KISA_SEED_CBC.ENDIAN
      );
      if (nPaddngLeng > 0 && nPaddngLeng <= KISA_SEED_CBC.BLOCK_SIZE_SEED) {
        for (i = nPaddngLeng; i > 0; i--) {
          Common.set_byte_for_int(
            output,
            out_offset - i,
            0x00,
            KISA_SEED_CBC.ENDIAN
          );
        }

        outLen[0] = nPaddngLeng;
      } else return 0;
    }
    return 1;
  }

  public static SEED_CBC_Encrypt(
    pbszUserKey: Uint8Array,
    pbszIV: Uint8Array,
    message: Uint8Array,
    message_offset: number,
    message_length: number
  ): Uint8Array {
    const info = new KISA_SEED_INFO();
    let outbuf: number[];
    let data: number[];
    let cdata: Uint8Array;
    let outlen: number;
    let nRetOutLeng: number[] = [0];
    let nPaddingLeng: number[] = [0];

    const pbszPlainText: Uint8Array = message.slice(
      message_offset,
      message_offset + message_length
    );
    const nPlainTextLen: number = pbszPlainText.length;

    const nPlainTextPadding: number =
      KISA_SEED_CBC.BLOCK_SIZE_SEED -
      (nPlainTextLen % KISA_SEED_CBC.BLOCK_SIZE_SEED);

    const newpbszPlainText: Uint8Array = new Uint8Array(
      nPlainTextLen + nPlainTextPadding
    );
    Common.arraycopy(newpbszPlainText, pbszPlainText, nPlainTextLen);

    const pbszCipherText: Uint8Array = new Uint8Array(newpbszPlainText.length);

    KISA_SEED_CBC.SEED_CBC_init(
      info,
      KISA_ENC_DEC.KISA_ENCRYPT,
      pbszUserKey,
      pbszIV
    );

    outlen =
      (newpbszPlainText.length / KISA_SEED_CBC.BLOCK_SIZE_SEED) *
      KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
    outbuf = new Array(outlen);

    data = KISA_SEED_CBC.chartoint32_for_SEED_CBC(
      newpbszPlainText,
      nPlainTextLen
    );

    KISA_SEED_CBC.SEED_CBC_Process(
      info,
      data,
      nPlainTextLen,
      outbuf,
      nRetOutLeng
    );

    KISA_SEED_CBC.SEED_CBC_Close(
      info,
      outbuf,
      Math.floor(nRetOutLeng[0] / 4),
      nPaddingLeng
    );

    cdata = KISA_SEED_CBC.int32tochar_for_SEED_CBC(
      outbuf,
      nRetOutLeng[0] + nPaddingLeng[0]
    );
    Common.arraycopy(pbszCipherText, cdata, nRetOutLeng[0] + nPaddingLeng[0]);

    return pbszCipherText;
  }

  public static SEED_CBC_Decrypt(
    pbszUserKey: Uint8Array,
    pbszIV: Uint8Array,
    message: Uint8Array,
    message_offset: number,
    message_length: number
  ): Uint8Array {
    let info = new KISA_SEED_INFO();
    let outbuf: number[];
    let data: number[];
    let cdata: Uint8Array;
    let outlen: number;
    let nRetOutLeng: number[] = [0];
    let nPaddingLeng: number[] = [0];

    const pbszCipherText: Uint8Array = message.slice(
      message_offset,
      message_offset + message_length
    );

    let nCipherTextLen: number = pbszCipherText.length;

    if (pbszCipherText.length % KISA_SEED_CBC.BLOCK_SIZE_SEED !== 0) {
      return new Uint8Array(0); // Return empty array if cipher text length is not a multiple of BLOCK_SIZE_SEED
    }

    let newpbszCipherText: Uint8Array = new Uint8Array(nCipherTextLen);
    Common.arraycopy(newpbszCipherText, pbszCipherText, nCipherTextLen);

    nCipherTextLen = newpbszCipherText.length;

    KISA_SEED_CBC.SEED_CBC_init(
      info,
      KISA_ENC_DEC.KISA_DECRYPT,
      pbszUserKey,
      pbszIV
    );

    outlen = (nCipherTextLen / 16) * 4;
    outbuf = new Array(outlen);

    data = KISA_SEED_CBC.chartoint32_for_SEED_CBC(
      newpbszCipherText,
      nCipherTextLen
    );

    KISA_SEED_CBC.SEED_CBC_Process(
      info,
      data,
      nCipherTextLen,
      outbuf,
      nRetOutLeng
    );

    if (
      KISA_SEED_CBC.SEED_CBC_Close(
        info,
        outbuf,
        nRetOutLeng[0],
        nPaddingLeng
      ) == 1
    ) {
      cdata = KISA_SEED_CBC.int32tochar_for_SEED_CBC(
        outbuf,
        nRetOutLeng[0] - nPaddingLeng[0]
      );

      let pbszPlainText: Uint8Array = new Uint8Array(
        nRetOutLeng[0] - nPaddingLeng[0]
      );

      Common.arraycopy(pbszPlainText, cdata, nRetOutLeng[0] - nPaddingLeng[0]);

      let pdmessage_length: number = nRetOutLeng[0] - nPaddingLeng[0];
      let result: Uint8Array = new Uint8Array(pdmessage_length);
      result = pbszPlainText.slice(0, pdmessage_length);

      return result;
    } else {
      return new Uint8Array(0);
    }
  }

  private static stringToUint8Array(str: string): Uint8Array {
    const encoder = new TextEncoder(); // TextEncoder encodes into UTF-8 by default
    const uint8Array = encoder.encode(str);
    return uint8Array;
  }

  private static uint8ArrayToString(uint8Array: Uint8Array): string {
    const decoder = new TextDecoder("utf-8");
    return decoder.decode(uint8Array);
  }

  private static base64ToUint8Array(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }

  public static encrypt(
    pbszUserKey: string,
    pbszIV: string,
    message_str: string
  ): string {
    const pbszUserKeyUint8Array: Uint8Array =
      KISA_SEED_CBC.base64ToUint8Array(pbszUserKey);
    const pbszIVUint8Array: Uint8Array =
      KISA_SEED_CBC.base64ToUint8Array(pbszIV);
    const message: Uint8Array = KISA_SEED_CBC.stringToUint8Array(message_str);
    const result: Uint8Array = KISA_SEED_CBC.SEED_CBC_Encrypt(
      pbszUserKeyUint8Array,
      pbszIVUint8Array,
      message,
      0,
      message.length
    );
    return btoa(String.fromCharCode(...result));
  }

  public static decrypt(
    pbszUserKey: string,
    pbszIV: string,
    base64_str: string
  ): string {
    const pbszUserKeyUint8Array: Uint8Array =
      KISA_SEED_CBC.base64ToUint8Array(pbszUserKey);
    const pbszIVUint8Array: Uint8Array =
      KISA_SEED_CBC.base64ToUint8Array(pbszIV);
    const message: Uint8Array = KISA_SEED_CBC.base64ToUint8Array(base64_str);
    const result: Uint8Array = KISA_SEED_CBC.SEED_CBC_Decrypt(
      pbszUserKeyUint8Array,
      pbszIVUint8Array,
      message,
      0,
      message.length
    );
    return KISA_SEED_CBC.uint8ArrayToString(result);
  }
}
