export class KISA_ENC_DEC {
  public static _KISA_ENCRYPT: number = 0;
  public static _KISA_DECRYPT: number = 1;

  public value: number;

  constructor(value: number) {
    this.value = value;
  }

  public static KISA_ENCRYPT: KISA_ENC_DEC = new KISA_ENC_DEC(
    KISA_ENC_DEC._KISA_ENCRYPT
  );
  public static KISA_DECRYPT: KISA_ENC_DEC = new KISA_ENC_DEC(
    KISA_ENC_DEC._KISA_DECRYPT
  );
}

export class KISA_SEED_KEY {
  public key_data: number[] = new Array(32).fill(0);

  public init(): void {
    this.key_data.fill(0);
  }
}

export class KISA_SEED_INFO {
  public encrypt: number;
  public ivec: number[] = new Array(4).fill(0);
  public seed_key: KISA_SEED_KEY = new KISA_SEED_KEY();
  public cbc_buffer: number[] = new Array(4).fill(0);
  public buffer_length: number = 0;
  public cbc_last_block: number[] = new Array(4).fill(0);
  public last_block_flag: number = 0;

  constructor() {
    this.encrypt = 0;
    this.ivec.fill(0);
    this.seed_key.init();
    this.cbc_buffer.fill(0);
    this.buffer_length = 0;
    this.cbc_last_block.fill(0);
    this.last_block_flag = 0;
  }
}
