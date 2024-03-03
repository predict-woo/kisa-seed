class Common {
  public static readonly BIG_ENDIAN: number = 0;
  public static readonly LITTLE_ENDIAN: number = 1;

  public static readonly ENDIAN: number = Common.BIG_ENDIAN;

  public static arraycopy(
    dst: Uint8Array,
    src: Uint8Array,
    length: number
  ): void {
    for (let i = 0; i < length; i++) {
      dst[i] = src[i];
    }
  }

  public static arraycopy_offset(
    dst: Uint8Array,
    dst_offset: number,
    src: Uint8Array,
    src_offset: number,
    length: number
  ): void {
    for (let i = 0; i < length; i++) {
      dst[dst_offset + i] = src[src_offset + i];
    }
  }

  public static arrayinit(
    dst: Uint8Array,
    value: number,
    length: number
  ): void {
    for (let i = 0; i < length; i++) {
      dst[i] = value;
    }
  }

  public static arrayinit_offset(
    dst: Uint8Array,
    dst_offset: number,
    value: number,
    length: number
  ): void {
    for (let i = 0; i < length; i++) {
      dst[dst_offset + i] = value;
    }
  }

  public static memcpy(
    dst: number[],
    src: Uint8Array,
    length: number,
    ENDIAN: number
  ): void;
  public static memcpy(
    dst: number[],
    src: number[],
    src_offset: number,
    length: number
  ): void;

  // Implementation
  public static memcpy(
    dst: number[],
    src: Uint8Array | number[],
    length: number,
    ENDIAN_or_src_offset?: number
  ): void {
    if (src instanceof Uint8Array && typeof ENDIAN_or_src_offset === "number") {
      // Handle the Uint8Array case
      let iLen = Math.floor(length / 4);
      for (let i = 0; i < iLen; i++) {
        // Assuming byte_to_int is a method that correctly handles this operation
        this.byte_to_int(dst, i, src, i * 4, ENDIAN_or_src_offset);
      }
    } else if (Array.isArray(src) && typeof ENDIAN_or_src_offset === "number") {
      // Handle the number[] case
      let iLen = Math.floor(length / 4) + (length % 4 !== 0 ? 1 : 0);
      for (let i = 0; i < iLen; i++) {
        dst[i] = src[ENDIAN_or_src_offset + i];
      }
    } else {
      throw new Error("Invalid arguments");
    }
  }

  public static set_byte_for_int(
    dst: number[],
    b_offset: number,
    value: number,
    endian: number
  ): void {
    let shift_value: number;
    let mask_value: number;
    let mask_value2: number;
    let value2: number;
    if (Common.ENDIAN == Common.BIG_ENDIAN) {
      shift_value = (3 - (b_offset % 4)) * 8;
      mask_value = 0x0ff << shift_value;
      mask_value2 = ~mask_value;
      value2 = (value & 0x0ff) << shift_value;
      dst[Math.floor(b_offset / 4)] =
        (dst[Math.floor(b_offset / 4)] & mask_value2) | (value2 & mask_value);
    } else {
      shift_value = (b_offset % 4) * 8;
      mask_value = 0x0ff << shift_value;
      mask_value2 = ~mask_value;
      value2 = (value & 0x0ff) << shift_value;
      dst[Math.floor(b_offset / 4)] =
        (dst[Math.floor(b_offset / 4)] & mask_value2) | (value2 & mask_value);
    }
  }

  public static get_byte_for_int(
    src: number[],
    b_offset: number,
    ENDIAN: number
  ): number {
    let shift_value: number;
    let mask_value: number;
    let value: number;

    if (ENDIAN == Common.BIG_ENDIAN) {
      shift_value = (3 - (b_offset % 4)) * 8;
      mask_value = 0x0ff << shift_value;
      value = (src[Math.floor(b_offset / 4)] & mask_value) >> shift_value;
      return value & 0xff;
    } else {
      shift_value = (b_offset % 4) * 8;
      mask_value = 0x0ff << shift_value;
      value = (src[Math.floor(b_offset / 4)] & mask_value) >> shift_value;
      return value & 0xff;
    }
  }

  public static get_bytes_for_ints(
    src: number[],
    offset: number,
    endian: number
  ): Uint8Array {
    let iLen = src.length - offset;
    let result = new Uint8Array(iLen * 4);
    for (let i = 0; i < iLen; i++) {
      this.int_to_byte(result, i * 4, src, offset + i, endian);
    }
    return result;
  }

  public static byte_to_int(
    dst: number[],
    dst_offset: number,
    src: Uint8Array,
    src_offset: number,
    ENDIAN: number
  ): void;
  public static byte_to_int(
    src: Uint8Array,
    src_offset: number,
    ENDIAN: number
  ): number;

  // Unified implementation
  public static byte_to_int(...args: any[]): void | number {
    if (args.length === 5) {
      // Destructuring arguments for clarity
      const [dst, dst_offset, src, src_offset, ENDIAN] = args;

      if (ENDIAN === Common.BIG_ENDIAN) {
        dst[dst_offset] =
          (src[src_offset] << 24) |
          (src[src_offset + 1] << 16) |
          (src[src_offset + 2] << 8) |
          src[src_offset + 3];
      } else {
        dst[dst_offset] =
          src[src_offset] |
          (src[src_offset + 1] << 8) |
          (src[src_offset + 2] << 16) |
          (src[src_offset + 3] << 24);
      }
    } else if (args.length === 3) {
      const [src, src_offset, ENDIAN] = args;

      if (ENDIAN === Common.BIG_ENDIAN) {
        return (
          (src[src_offset] << 24) |
          (src[src_offset + 1] << 16) |
          (src[src_offset + 2] << 8) |
          src[src_offset + 3]
        );
      } else {
        return (
          src[src_offset] |
          (src[src_offset + 1] << 8) |
          (src[src_offset + 2] << 16) |
          (src[src_offset + 3] << 24)
        );
      }
    } else {
      throw new Error("Invalid arguments");
    }
  }

  // Convert byte array to int, assuming big endian
  public static byte_to_int_big_endian(
    src: Uint8Array,
    src_offset: number
  ): number {
    return (
      (src[src_offset] << 24) |
      (src[src_offset + 1] << 16) |
      (src[src_offset + 2] << 8) |
      src[src_offset + 3]
    );
  }

  // Convert int to byte array
  public static int_to_byte(
    dst: Uint8Array,
    dst_offset: number,
    src: number[],
    src_offset: number,
    ENDIAN: number
  ): void {
    this.int_to_byte_unit(dst, dst_offset, src[src_offset], ENDIAN);
  }

  // Helper method for int_to_byte
  public static int_to_byte_unit(
    dst: Uint8Array,
    dst_offset: number,
    src: number,
    ENDIAN: number
  ): void {
    if (ENDIAN === this.BIG_ENDIAN) {
      dst[dst_offset] = (src >> 24) & 0xff;
      dst[dst_offset + 1] = (src >> 16) & 0xff;
      dst[dst_offset + 2] = (src >> 8) & 0xff;
      dst[dst_offset + 3] = src & 0xff;
    } else {
      dst[dst_offset] = src & 0xff;
      dst[dst_offset + 1] = (src >> 8) & 0xff;
      dst[dst_offset + 2] = (src >> 16) & 0xff;
      dst[dst_offset + 3] = (src >> 24) & 0xff;
    }
  }

  // Convert int to byte array, assuming big endian
  public static int_to_byte_unit_big_endian(
    dst: Uint8Array,
    dst_offset: number,
    src: number
  ): void {
    dst[dst_offset] = (src >> 24) & 0xff;
    dst[dst_offset + 1] = (src >> 16) & 0xff;
    dst[dst_offset + 2] = (src >> 8) & 0xff;
    dst[dst_offset + 3] = src & 0xff;
  }

  // Unsigned right shift
  public static URShift(x: number, n: number): number {
    if (n === 0) return x;
    if (n >= 32) return 0;
    let v = x >> n;
    let v_mask = ~(0x80000000 >> (n - 1));
    return v & v_mask;
  }

  // Convert signed int to unsigned long
  static readonly INT_RANGE_MAX: number = Math.pow(2, 32);

  public static intToUnsigned(x: number): number {
    if (x >= 0) return x;
    return x + this.INT_RANGE_MAX;
  }

  // PKCS #7 Padding
  public static Padding(
    pbData: Uint8Array,
    padData: Uint8Array,
    length: number
  ): number {
    let padvalue = 16 - (length % 16);
    for (let i = 0; i < length; i++) {
      padData[i] = pbData[i];
    }
    let i = length;
    do {
      padData[i] = padvalue;
      i++;
    } while (i % 16 !== 0);
    return i;
  }

  // 128-bit XOR operation
  public static BLOCK_XOR_PROPOSAL(
    OUT_VALUE: number[],
    out_value_offset: number,
    IN_VALUE1: number[],
    in_value1_offset: number,
    IN_VALUE2: number[],
    in_value2_offset: number
  ): void {
    for (let i = 0; i < 4; i++) {
      OUT_VALUE[out_value_offset + i] =
        (in_value1_offset + i < IN_VALUE1.length
          ? IN_VALUE1[in_value1_offset + i]
          : 0) ^
        (in_value2_offset + i < IN_VALUE2.length
          ? IN_VALUE2[in_value2_offset + i]
          : 0);
    }
  }
}

export default Common;
