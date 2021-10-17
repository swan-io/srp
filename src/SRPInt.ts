import { BigInteger } from "jsbn";
import { getRandomValues } from "./crypto";
import { bufferToHex, sanitizeHex } from "./utils";

const kBigInt = Symbol("big-int");
const kHexLength = Symbol("hex-length");

export class SRPInt {
  [kBigInt]: BigInteger;
  [kHexLength]: number | null;

  constructor(bigInt: BigInteger, hexLength: number | null) {
    this[kBigInt] = bigInt;
    this[kHexLength] = hexLength;
  }

  static ZERO = new SRPInt(new BigInteger("0"), null);

  static getRandom(bytes: number): SRPInt {
    const array = new Uint8Array(bytes);
    getRandomValues(array);
    return SRPInt.fromHex(bufferToHex(array));
  }

  static fromHex(hex: string): SRPInt {
    // TODO: Remove support for hex that are not % 2 and the need for kHexLength
    const sanitized = sanitizeHex(hex);
    return new SRPInt(new BigInteger(sanitized, 16), sanitized.length);
  }

  toHex(): string {
    const hexLength = this[kHexLength];

    if (hexLength === null) {
      throw new Error("This SRPInt has no specified length");
    }

    return this[kBigInt].toString(16).padStart(hexLength, "0");
  }

  equals(value: SRPInt): boolean {
    return this[kBigInt].equals(value[kBigInt]);
  }

  add(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].add(value[kBigInt]), null);
  }

  subtract(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].subtract(value[kBigInt]), this[kHexLength]);
  }

  multiply(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].multiply(value[kBigInt]), null);
  }

  xor(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].xor(value[kBigInt]), this[kHexLength]);
  }

  mod(modulus: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].mod(modulus[kBigInt]), modulus[kHexLength]);
  }

  modPow(exponent: SRPInt, modulus: SRPInt): SRPInt {
    return new SRPInt(
      this[kBigInt].modPow(exponent[kBigInt], modulus[kBigInt]),
      modulus[kHexLength],
    );
  }

  pad(paddedLength: number): SRPInt {
    const hexLength = this[kHexLength];

    if (hexLength !== null && paddedLength < hexLength) {
      throw new Error("Cannot pad to a shorter length");
    }

    return new SRPInt(this[kBigInt], paddedLength);
  }
}
