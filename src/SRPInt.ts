import { BigInteger } from "jsbn";
import { getRandomValues } from "./crypto";
import { bufferToHex, sanitizeHex } from "./utils";

const kBigInt = Symbol("big-int");
const kLength = Symbol("hex-length");

export class SRPInt {
  [kBigInt]: BigInteger;
  [kLength]: number | null;

  constructor(bigInt: BigInteger, length: number | null) {
    this[kBigInt] = bigInt;
    this[kLength] = length;
  }

  static ZERO = new SRPInt(new BigInteger("0"), null);

  static getRandom(bytes: number): SRPInt {
    const array = new Uint8Array(bytes);
    getRandomValues(array);
    return SRPInt.fromHex(bufferToHex(array));
  }

  static fromHex(hex: string): SRPInt {
    const sanitized = sanitizeHex(hex);
    return new SRPInt(new BigInteger(sanitized, 16), sanitized.length);
  }

  toHex(): string {
    const length = this[kLength];

    if (length === null) {
      throw new Error("This SRPInt has no specified length");
    }

    return this[kBigInt].toString(16).padStart(length, "0");
  }

  equals(value: SRPInt): boolean {
    return this[kBigInt].equals(value[kBigInt]);
  }

  add(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].add(value[kBigInt]), null);
  }

  subtract(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].subtract(value[kBigInt]), this[kLength]);
  }

  multiply(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].multiply(value[kBigInt]), null);
  }

  xor(value: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].xor(value[kBigInt]), this[kLength]);
  }

  mod(modulus: SRPInt): SRPInt {
    return new SRPInt(this[kBigInt].mod(modulus[kBigInt]), modulus[kLength]);
  }

  modPow(exponent: SRPInt, modulus: SRPInt): SRPInt {
    return new SRPInt(
      this[kBigInt].modPow(exponent[kBigInt], modulus[kBigInt]),
      modulus[kLength],
    );
  }

  pad(paddedLength: number): SRPInt {
    const length = this[kLength];

    if (length !== null && paddedLength < length) {
      throw new Error("Cannot pad to a shorter length");
    }

    return new SRPInt(this[kBigInt], paddedLength);
  }
}
