import { BigInteger } from "jsbn";
import { getRandomValues } from "./crypto";
import { bufferToHex } from "./utils";

const bi = Symbol("big-int");

export class SRPInt {
  [bi]: BigInteger;

  constructor(
    bigInt: BigInteger,
    public hexLength: number | null,
  ) {
    this[bi] = bigInt;
  }

  static ZERO = new SRPInt(new BigInteger("0"), null);

  static fromHex(hex: string): SRPInt {
    const sanitized = hex.replace(/\s+/g, "").toLowerCase();
    return new SRPInt(new BigInteger(sanitized, 16), sanitized.length);
  }

  static getRandom(bytes: number): SRPInt {
    const array = new Uint8Array(bytes);
    getRandomValues(array);
    return SRPInt.fromHex(bufferToHex(array));
  }

  add(value: SRPInt): SRPInt {
    return new SRPInt(this[bi].add(value[bi]), null);
  }

  equals(value: SRPInt): boolean {
    return this[bi].equals(value[bi]);
  }

  mod(modulus: SRPInt): SRPInt {
    return new SRPInt(this[bi].mod(modulus[bi]), modulus.hexLength);
  }

  modPow(exponent: SRPInt, modulus: SRPInt): SRPInt {
    return new SRPInt(
      this[bi].modPow(exponent[bi], modulus[bi]),
      modulus.hexLength,
    );
  }

  multiply(value: SRPInt): SRPInt {
    return new SRPInt(this[bi].multiply(value[bi]), null);
  }

  pad(paddedHexLength: number): SRPInt {
    if (this.hexLength !== null && paddedHexLength < this.hexLength) {
      throw new Error("Cannot pad to a shorter length");
    }

    return new SRPInt(this[bi], paddedHexLength);
  }

  subtract(value: SRPInt): SRPInt {
    return new SRPInt(this[bi].subtract(value[bi]), this.hexLength);
  }

  toHex(): string {
    if (this.hexLength === null) {
      throw new Error("This SRPInt has no specified length");
    }

    return this[bi].toString(16).padStart(this.hexLength, "0");
  }

  xor(value: SRPInt): SRPInt {
    return new SRPInt(this[bi].xor(value[bi]), this.hexLength);
  }
}
