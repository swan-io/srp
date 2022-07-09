import { expect, test } from "vitest";
import { SRPInt } from "../src/SRPInt";

test("SRPInt should keep padding when going back and forth", () => {
  expect(SRPInt.fromHex("a").toHex()).toStrictEqual("a");
  expect(SRPInt.fromHex("0a").toHex()).toStrictEqual("0a");
  expect(SRPInt.fromHex("00a").toHex()).toStrictEqual("00a");
  expect(SRPInt.fromHex("000a").toHex()).toStrictEqual("000a");
  expect(SRPInt.fromHex("0000a").toHex()).toStrictEqual("0000a");
  expect(SRPInt.fromHex("00000a").toHex()).toStrictEqual("00000a");
  expect(SRPInt.fromHex("000000a").toHex()).toStrictEqual("000000a");
  expect(SRPInt.fromHex("0000000a").toHex()).toStrictEqual("0000000a");
  expect(SRPInt.fromHex("00000000a").toHex()).toStrictEqual("00000000a");
});
