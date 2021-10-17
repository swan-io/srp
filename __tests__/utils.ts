import isEqual from "arraybuffer-equal";
import { bufferToHex, hexToBuffer } from "../src/utils";

const numbersToBuffer = (numbers: number[]): ArrayBuffer => {
  const array = new Uint8Array(numbers.length);

  for (let i = 0; i < array.length; i++) {
    array[i] = numbers[i];
  }

  return array.buffer;
};

test("bufferToHex", () => {
  expect(
    bufferToHex(
      numbersToBuffer([0x8c, 0x82, 0x5d, 0x0c, 0x40, 0xd8, 0x7f, 0xfa]),
    ),
  ).toStrictEqual("8c825d0c40d87ffa");
});

test("hexToBuffer", () => {
  const run = (hex: string, numbers: number[]) =>
    expect(isEqual(hexToBuffer(hex), numbersToBuffer(numbers))).toBeTruthy();

  run("", []);

  run("1337", [0x13, 0x37]);
  run("aabb", [0xaa, 0xbb]);
  run("AABB", [0xaa, 0xbb]);

  run(
    "ceae96a325e1dc5dd4f405d905049ceb",
    [
      0xce, 0xae, 0x96, 0xa3, 0x25, 0xe1, 0xdc, 0x5d, 0xd4, 0xf4, 0x05, 0xd9,
      0x05, 0x04, 0x9c, 0xeb,
    ],
  );

  run(
    "CEAE96A325E1DC5DD4F405D905049CEB",
    [
      0xce, 0xae, 0x96, 0xa3, 0x25, 0xe1, 0xdc, 0x5d, 0xd4, 0xf4, 0x05, 0xd9,
      0x05, 0x04, 0x9c, 0xeb,
    ],
  );
});
