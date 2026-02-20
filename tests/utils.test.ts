import { expect, test } from 'bun:test'
import { bufferToHex, constantTimeEqualHex, hexToBuffer } from '../src/utils'

const numbersToBuffer = (numbers: number[]): ArrayBuffer =>
  new Uint8Array(numbers).buffer

const isArrayBufferEqual = (
  buffer1: ArrayBuffer,
  buffer2: ArrayBuffer,
): boolean => {
  // Vérifie si les deux ArrayBuffers ont la même longueur
  if (buffer1.byteLength !== buffer2.byteLength) {
    return false
  }

  // Crée des vues Uint8Array pour comparer les octets
  const view1 = new Uint8Array(buffer1)
  const view2 = new Uint8Array(buffer2)

  // Compare chaque octet
  for (let i = 0; i < view1.length; i++) {
    if (view1[i] !== view2[i]) {
      return false
    }
  }

  // Si tous les octets sont égaux, les ArrayBuffers sont égaux
  return true
}

test('bufferToHex', () => {
  const runTest = (numbers: number[], hex: string) =>
    expect(bufferToHex(numbersToBuffer(numbers))).toStrictEqual(hex)

  runTest([], '')
  runTest([0x13, 0x37], '1337')
  runTest([0xaa, 0xbb], 'aabb')
  runTest([0x8c, 0x82, 0x5d, 0x0c, 0x40, 0xd8, 0x7f, 0xfa], '8c825d0c40d87ffa')

  runTest(
    [
      0xce, 0xae, 0x96, 0xa3, 0x25, 0xe1, 0xdc, 0x5d, 0xd4, 0xf4, 0x05, 0xd9,
      0x05, 0x04, 0x9c, 0xeb,
    ],
    'ceae96a325e1dc5dd4f405d905049ceb',
  )
})

test('hexToBuffer', () => {
  const runTest = (hex: string, numbers: number[]) =>
    expect(
      isArrayBufferEqual(hexToBuffer(hex), numbersToBuffer(numbers)),
    ).toBeTruthy()

  runTest('', [])
  runTest('1337', [0x13, 0x37])
  runTest('aabb', [0xaa, 0xbb])
  runTest('AABB', [0xaa, 0xbb])
  runTest('8c825d0c40d87ffa', [0x8c, 0x82, 0x5d, 0x0c, 0x40, 0xd8, 0x7f, 0xfa])

  runTest(
    'ceae96a325e1dc5dd4f405d905049ceb',
    [
      0xce, 0xae, 0x96, 0xa3, 0x25, 0xe1, 0xdc, 0x5d, 0xd4, 0xf4, 0x05, 0xd9,
      0x05, 0x04, 0x9c, 0xeb,
    ],
  )
  runTest(
    'CEAE96A325E1DC5DD4F405D905049CEB',
    [
      0xce, 0xae, 0x96, 0xa3, 0x25, 0xe1, 0xdc, 0x5d, 0xd4, 0xf4, 0x05, 0xd9,
      0x05, 0x04, 0x9c, 0xeb,
    ],
  )
})

test('hexToBuffer should reject malformed hex input', () => {
  expect(() => hexToBuffer('abc')).toThrow(RangeError)
  expect(() => hexToBuffer('zz')).toThrow(RangeError)
})

test('constantTimeEqualHex', () => {
  expect(constantTimeEqualHex('AABBCC', 'aabbcc')).toBeTruthy()
  expect(constantTimeEqualHex('aa', 'ab')).toBeFalsy()
  expect(constantTimeEqualHex('aa', 'aabb')).toBeFalsy()
  expect(constantTimeEqualHex('zz', 'aa')).toBeFalsy()
})
