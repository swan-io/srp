export const encodeUtf8 = TextEncoder.prototype.encode.bind(new TextEncoder())
const hexPattern = /^[\da-f]+$/i

export const sanitizeHex = (hex: string): string =>
  hex.replace(/\s+/g, '').toLowerCase()

export const bufferToHex = (buffer: ArrayBuffer): string => {
  const array = new Uint8Array(buffer)
  let hex = ''

  for (let i = 0; i < array.length; i++) {
    const item = array[i]

    if (item != null) {
      hex += item.toString(16).padStart(2, '0')
    }
  }

  return hex
}

export const hexToBuffer = (hex: string): ArrayBuffer => {
  const sanitized = sanitizeHex(hex)

  if (sanitized.length % 2 !== 0) {
    throw new RangeError('Expected string to be an even number of characters')
  }

  if (sanitized.length > 0 && !hexPattern.test(sanitized)) {
    throw new RangeError(
      'Expected string to only contain hexadecimal characters',
    )
  }

  const array = new Uint8Array(sanitized.length / 2)

  for (let i = 0; i < sanitized.length; i += 2) {
    array[i / 2] = Number.parseInt(sanitized.substring(i, i + 2), 16)
  }

  return array.buffer
}

export const constantTimeEqualHex = (
  leftHex: string,
  rightHex: string,
): boolean => {
  const left = sanitizeHex(leftHex)
  const right = sanitizeHex(rightHex)

  if (
    left.length % 2 !== 0 ||
    right.length % 2 !== 0 ||
    !hexPattern.test(left) ||
    !hexPattern.test(right)
  ) {
    return false
  }

  const leftBytes = new Uint8Array(hexToBuffer(left))
  const rightBytes = new Uint8Array(hexToBuffer(right))
  const maxLength = Math.max(leftBytes.length, rightBytes.length)

  let mismatch = leftBytes.length ^ rightBytes.length

  for (let i = 0; i < maxLength; i++) {
    mismatch |= (leftBytes[i] ?? 0) ^ (rightBytes[i] ?? 0)
  }

  return mismatch === 0
}
