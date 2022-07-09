export const encodeUtf8 = TextEncoder.prototype.encode.bind(new TextEncoder());

export const bufferToHex = (buffer: ArrayBuffer): string => {
  const array = new Uint8Array(buffer);
  let hex = "";

  for (let i = 0; i < array.length; i++) {
    const item = array[i];

    if (item != null) {
      hex += item.toString(16).padStart(2, "0");
    }
  }

  return hex;
};

export const hexToBuffer = (hex: string): ArrayBuffer => {
  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const array = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return array.buffer;
};
