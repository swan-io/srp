export const bufferToHex = (buffer: ArrayBuffer): string => {
  let hex = "";
  const array = new Uint8Array(buffer);

  for (let i = 0; i < array.length; i++) {
    const value = array[i].toString(16);
    hex += value.length === 1 ? "0" + value : value;
  }

  return hex;
};

export const hexToBuffer = (hex: string): ArrayBuffer => {
  hex = hex.length % 2 !== 0 ? "0" + hex : hex;
  const array = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return array.buffer;
};
