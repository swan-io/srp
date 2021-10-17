export const sanitizeHex = (hex: string) =>
  hex.replace(/\s+/g, "").toLowerCase();

export const padHex = (hex: string) => (hex.length % 2 === 0 ? hex : "0" + hex);

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
  // hex = padHex(hex); Not needed for the moment
  const array = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return array.buffer;
};
