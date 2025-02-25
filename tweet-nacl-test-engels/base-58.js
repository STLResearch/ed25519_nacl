const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function toBase58(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return "";

  let encoded = "";
  const bytes = [...buffer];

  // Count leading zeroes
  let zeroes = 0;
  while (zeroes < bytes.length && bytes[zeroes] === 0) {
    zeroes++;
  }

  let length = 0;
  const size = Math.floor((bytes.length - zeroes) * 138 / 100) + 1;
  const b58bytes = new Array(size).fill(0);

  for (let byte of bytes.slice(zeroes)) {
    let carry = byte;
    let i = 0;
    for (let j = 0; j < size; j++, i++) {
      if (!(carry !== 0 || i < length)) break;
      carry += 256 * b58bytes[j];
      b58bytes[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = i;
  }

  const finalBytes = b58bytes.slice(0, length);
  for (let byte of finalBytes.reverse()) {
    encoded += BASE58_ALPHABET[byte];
  }

  return "1".repeat(zeroes) + encoded;
}

module.exports = { toBase58 }