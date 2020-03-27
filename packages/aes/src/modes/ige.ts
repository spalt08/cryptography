import AES from '../aes';
import { getWords, xor } from '../utils/words';

/**
 * AES-IGE mode.
 */
export default class AES_IGE {
  cipher: AES;
  key: Uint32Array;
  iv: Uint32Array;
  blockSize: number;

  constructor(key: string | Uint32Array | Uint8Array, iv: string | Uint32Array | Uint8Array, blockSize = 16) {
    this.key = getWords(key);
    this.iv = getWords(iv);
    this.cipher = new AES(key);
    this.blockSize = blockSize / 4;
  }

  /**
   * Encrypts plain text with AES-IGE mode.
   */
  encrypt(message: string | Uint32Array | Uint8Array, buf?: Uint32Array) {
    const text = getWords(message);
    const cipherText = buf || new Uint32Array(text.length);

    const prevX = this.iv.subarray(this.blockSize, this.iv.length);
    const prevY = this.iv.subarray(0, this.blockSize);
    const x = new Uint32Array(this.blockSize);
    const y = new Uint32Array(this.blockSize);
    const yXOR = new Uint32Array(this.blockSize);

    for (let i = 0; i < text.length; i += this.blockSize) {
      x.set(text.subarray(i, i + this.blockSize));
      xor(x, prevX, yXOR);

      y.set(this.cipher.encrypt(yXOR));
      xor(y, prevX);

      prevX.set(x);
      prevY.set(y);

      cipherText.set(y, i);
    }

    return cipherText;
  }

  /**
   * Decrypts cipher text with AES-IGE mode.
   */
  decrypt(message: string | Uint32Array | Uint8Array, buf?: Uint32Array) {
    const cipherText = getWords(message);
    const text = buf || new Uint32Array(cipherText.length);

    const prevY = this.iv.subarray(this.blockSize, this.iv.length);
    const prevX = this.iv.subarray(0, this.blockSize);
    const x = new Uint32Array(this.blockSize);
    const y = new Uint32Array(this.blockSize);
    const yXOR = new Uint32Array(this.blockSize);

    for (let i = 0; i < text.length; i += this.blockSize) {
      x.set(cipherText.subarray(i, i + this.blockSize));
      xor(x, prevY, yXOR);

      y.set(this.cipher.decrypt(yXOR));
      xor(y, prevX);

      prevX.set(x);
      prevY.set(y);

      text.set(y, i);
    }

    return text;
  }
}
