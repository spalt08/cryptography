import { s2i } from '@cryptography/utils';
import type { HashFunction } from '@cryptography/utils';

/**
 * Produces the Message Authentication Code (MAC).
 */
function hmac(message: string | Uint32Array, key: Uint32Array, digest: HashFunction, formay?: 'array', buf?: Uint32Array): Uint32Array;
function hmac(message: string | Uint32Array, key: Uint32Array, digest: HashFunction, format: 'hex' | 'binary', buf?: Uint32Array): string;
function hmac(message: string | Uint32Array, key: Uint32Array, digest: HashFunction, format?: any, buf?: Uint32Array): string | Uint32Array {
  const ilen = digest.blockLength / 4;
  const ipad = new Uint32Array(ilen);
  const opad = new Uint32Array(ilen);

  // mix key into inner and outer padding
  // ipadding = [0x36 * blocksize] ^ key
  // opadding = [0x5C * blocksize] ^ key
  for (let i = 0; i < ilen; i += 1) {
    ipad[i] = 0x36363636 ^ key[i];
    opad[i] = 0x5C5C5C5C ^ key[i];
  }

  // digest is done like so: hash(opadding | hash(ipadding | message))
  const inner = digest.stream().update(ipad).update(message).digest();
  return digest.stream(buf).update(opad).update(inner).digest(format);
}

/**
 * Prepare string key for hmac
 */
hmac.key = (str: string, digest: HashFunction) => {
  let key: Uint32Array;

  // if key is longer than blocksize, hash it
  if (str.length > digest.blockLength) key = digest(str);
  else {
    key = new Uint32Array(digest.blockLength);
    for (let i = 0; i < str.length; i += 4) key[i / 4] = s2i(str, i);
  }

  return key;
};

export default hmac;
