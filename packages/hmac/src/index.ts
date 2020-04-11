import { s2i } from '@cryptography/utils';

export interface HashStream {
  update(chunk: string | Uint32Array): HashStream;
  digest(): Uint32Array;
  digest(format: 'hex' | 'binary'): string;
}

export interface HashFunction {
  (message: string | Uint32Array): Uint32Array;
  (message: string | Uint32Array, format: 'hex' | 'binary'): string;
  stream(buf?: Uint32Array): HashStream;
  blockLength: number;
  digestLength: number;
}

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
hmac.key = (src: string | Uint32Array, digest: HashFunction) => {
  if (src instanceof Uint32Array) {
    if (src.length > digest.blockLength / 4) return digest(src);
    return src;
  }

  // if key is longer than blocksize, hash it
  if (src.length > digest.blockLength) return digest(src);

  const key = new Uint32Array(digest.blockLength);
  for (let i = 0; i < src.length; i += 4) key[i / 4] = s2i(src, i);

  return key;
};

export default hmac;
