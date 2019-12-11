/** Gets a uint32 from string in big-endian order order */
function strToInt32(str: string, pos: number) {
  return (
    str.charCodeAt(pos) << 24
    ^ str.charCodeAt(pos + 1) << 16
    ^ str.charCodeAt(pos + 2) << 8
    ^ str.charCodeAt(pos + 3)
  );
}

/** Returns a uint32 as a string in big-endian order order */
function int32ToStr(data: number) {
  return (
    String.fromCharCode((data >> 24) & 0xFF)
    + String.fromCharCode((data >> 16) & 0xFF)
    + String.fromCharCode((data >> 8) & 0xFF)
    + String.fromCharCode(data & 0xFF)
  );
}

// K table for SHA-256
const _k = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// padding
let _padding = String.fromCharCode(128);
for (let i = 0; i < 64; i += 1) _padding += String.fromCharCode(0);

/**
 * Creates new sha256 state
 */
function init(): Uint32Array {
  const h = new Uint32Array(8);

  // SHA-256 state contains eight 32-bit integers
  h[0] = 0x6A09E667;
  h[1] = 0xBB67AE85;
  h[2] = 0x3C6EF372;
  h[3] = 0xA54FF53A;
  h[4] = 0x510E527F;
  h[5] = 0x9B05688C;
  h[6] = 0x1F83D9AB;
  h[7] = 0x5BE0CD19;

  return h;
}

// Array to use to store words.
const words = new Uint32Array(64);

/**
 * Updates sha512 state
 */
function update(state: Uint32Array, data: string): string;
function update(state: Uint32Array, data: Uint32Array): Uint32Array;
function update(state: Uint32Array, data: string | Uint32Array) {
  let t1; let t2; let s0; let s1; let ch; let maj;
  let a; let b; let c; let d; let e; let f; let g; let h;

  let i = 0;
  let len = 0;
  let selector;

  if (typeof data === 'string') {
    len = data.length;
    selector = (dt: string, ix: number): number => strToInt32(dt, ix * 4);

    data.substr(0, 1);
  } else {
    len = data.length * 4;
    selector = (dt: Uint32Array, ix: number): number => dt[ix];
  }

  // While decrementing loop is much faster than for
  while (len >= 64) {
    // initialize hash value for this chunk
    // [a, b, c, d, e, f, g, h] = nextState;
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 16; i += 1) {
      words[i] = selector(data as any, i);
    }

    for (; i < 64; i += 1) {
      // XOR word 2 words ago rot right 17, rot right 19, shft right 10
      t1 = words[i - 2];
      t1 = ((t1 >>> 17) | (t1 << 15))
        ^ ((t1 >>> 19) | (t1 << 13))
        ^ (t1 >>> 10);

      // XOR word 15 words ago rot right 7, rot right 18, shft right 3
      t2 = words[i - 15];
      t2 = ((t2 >>> 7) | (t2 << 25))
        ^ ((t2 >>> 18) | (t2 << 14))
        ^ (t2 >>> 3);

      // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^32
      words[i] = (t1 + words[i - 7] + t2 + words[i - 16]);
    }

    // Round Function
    for (i = 0; i < 64; i += 1) {
      // Sum1(e)
      s1 = ((e >>> 6) | (e << 26))
        ^ ((e >>> 11) | (e << 21))
        ^ ((e >>> 25) | (e << 7));

      // Ch(e, f, g) (optimized the same way as SHA-1)
      ch = g ^ (e & (f ^ g));

      // Sum0(a)
      s0 = ((a >>> 2) | (a << 30))
        ^ ((a >>> 13) | (a << 19))
        ^ ((a >>> 22) | (a << 10));

      // Maj(a, b, c) (optimized the same way as SHA-1)
      maj = (a & b) | (c & (a ^ b));

      // main algorithm
      t1 = h + s1 + ch + _k[i] + words[i];
      t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    // update hash state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    len -= 64;
    if (typeof data === 'string') data = data.slice(64);
  }

  return data;
}

/**
 * Adds padding to message and updates sha512 state
 */
function finalize(h: Uint32Array, data: string, len: number = data.length) {
  // true 64-bit message length as two 32-bit ints
  const len64hi = (len / 0x100000000) >>> 0;
  const len64lo = len >>> 0;

  const pad = data
    + _padding.substr(0, 64 - ((len64lo + 8) & 0x3F))
    + int32ToStr((len64hi << 3) | (len64hi >>> 28))
    + int32ToStr(len64lo << 3);

  update(h, pad);
}

/**
 * Convert sha256 state to string
 */
function stateToStr(h: Uint32Array): string {
  return int32ToStr(h[0])
  + int32ToStr(h[1])
  + int32ToStr(h[2])
  + int32ToStr(h[3])
  + int32ToStr(h[4])
  + int32ToStr(h[5])
  + int32ToStr(h[6])
  + int32ToStr(h[7]);
}


/**
 * Calculates sha256 hash from string
 */
function sha256(message: string): string;
function sha256(message: string, out: 'array'): Uint32Array;
function sha256(message: string, out?: string): string | Uint32Array {
  const h = init();
  finalize(h, message);

  if (out === 'array') {
    return h;
  }

  return stateToStr(h);
}

interface StreamInterface {
  data: string;
  length: number;
  state: Uint32Array;
  update(data: string | Uint32Array): StreamInterface;
  digest(): string;
  digest(format: 'array'): Uint32Array;
}

interface StreamConstructor {
  new (): StreamInterface;
}

/**
 * Creates stream object
 */
const CreateStream = function (this: StreamInterface): StreamInterface {
  this.data = '';
  this.length = 0;
  this.state = init();

  this.update = function (data: string | Uint32Array) {
    if (typeof data === 'string') {
      this.length += data.length;
      this.data = update(this.state, this.data + data);
    } else {
      this.length += data.length * 4;
      update(this.state, data);
    }

    return this;
  };

  this.digest = function (format?: string): any {
    finalize(this.state, this.data, this.length);

    if (format === 'array') {
      return this.state;
    }

    return stateToStr(this.state);
  };

  return this;
} as any as StreamConstructor;

/**
 * Stream hashing mode
 */
sha256.stream = function (): StreamInterface {
  return new CreateStream();
};

sha256.blockLength = 64;
sha256.digestLength = 32;

export default sha256;
