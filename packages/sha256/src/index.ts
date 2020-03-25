/**
 * Creates new SHA-256 state
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


/** Array to use to store round words. */
const words = new Uint32Array(64);

/** K table for SHA-256 */
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

/** Reusing vars */
let t1; let t2; let s0; let s1; let ch; let maj;
let a; let b; let c; let d; let e; let f; let g; let h;
let i;

/**
 * Perform round function
 */
function round(state: Uint32Array, data: Uint32Array) {
  // initialize hash value for this chunk
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  words.set(data);

  for (i = 16; i < 64; i += 1) {
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
}

/**
 * Gets a uint32 from string in big-endian order order
 */
function strToInt32(str: string, pos: number) {
  return (
    str.charCodeAt(pos) << 24
    ^ str.charCodeAt(pos + 1) << 16
    ^ str.charCodeAt(pos + 2) << 8
    ^ str.charCodeAt(pos + 3)
  );
}

/**
 * Returns a uint32 as a string in big-endian order order
 */
function int32ToStr(data: number) {
  return (
    String.fromCharCode((data >> 24) & 0xFF)
    + String.fromCharCode((data >> 16) & 0xFF)
    + String.fromCharCode((data >> 8) & 0xFF)
    + String.fromCharCode(data & 0xFF)
  );
}

/**
 * Pre-processing round buffer for string input
 */
function prepare(str: string, buf: Uint32Array, offset: number = 0) {
  for (i = offset; i < 16; i++) buf[i] = strToInt32(str, i * 4);
  return str.slice(64 - offset * 4);
}

// padding
let _padstr = String.fromCharCode(128);
for (i = 0; i < 64; i += 1) _padstr += String.fromCharCode(0);

/**
 * Adds padding to message
 */
function padstring(len: number) {
  // true 64-bit message length as two 32-bit ints
  const len64hi = (len / 0x100000000) >>> 0;
  const len64lo = len >>> 0;

  return (
    _padstr.substr(0, 64 - ((len64lo + 8) & 0x3F))
    + int32ToStr((len64hi << 3) | (len64hi >>> 28))
    + int32ToStr(len64lo << 3)
  );
}

/**
 * Adds padding to buffer
 */
function padbuffer(buf: Uint32Array, len: number, offset = 0) {
  // true 64-bit message length as two 32-bit ints
  const len64hi = (len / 0x100000000) >>> 0;
  const len64lo = len >>> 0;

  buf[offset] = 0x80000000;

  for (i = offset + 1; i < 14; i++) buf[i] = 0;

  buf[14] = (len64hi << 3) | (len64hi >>> 28);
  buf[15] = len64lo << 3;
}

function out(state: Uint32Array, format: 'array'): Uint32Array;
function out(state: Uint32Array, format: 'hex' | 'binary'): string;
function out(state: Uint32Array, format: any = 'array') {
  switch (format) {
    case 'hex': return (
      `00000000${state[0].toString(16)}`.slice(-8)
    + `00000000${state[1].toString(16)}`.slice(-8)
    + `00000000${state[2].toString(16)}`.slice(-8)
    + `00000000${state[3].toString(16)}`.slice(-8)
    + `00000000${state[4].toString(16)}`.slice(-8)
    + `00000000${state[5].toString(16)}`.slice(-8)
    + `00000000${state[6].toString(16)}`.slice(-8)
    + `00000000${state[7].toString(16)}`.slice(-8)
    );

    case 'binary': return (
      int32ToStr(state[0])
    + int32ToStr(state[1])
    + int32ToStr(state[2])
    + int32ToStr(state[3])
    + int32ToStr(state[4])
    + int32ToStr(state[5])
    + int32ToStr(state[6])
    + int32ToStr(state[7])
    );

    default: return state;
  }
}
/**
 * Stream handler for hashing
 */
class Stream implements StreamInterface {
  buffer: Uint32Array;
  state: Uint32Array;
  length: number;
  offset: number;
  tail: string;

  constructor() {
    this.buffer = new Uint32Array(16);
    this.state = init();
    this.length = 0;
    this.offset = 0;
    this.tail = '';
  }

  update(chunk: string | Uint32Array): StreamInterface {
    if (typeof chunk === 'string') {
      this.length += chunk.length;

      if (this.tail.length > 0) chunk = this.tail + chunk;
      while (chunk.length > 64) {
        chunk = prepare(chunk, this.buffer, this.offset);
        round(this.state, this.buffer);
        this.offset = 0;
      }

      this.tail = chunk;
    } else {
      if (this.tail.length > 0) throw new Error('Unable to update hash-stream with array');

      this.length += chunk.length * 4;

      while (chunk.length >= this.buffer.length) {
        this.buffer.set(chunk, this.offset);
        round(this.state, this.buffer);
        chunk = chunk.subarray(this.buffer.length - this.offset);
        this.offset = 0;
      }

      if (chunk.length > 0) {
        this.buffer.set(chunk);
        this.offset = chunk.length;
      }
    }

    return this;
  }

  digest(): Uint32Array;
  digest(format: 'hex' | 'binary'): string;
  digest(format: any = 'array'): any {
    if (this.tail.length > 0) {
      let final = this.tail + padstring(this.length);
      while (final.length > 0) {
        final = prepare(final, this.buffer, this.offset);
        round(this.state, this.buffer);
        this.offset = 0;
      }
    } else {
      padbuffer(this.buffer, this.length, this.offset);
      round(this.state, this.buffer);
    }

    return out(this.state, format);
  }
}

/**
 * Hash as single function
 */
function sha256(message: string | Uint32Array): Uint32Array;
function sha256(message: string | Uint32Array, format: 'hex' | 'binary'): string;
function sha256(message: string | Uint32Array, format: any = 'array'): string | Uint32Array {
  const buf = new Uint32Array(16);
  const state = init();

  if (typeof message === 'string') {
    let data = message + padstring(message.length);

    while (data.length > 0) {
      data = prepare(data, buf);
      round(state, buf);
    }
  } else {
    const len = message.length * 4;
    let data = message;

    while (data.length >= buf.length) {
      buf.set(data);
      round(state, buf);
      data = data.subarray(buf.length);
    }

    buf.set(data);
    padbuffer(buf, len);
    round(state, buf);
  }

  return out(state, format);
}

/**
 * Hash with stream constructor
 */
sha256.stream = () => new Stream();

export default sha256;
