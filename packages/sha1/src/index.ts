import { s2i, i2s, i2h } from '@cryptography/utils';

/**
 * Creates new SHA-1 state
 */
function init(h?: Uint32Array): Uint32Array {
  if (!h) h = new Uint32Array(5);

  // SHA-1 state contains five 32-bit integers
  h[0] = 0x67452301;
  h[1] = 0xEFCDAB89;
  h[2] = 0x98BADCFE;
  h[3] = 0x10325476;
  h[4] = 0xC3D2E1F0;

  return h;
}

/** Array to use to store round words. */
const words = new Uint32Array(80);

/**
 * Perform round function
 */
function round(state: Uint32Array, data: Uint32Array) {
  let i = 0; let t = 0; let f = 0;

  // initialize hash value for this chunk
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];

  // round 1
  for (i = 0; i < 16; i += 1) {
    words[i] = data[i];

    f = d ^ (b & (c ^ d));
    t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + words[i];
    e = d;
    d = c;
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  for (; i < 20; i += 1) {
    t = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]);
    t = (t << 1) | (t >>> 31);
    words[i] = t;

    f = d ^ (b & (c ^ d));
    t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t;
    e = d;
    d = c;
    // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  // round 2
  for (; i < 32; i += 1) {
    t = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]);
    t = (t << 1) | (t >>> 31);
    words[i] = t;
    f = b ^ c ^ d;
    t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
    e = d;
    d = c;
    // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  for (; i < 40; i += 1) {
    t = (words[i - 6] ^ words[i - 16] ^ words[i - 28] ^ words[i - 32]);
    t = (t << 2) | (t >>> 30);
    words[i] = t;
    f = b ^ c ^ d;
    t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
    e = d;
    d = c;
    // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  // round 3
  for (; i < 60; i += 1) {
    t = (words[i - 6] ^ words[i - 16] ^ words[i - 28] ^ words[i - 32]);
    t = (t << 2) | (t >>> 30);
    words[i] = t;
    f = (b & c) | (d & (b ^ c));
    t = ((a << 5) | (a >>> 27)) + f + e + 0x8F1BBCDC + t;
    e = d;
    d = c;
    // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  // round 4
  for (; i < 80; i += 1) {
    t = (words[i - 6] ^ words[i - 16] ^ words[i - 28] ^ words[i - 32]);
    t = (t << 2) | (t >>> 30);
    words[i] = t;
    f = b ^ c ^ d;
    t = ((a << 5) | (a >>> 27)) + f + e + 0xCA62C1D6 + t;
    e = d;
    d = c;
    // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
    c = ((b << 30) | (b >>> 2)) >>> 0;
    b = a;
    a = t;
  }

  // update hash state
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

/**
 * Pre-processing round buffer for string input
 */
function preprocess(str: string, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  while (str.length >= 64) {
    for (let i = offset; i < 16; i++) buf[i] = s2i(str, i * 4);
    str = str.slice(64 - offset * 4);
    offset = 0;

    round(state, buf);
  }

  return str;
}

/**
 * Process input buffer
 */
function process(input: Uint32Array, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  while (input.length >= buf.length - offset) {
    for (let i = 0; i < buf.length - offset; i++) buf[offset + i] = input[i];
    input = input.subarray(buf.length - offset);
    offset = 0;

    round(state, buf);
  }

  if (input.length > 0) {
    for (let i = 0; i < input.length; i++) buf[offset + i] = input[i];
    offset += input.length;
  }

  return offset;
}

/**
 * Repeatable part
 */
function finish(len: number, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  const len64hi = (len / 0x100000000) >>> 0;
  const len64lo = len >>> 0;

  for (let i = offset + 1; i < buf.length; i++) buf[i] = 0;

  if (offset >= 14) {
    round(state, buf);
    for (let i = 0; i < buf.length; i++) buf[i] = 0;
  }

  buf[14] = (len64hi << 3) + ((len64lo << 3) / 0x100000000 >>> 0);
  buf[15] = len64lo << 3;

  round(state, buf);
}

/**
 * Adds padding to message
 */
function finalizestr(chunk: string, len: number, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  for (; chunk.length >= 4; offset++) {
    buf[offset] = s2i(chunk, 0);
    chunk = chunk.slice(4);
  }

  if (offset >= 16) {
    round(state, buf);
    offset = 0;
  }

  buf[offset] = s2i(`${chunk}\x80\x00\x00\x00`, 0);
  finish(len, buf, state, offset);
}

/**
 * Adds padding to buffer
 */
function finalize(len: number, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  buf[offset] = 0x80000000;
  finish(len, buf, state, offset);
}

/**
 * Output depending on format
 */
function out(state: Uint32Array, format: 'array'): Uint32Array;
function out(state: Uint32Array, format: 'hex' | 'binary'): string;
function out(state: Uint32Array, format: any = 'array') {
  switch (format) {
    case 'hex': return (
      i2h(state[0])
    + i2h(state[1])
    + i2h(state[2])
    + i2h(state[3])
    + i2h(state[4])
    );

    case 'binary': return (
      i2s(state[0])
    + i2s(state[1])
    + i2s(state[2])
    + i2s(state[3])
    + i2s(state[4])
    );

    default: return state;
  }
}
/**
 * Stream handler for hashing
 */
class Stream {
  buffer: Uint32Array;
  state: Uint32Array;
  length: number;
  offset: number;
  tail: string;

  constructor(buf?: Uint32Array) {
    this.buffer = new Uint32Array(16);
    this.state = init(buf);
    this.length = 0;
    this.offset = 0;
    this.tail = '';
  }

  update(chunk: string | Uint32Array) {
    if (typeof chunk === 'string') {
      this.length += chunk.length;
      this.tail = preprocess(this.tail + chunk, this.buffer, this.state, this.offset);
      this.offset = 0;
    } else {
      if (this.tail.length > 0) throw new Error('Unable to update hash-stream with array');

      this.length += chunk.length * 4;
      this.offset = process(chunk, this.buffer, this.state, this.offset);
    }

    return this;
  }

  digest(): Uint32Array;
  digest(format: 'hex' | 'binary'): string;
  digest(format: any = 'array'): any {
    if (this.tail.length > 0) {
      finalizestr(this.tail, this.length, this.buffer, this.state, this.offset);
    } else {
      finalize(this.length, this.buffer, this.state, this.offset);
    }

    return out(this.state, format);
  }

  clear() {
    this.state = init();
    this.length = 0;
    this.offset = 0;
    this.tail = '';
  }
}

/**
 * Hash as single function
 */
function sha1(message: string | Uint32Array): Uint32Array;
function sha1(message: string | Uint32Array, format: 'hex' | 'binary'): string;
function sha1(message: string | Uint32Array, format: any = 'array'): string | Uint32Array {
  const buf = new Uint32Array(16);
  const state = init();

  if (typeof message === 'string') finalizestr(preprocess(message, buf, state), message.length, buf, state);
  else finalize(message.length * 4, buf, state, process(message, buf, state));

  return out(state, format);
}

/**
 * Hash with stream constructor
 */
sha1.stream = (buf?: Uint32Array) => new Stream(buf);
sha1.blockLength = 64;
sha1.digestLength = 20;

export default sha1;
