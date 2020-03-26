import { s2i, i2s, i2h } from '@cryptography/utils';

/**
 * Creates new SHA-256 state
 */
function init(): Uint32Array {
  const state = new Uint32Array(16);

  // SHA-512 state contains eight 64-bit integers
  state[0] = 0x6a09e667; state[1] = 0xf3bcc908;
  state[2] = 0xbb67ae85; state[3] = 0x84caa73b;
  state[4] = 0x3c6ef372; state[5] = 0xfe94f82b;
  state[6] = 0xa54ff53a; state[7] = 0x5f1d36f1;
  state[8] = 0x510e527f; state[9] = 0xade682d1;
  state[10] = 0x9b05688c; state[11] = 0x2b3e6c1f;
  state[12] = 0x1f83d9ab; state[13] = 0xfb41bd6b;
  state[14] = 0x5be0cd19; state[15] = 0x137e2179;

  return state;
}

/** Array to use to store round words. */
const words = new Uint32Array(160);

// K table for SHA-512
const _k = new Uint32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

/** Reusing vars */
let hi; let lo; let t1hi; let t1lo; let t2hi; let t2lo;
let ahi; let alo; let bhi; let blo; let chi; let clo; let dhi; let dlo;
let ehi; let elo; let fhi; let flo; let ghi; let glo; let hhi; let hlo;
let s1hi; let s1lo; let chlo; let chhi; let s0hi; let s0lo; let majhi; let majlo;
let i = 0;

/**
 * Perform round function
 */
function round(state: Uint32Array, data: Uint32Array) {
  // initialize hash value for this chunk
  ahi = state[0]; alo = state[1];
  bhi = state[2]; blo = state[3];
  chi = state[4]; clo = state[5];
  dhi = state[6]; dlo = state[7];
  ehi = state[8]; elo = state[9];
  fhi = state[10]; flo = state[11];
  ghi = state[12]; glo = state[13];
  hhi = state[14]; hlo = state[15];

  words.set(data);

  for (i = 32; i < 160; i += 2) {
    // for word 2 words ago: ROTR 19(x) ^ ROTR 61(x) ^ SHR 6(x)
    hi = words[i - 4];
    lo = words[i - 3];

    // high bits
    t1hi = (
      ((hi >>> 19) | (lo << 13)) // ROTR 19
      ^ ((lo >>> 29) | (hi << 3)) // ROTR 61/(swap + ROTR 29)
      ^ (hi >>> 6)) >>> 0; // SHR 6

    // low bits
    t1lo = (
      ((hi << 13) | (lo >>> 19)) // ROTR 19
      ^ ((lo << 3) | (hi >>> 29)) // ROTR 61/(swap + ROTR 29)
      ^ ((hi << 26) | (lo >>> 6))) >>> 0; // SHR 6

    // for word 15 words ago: ROTR 1(x) ^ ROTR 8(x) ^ SHR 7(x)
    hi = words[i - 30];
    lo = words[i - 29];

    // high bits
    t2hi = (
      ((hi >>> 1) | (lo << 31)) // ROTR 1
      ^ ((hi >>> 8) | (lo << 24)) // ROTR 8
      ^ (hi >>> 7)) >>> 0; // SHR 7

    // low bits
    t2lo = (
      ((hi << 31) | (lo >>> 1)) // ROTR 1
      ^ ((hi << 24) | (lo >>> 8)) // ROTR 8
      ^ ((hi << 25) | (lo >>> 7))) >>> 0; // SHR 7

    // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^64 (carry lo overflow)
    lo = t1lo + words[i - 13] + t2lo + words[i - 31];
    words[i] = t1hi + words[i - 14] + t2hi + words[i - 32] + ((lo / 0x100000000) >>> 0);
    words[i + 1] = lo;
  }

  // Round function
  for (i = 0; i < 160; i += 2) {
    // Sum1(e) = ROTR 14(e) ^ ROTR 18(e) ^ ROTR 41(e)
    s1hi = (
      ((ehi >>> 14) | (elo << 18)) // ROTR 14
      ^ ((ehi >>> 18) | (elo << 14)) // ROTR 18
      ^ ((elo >>> 9) | (ehi << 23))) >>> 0; // ROTR 41/(swap + ROTR 9)

    s1lo = (
      ((ehi << 18) | (elo >>> 14)) // ROTR 14
      ^ ((ehi << 14) | (elo >>> 18)) // ROTR 18
      ^ ((elo << 23) | (ehi >>> 9))) >>> 0; // ROTR 41/(swap + ROTR 9)

    // Ch(e, f, g) (optimized the same way as SHA-1)
    chhi = (ghi ^ (ehi & (fhi ^ ghi))) >>> 0;
    chlo = (glo ^ (elo & (flo ^ glo))) >>> 0;

    // Sum0(a) = ROTR 28(a) ^ ROTR 34(a) ^ ROTR 39(a)
    s0hi = (
      ((ahi >>> 28) | (alo << 4)) // ROTR 28
      ^ ((alo >>> 2) | (ahi << 30)) // ROTR 34/(swap + ROTR 2)
      ^ ((alo >>> 7) | (ahi << 25))) >>> 0; // ROTR 39/(swap + ROTR 7)

    s0lo = (
      ((ahi << 4) | (alo >>> 28)) // ROTR 28
      ^ ((alo << 30) | (ahi >>> 2)) // ROTR 34/(swap + ROTR 2)
      ^ ((alo << 25) | (ahi >>> 7))) >>> 0; // ROTR 39/(swap + ROTR 7)

    // Maj(a, b, c) (optimized the same way as SHA-1)
    majhi = ((ahi & bhi) | (chi & (ahi ^ bhi))) >>> 0;
    majlo = ((alo & blo) | (clo & (alo ^ blo))) >>> 0;

    // main algorithm
    // t1 = (h + s1 + ch + _k[i] + _w[i]) modulo 2^64 (carry lo overflow)
    t1lo = (hlo + s1lo + chlo + _k[i + 1] + words[i + 1]);
    t1hi = (hhi + s1hi + chhi + _k[i] + words[i] + ((t1lo / 0x100000000) >>> 0)) >>> 0;
    t1lo >>>= 0;

    // t2 = s0 + maj modulo 2^64 (carry lo overflow)
    t2lo = s0lo + majlo;
    t2hi = (s0hi + majhi + ((t2lo / 0x100000000) >>> 0)) >>> 0;
    t2lo >>>= 0;

    // Update working variables
    hhi = ghi;
    hlo = glo;

    ghi = fhi;
    glo = flo;

    fhi = ehi;
    flo = elo;

    // e = (d + t1) modulo 2^64 (carry lo overflow)
    elo = dlo + t1lo;
    ehi = (dhi + t1hi + ((elo / 0x100000000) >>> 0)) >>> 0;
    elo >>>= 0;

    dhi = chi;
    dlo = clo;

    chi = bhi;
    clo = blo;

    bhi = ahi;
    blo = alo;

    // a = (t1 + t2) modulo 2^64 (carry lo overflow)
    alo = t1lo + t2lo;
    ahi = (t1hi + t2hi + ((alo / 0x100000000) >>> 0)) >>> 0;
    alo >>>= 0;
  }

  // update hash state (additional modulo 2^64)
  lo = state[1] + alo;
  state[0] = state[0] + ahi + ((lo / 0x100000000) >>> 0);
  state[1] = lo;

  lo = state[3] + blo;
  state[2] = state[2] + bhi + ((lo / 0x100000000) >>> 0);
  state[3] = lo;

  lo = state[5] + clo;
  state[4] = state[4] + chi + ((lo / 0x100000000) >>> 0);
  state[5] = lo;

  lo = state[7] + dlo;
  state[6] = state[6] + dhi + ((lo / 0x100000000) >>> 0);
  state[7] = lo;

  lo = state[9] + elo;
  state[8] = state[8] + ehi + ((lo / 0x100000000) >>> 0);
  state[9] = lo;

  lo = state[11] + flo;
  state[10] = state[10] + fhi + ((lo / 0x100000000) >>> 0);
  state[11] = lo;

  lo = state[13] + glo;
  state[12] = state[12] + ghi + ((lo / 0x100000000) >>> 0);
  state[13] = lo;

  lo = state[15] + hlo;
  state[14] = state[14] + hhi + ((lo / 0x100000000) >>> 0);
  state[15] = lo;
}

/**
 * Pre-processing round buffer for string input
 */
function preprocess(str: string, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  while (str.length >= 128) {
    for (i = offset; i < 32; i++) buf[i] = s2i(str, i * 4);

    str = str.slice(128 - offset * 4);
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
    buf.set(input.subarray(0, buf.length - offset), offset);
    input = input.subarray(buf.length - offset);
    offset = 0;

    round(state, buf);
  }

  if (input.length > 0) {
    buf.set(input, offset);
    offset += input.length;
  }

  return offset;
}

/**
 * Repeatable part
 */
function finish(len: number, buf: Uint32Array, state: Uint32Array, offset: number = 0) {
  for (i = offset + 1; i < buf.length; i++) buf[i] = 0;

  if (offset >= 28) {
    round(state, buf);
    for (i = 0; i < buf.length; i++) buf[i] = 0;
  }

  buf[30] = ((len * 8) / 0x100000000) >>> 0;
  buf[31] = (len * 8) | 0;

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

  if (offset >= 32) {
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
      i2h(state[0]) + i2h(state[1])
    + i2h(state[2]) + i2h(state[3])
    + i2h(state[4]) + i2h(state[5])
    + i2h(state[6]) + i2h(state[7])
    + i2h(state[8]) + i2h(state[9])
    + i2h(state[10]) + i2h(state[11])
    + i2h(state[12]) + i2h(state[13])
    + i2h(state[14]) + i2h(state[15])
    );

    case 'binary': return (
      i2s(state[0]) + i2s(state[1])
    + i2s(state[2]) + i2s(state[3])
    + i2s(state[4]) + i2s(state[5])
    + i2s(state[6]) + i2s(state[7])
    + i2s(state[8]) + i2s(state[9])
    + i2s(state[10]) + i2s(state[11])
    + i2s(state[12]) + i2s(state[13])
    + i2s(state[14]) + i2s(state[15])
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

  constructor() {
    this.buffer = new Uint32Array(32);
    this.state = init();
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
function sha512(message: string | Uint32Array): Uint32Array;
function sha512(message: string | Uint32Array, format: 'hex' | 'binary'): string;
function sha512(message: string | Uint32Array, format: any = 'array'): string | Uint32Array {
  const buf = new Uint32Array(32);
  const state = init();

  if (typeof message === 'string') finalizestr(preprocess(message, buf, state), message.length, buf, state);
  else finalize(message.length * 4, buf, state, process(message, buf, state));

  return out(state, format);
}

/**
 * Hash with stream constructor
 */
sha512.stream = () => new Stream();
sha512.blockLength = 128;
sha512.digestLength = 64;

export default sha512;
