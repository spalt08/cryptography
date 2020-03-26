# @cryptography/sha256
[![Bundlephobia](https://img.shields.io/bundlephobia/minzip/@cryptography/sha256)](https://bundlephobia.com/result?p=@cryptography/sha256@0.1.4)
[![Coverage](https://img.shields.io/codecov/c/github/js-cryptography/sha256?token=617017dc35344eb6b4637420457746c8)](https://codecov.io/gh/js-cryptography/sha256)
[![Travis CI](https://img.shields.io/travis/js-cryptography/sha256)](https://travis-ci.com/js-cryptography/sha256)

High-performance synchronous SHA-256 implementation for JavaScript. Optimized for browsers.

## Features
* Blazing fast
* Ultra lightweight
* ECMAScript 3-6
* Typed
* Tested`

## Setup
[Package](https://www.npmjs.com/package/@cryptography/sha256) is available through `npm` and `yarn`
```
npm install @cryptography/sha256
```
```
yarn add @cryptography/sha256
````

## Usage
This package is optimized for small byte inputs (<10kb).

Also, it is highly recommended to run CPU-intensive tasks in a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers).
```js
import sha256 from '@cryptography/sha256'

// as Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3, 0x18ef1adc, 0x43da750e, 0x49ebe4be])
const array = sha256('Hello World!') 

// as hex-string: "a8d627d93f518e9096b6f40e36d27b7660fa26d318ef1adc43da750e49ebe4be"
const hex = sha256('Hello World!', 'hex')

// as binary string: "ÄïükYoUH½LÛ,Zß\nNÆêE©¡`M¢"
const raw = sha256('Hello World!', 'binary')

// UInt32Array as input
const buf = new Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3, 0x18ef1adc, 0x43da750e, 0x49ebe4be]);
sha256(buf)
```
For hashing large files or other data chuncks use `stream()` to create a hashing stream.
```js
sha256.stream().update('Hello World!').digest();
```

## Benchmarks
Faster than [forge](https://github.com/digitalbazaar/forge), [sjcl](https://github.com/bitwiseshiftleft/sjcl) and [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) in **sequence** mode. 

### 2x faster at desktop browsers (benchmarked with Macbook Pro 2016)
![Macbook 2016 perfromance](./files/perf_macbook.png)

### 4x faster at mobile browsers (benchmarked with iPhone 6S 13.2)
![iPhone 6S perfromance](./files/perf_iphone.png)

### Try yourself
* http://jsben.ch/Um0Uc
* https://jsbench.me/i1k3b0xrvy/4

## Contributing
Contributions are welcome! Contribution guidelines will be published soon.