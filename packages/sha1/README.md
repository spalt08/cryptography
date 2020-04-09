# @cryptography/sha256
[![Bundlephobia](https://img.shields.io/bundlephobia/minzip/@cryptography/sha256)](https://bundlephobia.com/result?p=@cryptography/sha1@0.2.0)
[![Coverage](https://img.shields.io/codecov/c/github/spalt08/cryptography?token=617017dc35344eb6b4637420457746c8)](https://codecov.io/gh/spalt08/cryptography)
[![Travis CI](https://img.shields.io/travis/spalt08/cryptography)](https://travis-ci.com/spalt08/cryptography)

High-performance synchronous SHA-1 implementation for JavaScript. Optimized for browsers.
  
## Features
* Blazing fast
* Ultra lightweight
* ECMAScript 3-6
* Typed
* Tested`

## Setup
[Package](https://www.npmjs.com/package/@cryptography/sha1) is available through `npm` and `yarn`
```
npm install @cryptography/sha1
```
```
yarn add @cryptography/sha1
````

### When you should use @cryptography/sha1
* Hashing small inputs (< 5kb)
* Key derivation functions
* 100% browser support required

### ⚠️ When you should not use this (WebCrypto API preferred cases)
* Hashing files (> 5kb)
* Concurrent hashing large amount of messages

## Usage
This package is optimized for small byte inputs (<10kb).

Also, it is highly recommended to run CPU-intensive tasks in a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers).
```js
import sha1 from '@cryptography/sha1'

// as Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3])
const array = sha1('Hello World!') 

// as hex-string: "a8d627d93f518e9096b6f4...."
const hex = sha1('Hello World!', 'hex')

// as binary string: "ÄïükYoUH½LÛ,Zß..."
const raw = sha1('Hello World!', 'binary')

// UInt32Array as input
const buf = new Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3, 0x18ef1adc, 0x43da750e, 0x49ebe4be]);
sha1(buf)
```
For hashing large files or other data chuncks use `stream()` to create a hashing stream.
```js
sha1.stream().update('Hello World!').digest();
```

## Benchmarks
Faster than [forge](https://github.com/digitalbazaar/forge), [sjcl](https://github.com/bitwiseshiftleft/sjcl), Rusha and [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) in **sequence** mode. 

### Try yourself
* https://jsbench.me/k8k3b15kg0

## Contributing
Contributions are welcome! Contribution guidelines will be published soon.