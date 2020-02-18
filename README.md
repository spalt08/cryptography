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

const hash = sha256('Hello World!')
const bytes = sha256('Hello World!', 'array')
```
For hashing large files or other data chuncks use `stream()` to create a hashing stream.
```js
sha256.stream().update('Hello World!').digest();
```
### When you should use @cryptography/sha256
* Hashing small inputs (< 5kb)
* Key derivation functions

### ⚠️ When you should not use this (WebCrypto API preferred cases)
* Hashing files (> 5kb)
* Concurrent hashing large amount of messages

## Benchmarks
Faster than [forge](https://github.com/digitalbazaar/forge), [sjcl](https://github.com/bitwiseshiftleft/sjcl) and [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) in **sequence** mode. 

### 2x faster at desktop browsers (benchmarked with Macbook Pro 2016)
![Macbook 2016 perfromance](/files/perf_macbook.png)
Displays hashes/sec at 128 byte input message

### 4x faster at mobile browsers (benchmarked with iPhone 6S 13.2)
![iPhone 6S perfromance](/files/perf_iphone.png)
Displays hashes/sec at 128 byte input message

### Try yourself
* http://jsben.ch/Um0Uc
* https://jsbench.me/i1k3b0xrvy/4

## Contributing
Contributions are welcome! Contribution guidelines will be published soon.
