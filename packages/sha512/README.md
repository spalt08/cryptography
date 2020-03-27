# @cryptography/sha512
[![Bundlephobia](https://img.shields.io/bundlephobia/minzip/@cryptography/sha512)](https://bundlephobia.com/result?p=@cryptography/sha512@0.1.0)
[![Coverage](https://img.shields.io/codecov/c/github/spalt08/cryptography?token=617017dc35344eb6b4637420457746c8)](https://codecov.io/gh/spalt08/cryptography)
[![Travis CI](https://img.shields.io/travis/spalt08/cryptography)](https://travis-ci.com/spalt08/cryptography)

High-performance synchronous SHA-512 implementation for JavaScript. Optimized for browsers.

## Features
* Blazing fast
* Ultra lightweight
* ECMAScript 3-6
* Typed
* Tested

## Setup
[Package](https://www.npmjs.com/package/@cryptography/sha512) is available through `npm` and `yarn`
```
npm install @cryptography/sha512
```
```
yarn add @cryptography/sha512
```

## Usage
This package is optimized for small byte inputs (<10kb).

Also, it is highly recommended to run CPU-intensive tasks in a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers).


```js
import sha512 from '@cryptography/sha512'

// as Uint32Array([0xa8d627d9, ...])
const array = sha512('Hello World!') 

// as hex-string: "a8d627d9..."
const hex = sha512('Hello World!', 'hex')

// as binary string: "Äïük..."
const raw = sha512('Hello World!', 'binary')

// UInt32Array as input
const buf = new Uint32Array([0xa8d627d9, ...]);
sha512(buf)
```
For hashing large files or other data chuncks use `stream()` to create a hashing stream.
```js
sha512.stream().update('Hello World!').digest();
```

## Performance
Benchmarks:
* https://jsbench.me/gak3pyle85/3

## Contributing
Contributions are welcome! Contribution guidelines will be published later.