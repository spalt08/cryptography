import sha256 from '../src/index';

test('sha256 | function output length', () => {
  expect(sha256('Hello world!', 'hex').length).toEqual(64);
  expect(sha256('Hello world!', 'binary').length).toEqual(32);
  expect(sha256('Hello world!').length).toEqual(8);
});

test('sha256 | function (string -> hex)', () => {
  expect(sha256('', 'hex')).toEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  expect(sha256('Hello world!', 'hex')).toEqual('c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a');
  expect(sha256('305436bf889314e4a3faec05ecffcbb7df31ad9e51f1312233123df1', 'hex')).toEqual('277b8bfc3330dffeab6b28dcfaab0d0c691e32e3069a32b35b7c692091e60808');

  expect(
    sha256(
      'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo '
    + 'inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.',
      'hex'
    )
  ).toEqual('e68fe78e064700fe6b98e47dc0758a4f966bd027299b685642c607ea376b7d47');

  expect(sha256('Hello world!', 'hex')).toEqual('c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a');

  expect(sha256('testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest', 'hex')).toEqual('3e2b0a3dc3503d99e14cf834a3be419c4729fe32ee5fd037407f81f4d73aa619');
});

test('sha256 | function result (string -> binary)', () => {
  expect(sha256('Test Input', 'binary')).toEqual('\x15\x4b\x35\xc3\x5f\xae\xc1\x79\xa7\x21\xcb\xae\xe3\x03\xcd\x9b\x74\x60\xd3\xda\x94\xf4\xaf\xd1\xd5\x9c\x9f\xa5\x0a\x8c\xff\x87');
  expect(sha256('Hello world!', 'binary')).toEqual('\xc0\x53\x5e\x4b\xe2\xb7\x9f\xfd\x93\x29\x13\x05\x43\x6b\xf8\x89\x31\x4e\x4a\x3f\xae\xc0\x5e\xcf\xfc\xbb\x7d\xf3\x1a\xd9\xe5\x1a');

  expect(
    sha256(
      'More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private '
    + 'messages;[3] various aspects in information security such as data confidentiality, data integrity, authentication, and non-repudiation[4] ' 
    + 'are central to modern cryptography. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, '
    + 'electrical engineering, communication science, and physics. Applications of cryptography include electronic commerce, chip-based payment cards, '
    + 'digital currencies, computer passwords, and military communications.',
      'binary'
    )
  ).toEqual('\xc4\xef\x15\xfc\x11\x6b\x59\x6f\x87\x55\x48\x01\xbd\x4c\x9d\xdb\x2c\x5a\xdf\x0d\x4e\x06\xc6\xea\x45\xa9\xa1\x87\x03\x60\x4d\xa2')
});

test('sha256 | function (string -> array)', () => {
  expect(sha256('JavaScript Monorepo')).toEqual(
    new Uint32Array([0x1285536b, 0xba487a50, 0xf2cd054a, 0x21ccc0a2, 0xf6da1fad, 0x096797bc, 0x56fe67da, 0x726e20ae])
  );

  expect(sha256('Yet Another Test Long Case + Yet Another Test Long Case!')).toEqual(
    new Uint32Array([0x4aaf1da2, 0x344b7690, 0x30212e7e, 0x44136cc8, 0x59d88afd, 0xf992b635, 0xa0f3ecc5, 0x659efca8])
  );
});

test('sha256 | function (array -> array)', () => {
  expect(
    sha256(new Uint32Array([0x54657374, 0x54657374]))
  ).toEqual(
    new Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3, 0x18ef1adc, 0x43da750e, 0x49ebe4be])
  );

  expect(
    sha256(new Uint32Array([0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x73653132]))
  ).toEqual(
    new Uint32Array([0x8c8814c1, 0x4c3b3526, 0x75179536, 0x1188e795, 0x474be238, 0xb3cfe2d3, 0x790ace4f, 0xcb818651])
  );

  expect(
    sha256(new Uint32Array([
      0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x7365202b, 
      0x20596574, 0x20416e6f, 0x74686572, 0x20546573, 0x74204c6f, 0x6e672043, 0x61736511
    ]))
  ).toEqual(
    new Uint32Array([0xe25034d2, 0xc2ff6f9a, 0x997c9f52, 0x6bc4802e, 0xa9804134, 0x17366d37, 0xbd64e675, 0x8a38bc70])
  );

  expect(
    sha256(new Uint32Array([
      0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x7365202b, 
      0x20596574, 0x20416e6f, 0x74686572, 0x20546573, 0x74204c6f, 0x6e672043, 0x61736511,
      0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x7365202b, 
      0x20596574, 0x20416e6f, 0x74686572, 0x20546573, 0x74204c6f, 0x6e672043, 0x61736511
    ]))
  ).toEqual(
    new Uint32Array([0x4dfd8cab, 0x67d30f01, 0xc7bf1b10, 0x4cb5abbd, 0x1dd836ff, 0x345a47dc, 0xc30599aa, 0xa1d80b9f])
  );
});

test('sha256 | stream', () => {
  let stream = sha256.stream();

  stream.update(new Uint32Array([0x54657374]));
  stream.update(new Uint32Array([0x54657374]));
  expect(stream.digest()).toEqual(new Uint32Array([0xa8d627d9, 0x3f518e90, 0x96b6f40e, 0x36d27b76, 0x60fa26d3, 0x18ef1adc, 0x43da750e, 0x49ebe4be]));
  stream.clear();

  stream.update(new Uint32Array([
    0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x7365202b, 
    0x20596574, 0x20416e6f, 0x74686572, 0x20546573, 0x74204c6f, 0x6e672043, 0x61736511
  ]));
  stream.update(new Uint32Array([
    0x59657420, 0x416e6f74, 0x68657220, 0x54657374, 0x204c6f6e, 0x67204361, 0x7365202b, 
    0x20596574, 0x20416e6f, 0x74686572, 0x20546573, 0x74204c6f, 0x6e672043, 0x61736511
  ]));
  expect(stream.digest('hex')).toEqual('4dfd8cab67d30f01c7bf1b104cb5abbd1dd836ff345a47dcc30599aaa1d80b9f');
  stream.clear();

  stream.update('More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private ');
  stream.update('messages;[3] various aspects in information security such as data confidentiality, data integrity, authentication, and non-repudiation[4] ');
  stream.update('are central to modern cryptography. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, ');
  stream.update('electrical engineering, communication science, and physics. Applications of cryptography include electronic commerce, chip-based payment cards, ');
  stream.update('digital currencies, computer passwords, and military communications.');
  expect(stream.digest('binary')).toEqual('\xc4\xef\x15\xfc\x11\x6b\x59\x6f\x87\x55\x48\x01\xbd\x4c\x9d\xdb\x2c\x5a\xdf\x0d\x4e\x06\xc6\xea\x45\xa9\xa1\x87\x03\x60\x4d\xa2')
});

test('sha256 | error', () => {
  const stream = sha256.stream();
  let raised = false;

  try {
    stream.update('test');
    stream.update(new Uint32Array([0x54657374]));
    stream.digest();
  } catch (e) {
    raised = true;
    expect(e.message).toEqual('Unable to update hash-stream with array');
  }

  expect(raised).toBeTruthy();
});