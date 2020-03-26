import sha512 from '../src/index';

test('sha512 | function output length', () => {
  expect(sha512('Hello world!', 'hex').length).toEqual(128);
  expect(sha512('Hello world!', 'binary').length).toEqual(64);
  expect(sha512('Hello world!').length).toEqual(16);
});

test('sha512 | function (string -> hex)', () => {
  expect(sha512('', 'hex')).toEqual('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
  expect(sha512('Hello world!', 'hex')).toEqual('f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad6094f517a2182360c9aacf6a3dc323162cb6fd8cdffedb0fe038f55e85ffb5b6');

  expect(
    sha512(
      'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo '
    + 'inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.',
      'hex'
    )
  ).toEqual('425286c1dc4db148139bd3c2adda330677f43e5e0505ef703f7802986d946d4e59306e537aaa22a257f78ee954060cbab059b429e16a0177252f1d30108c9eb6');

  expect(
    sha512(
      'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
    + 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest',
      'hex'
    )
  ).toEqual('32b9fc99e66d8a66c3c0b8ee6ee7554a3fc152d0b0820af25371b175078b6d0fb7825626cc84453026e540d60ebeabbfd9e3eeb3fd590deb2787fe6cd8a2946f');
});

test('sha512 | function result (string -> binary)', () => {
  expect(sha512('Test Input', 'hex')).toEqual('91585ef48a0baad22ec820744a75450bce80519171d41ce039a723e7bae09fe3e82c09c4fed8a5e77094347460cc3970e261b5238969b1e2adbc3fa6841cdb1e');
  expect(sha512('Test Input', 'binary')).toEqual('\x91\x58\x5e\xf4\x8a\x0b\xaa\xd2\x2e\xc8\x20\x74\x4a\x75\x45\x0b\xce\x80\x51\x91\x71\xd4\x1c\xe0\x39\xa7\x23\xe7\xba\xe0\x9f\xe3\xe8\x2c\x09\xc4\xfe\xd8\xa5\xe7\x70\x94\x34\x74\x60\xcc\x39\x70\xe2\x61\xb5\x23\x89\x69\xb1\xe2\xad\xbc\x3f\xa6\x84\x1c\xdb\x1e');
});

test('sha512 | function (string -> array)', () => {
  expect(sha512('JavaScript Monorepo')).toEqual(
    new Uint32Array([
      0x0f5410d2, 0xcf8b8718, 0xddeb1a69, 0xe224db23, 0x4cc4960c, 0x0dff2dcb, 0xe02820c8, 0xbc3ba027,
      0x6299199c, 0x644a81bc, 0x22c739bd, 0x8378f263, 0x708ef589, 0xeb054d75, 0xd6a2297b, 0x3f5272ee
    ])
  );
});

test('sha512 | function (array -> array)', () => {
  expect(
    sha512(new Uint32Array([0x54657374, 0x54657374]))
  ).toEqual(
    new Uint32Array([
      0xf7c87428, 0xfadda0a5, 0x5c3cd42f, 0x353eb173, 0x4eb0e3d1, 0x8f3a46db, 0xc535f8c6, 0x53418a91,
      0x52e74de7, 0x40270498, 0x35f1491f, 0x43ce5368, 0xbbbffe18, 0xd853bce9, 0xb6414c52, 0x0b7d6bc6
    ])
  );
});

test('sha512 | stream', () => {
  let stream = sha512.stream();

  stream.update(new Uint32Array([0x54657374]));
  stream.update(new Uint32Array([0x54657374]));
  expect(stream.digest()).toEqual(new Uint32Array([
    0xf7c87428, 0xfadda0a5, 0x5c3cd42f, 0x353eb173, 0x4eb0e3d1, 0x8f3a46db, 0xc535f8c6, 0x53418a91,
    0x52e74de7, 0x40270498, 0x35f1491f, 0x43ce5368, 0xbbbffe18, 0xd853bce9, 0xb6414c52, 0x0b7d6bc6
  ]));
  stream.clear();

  stream.update('More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private ');
  stream.update('messages;[3] various aspects in information security such as data confidentiality, data integrity, authentication, and non-repudiation[4] ');
  stream.update('are central to modern cryptography. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, ');
  stream.update('electrical engineering, communication science, and physics. Applications of cryptography include electronic commerce, chip-based payment cards, ');
  stream.update('digital currencies, computer passwords, and military communications.');
  
  expect(stream.digest('binary')).toEqual('\xd2\x20\x9e\x52\xf5\x31\x95\x33\x14\x9a\x51\x3e\x5a\x2d\x76\x28\x46\x60\x63\xd2\xd1\x52\x35\x1d\x7c\xab\xc2\x94\x84\x4d\x66\x69\x4d\x8e\xc3\x1e\xbf\x54\xc3\xb3\x0c\xe1\x7c\x53\xe6\x6e\x9c\xcb\xbb\x4f\x71\x97\xef\xb9\x59\x89\xb2\x18\x18\x3a\xf2\x26\xd5\xa7')
});

test('sha512 | error', () => {
  const stream = sha512.stream();
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