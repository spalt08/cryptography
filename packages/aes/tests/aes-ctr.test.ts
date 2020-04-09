import AES_CTR from "../src/modes/ctr";

test('aes | ctr', () => {
  const key = 'testtesttesttest'
  const counter = 'testtesttesttest';

  expect(new AES_CTR(key, counter).encrypt('Test')).toEqual(new Uint32Array([0x5167b3e6]));

  expect(
    new AES_CTR(key, counter).encrypt('Javascript Typed Arrays and Endianness - Stack Overflow!test')
  ).toEqual(
    new Uint32Array([
      0x4f63b6f3, 0x1daa3400, 0xa71454fd, 0xbf65fa3e, 0xa75f0c3a, 0xf8644319,
      0x793565fa, 0xb5e85b07, 0x06b68603, 0x6cb4c721, 0x3719832f, 0xf1b02dbc,
      0xa75f582b, 0x111e928a, 0xe531a534
    ])
  );

  const cipher = new AES_CTR(
    new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  );

  expect(
    cipher.encrypt(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
  ).toEqual(
    new Uint32Array([0x66e94bd4, 0xef8a2c3b, 0x884cfa59, 0xca342b2e]),
  );

  expect(
    cipher.encrypt(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
  ).toEqual(
    new Uint32Array([0x58e2fcce, 0xfa7e3061, 0x367f1d57, 0xa4e7455a]),
  );
});
