import pbkdf2 from '../src/index';
import sha512 from '@cryptography/sha512';

test('pbkdf2', () => {
  expect(
    pbkdf2('Test', 'Hallo', 1000, sha512, 64),
  ).toEqual(
    new Uint32Array([
      0x217ba952, 0xda0c37f5, 0x1a31fc2d, 0xecc0b6f0, 0x661c36b2, 0x64795dde, 0x323933be, 0xea8ee3ea, 0xb3fb1747, 0xc779cb9f, 0xea529b44, 0xcc9d21a3, 0x23d82147, 0x4e3b950e, 0x1fe780ce, 0x8daae14f
    ]),
    //'\x21\x7b\xa9\x52\xda\x0c\x37\xf5\x1a\x31\xfc\x2d\xec\xc0\xb6\xf0\x66\x1c\x36\xb2\x64\x79\x5d\xde\x32\x39\x33\xbe\xea\x8e\xe3\xea\xb3\xfb\x17\x47\xc7\x79\xcb\x9f\xea\x52\x9b\x44\xcc\x9d\x21\xa3\x23\xd8\x21\x47\x4e\x3b\x95\x0e\x1f\xe7\x80\xce\x8d\xaa\xe1\x4f',
  )

  expect(
    pbkdf2('Testdsdsfsdds', 'Hallodsds', 100, sha512, 32),
  ).toEqual(
    new Uint32Array([0xd2f26352, 0x3575927a, 0xf455d809, 0x031ea95c, 0x45f30273, 0x1295eef2, 0x53232a33, 0xbaa5fcaf]),
  );

  expect(
    pbkdf2('Testdsdsfsddsdsfsdsdfsf', 'Hallodsds34424232dsfsdfsdfefwerwerr', 100000, sha512, 64),
  ).toEqual(
    new Uint32Array([
      0xc91489de, 0xeae689bd, 0x09c141d6, 0x7bd3af51, 0x86098b4d, 0x8012e774, 0xbee7cc38, 0x0a1ee37d, 0x5534a6ab, 0x4c554b06, 0xf282e3f8, 0x8b3c0cbc, 0x914716a4, 0x99035e65, 0x3ad7f9d2, 0xf24732ee
    ]),
  );
});