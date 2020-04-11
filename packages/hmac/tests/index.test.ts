import sha256 from '@cryptography/sha256';
import hmac from '../src';

test('hmac | string -> array', () => {
  expect(
    hmac('Test', hmac.key('\x63\x72\x79\x70\x74\x69\x69', sha256), sha256)
  ).toEqual(
    new Uint32Array([0x69f9d988, 0x4f360ec0, 0x27e59c03, 0x23761b7b, 0x912d3620, 0x8f07c3bb, 0x259b80da, 0x80ec65bb])
  );

  expect(
    hmac(
      'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.',
      hmac.key('\x63\x72\x79\x70\x74\x69\x69\x69\x69', sha256),
      sha256
    )
  ).toEqual(
    new Uint32Array([0x0ea63456, 0x25f57cf9, 0x153dc7d8, 0xf393446e, 0x2c568e43, 0xe31014ef, 0xf1c921e7, 0xc4f29f0a])
  );

  expect(
    hmac(
      'Sed',
      hmac.key('\x63\x72\x79\x70\x74\x69\x69'.repeat(8), sha256),
      sha256
    )
  ).toEqual(
    new Uint32Array([0xfcaf946b, 0xb269387e, 0x24f92cae, 0x9a477320, 0x5d0cfa2c, 0xb6a8d30a, 0x986f238d, 0x9d749df4])
  );

  expect(
    hmac(
      'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.',
      hmac.key('\x63\x72\x79\x70\x74\x69\x69'.repeat(8), sha256),
      sha256
    )
  ).toEqual(
    new Uint32Array([0xcc4c4689, 0xb5cbaa55, 0x81a853e3, 0xc4a588e2, 0xc263fece, 0x504e1738, 0xf4887c71, 0x7247d477])
  );

  expect(
    hmac(
      'Sed',
      hmac.key('\x63\x72\x79\x70\x74\x69\x69'.repeat(10), sha256),
      sha256
    )
  ).toEqual(
    new Uint32Array([0x6051bc8b, 0x126df300, 0x6654a259, 0x12da168b, 0xb7819ed1, 0xee4bf855, 0x9254c349, 0x5c478961])
  );

});