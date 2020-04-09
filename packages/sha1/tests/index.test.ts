import sha1 from '../src/index';

test('sha1 | function output length', () => {
  expect(sha1('Hello world!', 'hex').length).toEqual(40);
  expect(sha1('Hello world!', 'binary').length).toEqual(20);
  expect(sha1('Hello world!').length).toEqual(5);
});

test('sha1 | function (string -> hex)', () => {
  expect(sha1('', 'hex')).toEqual('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  expect(sha1('Hello world!', 'hex')).toEqual('d3486ae9136e7856bc42212385ea797094475802');
  expect(
    sha1(
      'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo '
    + 'inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.',
      'hex'
    )
  ).toEqual('e607a674e3c8454398a7d33a28268f44719af694');
});

test('sha1 | function result (string -> binary)', () => {
  expect(sha1('Test Input', 'binary')).toEqual('\x65\x83\x28\x19\xbb\xcf\x7e\x58\x83\x61\x6c\x62\x59\xb3\xda\x34\xae\x6a\x0d\x84');

  expect(
    sha1(
      'More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private '
    + 'messages;[3] various aspects in information security such as data confidentiality, data integrity, authentication, and non-repudiation[4] ' 
    + 'are central to modern cryptography. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, '
    + 'electrical engineering, communication science, and physics. Applications of cryptography include electronic commerce, chip-based payment cards, '
    + 'digital currencies, computer passwords, and military communications.',
      'binary'
    )
  ).toEqual('\x3d\x17\xba\x26\x43\x81\x8c\x1a\x96\x79\xf6\xb9\x74\x3a\xde\x1e\xc6\xe0\xd3\xe1')
});

test('sha1 | function (string -> array)', () => {
  expect(sha1('JavaScript Monorepo')).toEqual(
    new Uint32Array([0x0c66cacb, 0xeb061a37, 0xadb2e204, 0xf6b4c9c0, 0x9f1f142d])
  );
});

test('sha256 | function (array -> array)', () => {
  expect(
    sha1(new Uint32Array([0x54657374, 0x54657374]))
  ).toEqual(
    new Uint32Array([0x7df71b73, 0x819f2e0c, 0x618339a2, 0xa45308a9, 0x775e3c6f])
  );
});

test('sha256 | stream', () => {
  let stream = sha1.stream();

  stream.update(new Uint32Array([0x54657374]));
  stream.update(new Uint32Array([0x54657374]));
  expect(stream.digest()).toEqual(new Uint32Array([0x7df71b73, 0x819f2e0c, 0x618339a2, 0xa45308a9, 0x775e3c6f]));
  stream.clear();

  stream.update('More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private ');
  stream.update('messages;[3] various aspects in information security such as data confidentiality, data integrity, authentication, and non-repudiation[4] ');
  stream.update('are central to modern cryptography. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, ');
  stream.update('electrical engineering, communication science, and physics. Applications of cryptography include electronic commerce, chip-based payment cards, ');
  stream.update('digital currencies, computer passwords, and military communications.');
  expect(stream.digest('binary')).toEqual('\x3d\x17\xba\x26\x43\x81\x8c\x1a\x96\x79\xf6\xb9\x74\x3a\xde\x1e\xc6\xe0\xd3\xe1')
});
