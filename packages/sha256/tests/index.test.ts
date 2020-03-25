import sha256 from '../src/index';

const cases = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['Hello world!', 'c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a'],
  ['305436bf889314e4a3faec05ecffcbb7df31ad9e51f1312233123df1', '277b8bfc3330dffeab6b28dcfaab0d0c691e32e3069a32b35b7c692091e60808'],
  ['Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.', 'e68fe78e064700fe6b98e47dc0758a4f966bd027299b685642c607ea376b7d47'],
];

test('sha256', () => {
  for (let i = 0; i < cases.length; i += 1) {
    const [input, out] = cases[i];
    const res = sha256(input, 'hex');

    expect(res.length).toEqual(64);
    expect(res).toEqual(out);
  }
});

test('sha256 | stream', () => {
  for (let i = 0; i < cases.length; i += 1) {
    const [input, out] = cases[i];
    expect(sha256.stream().update(input).digest('hex')).toEqual(out);
  }
});

test('sha256 | uintarr', () => {
  let res = sha256("test");
  expect(res instanceof Uint32Array).toBeTruthy();
  expect(res.length).toBe(8);

  res = sha256.stream().update("test").digest() as Uint32Array;
  expect(res instanceof Uint32Array).toBeTruthy();
  expect(res.length).toBe(8);
});

test('sha256 | bytes', () => {
  const input = new Uint32Array([
    0x53656420, 0x75742070, 0x65727370, 0x69636961,
    0x74697320, 0x756e6465, 0x206f6d6e, 0x69732069,
    0x73746520, 0x6e617475, 0x73206572, 0x726f7220,
    0x73697420, 0x766f6c75, 0x70746174, 0x656d2061,
  ]);

  const res = '941be5174e968c1e8f9df99654c1394b6021df6b9f3fd9a288295432a1968173';

  expect(sha256.stream().update(input).digest('hex')).toEqual(res);
});