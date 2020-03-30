import AES_IGE from "../src/modes/ige";

test('aes | IGE', () => {
  const cipherText = new Uint32Array([
    0x28A92FE2, 0x0173B347, 0xA8BB324B, 0x5FAB2667, 0xC9A8BBCE, 0x6468D5B5, 0x09A4CBDD, 0xC186240A, 0xC912CF70, 0x06AF8926, 0xDE606A2E,
    0x74C0493C, 0xAA57741E, 0x6C82451F, 0x54D3E068, 0xF5CCC49B, 0x4444124B, 0x9666FFB4, 0x05AAB564, 0xA3D01E67, 0xF6E91286, 0x7C8D20D9,
    0x882707DC, 0x330B17B4, 0xE0DD57CB, 0x53BFAAFA, 0x9EF5BE76, 0xAE6C1B9B, 0x6C51E2D6, 0x502A47C8, 0x83095C46, 0xC81E3BE2, 0x5F62427B,
    0x585488BB, 0x3BF23921, 0x3BF48EB8, 0xFE34C9A0, 0x26CC8413, 0x93404397, 0x4DB03556, 0x63303839, 0x2CECB51F, 0x94824E14, 0x0B986377,
    0x30A4BE79, 0xA8F9DAFA, 0x39BAE81E, 0x1095849E, 0xA4C83467, 0xC92A3A17, 0xD997817C, 0x8A7AC61C, 0x3FF414DA, 0x37B7D66E, 0x949C0AEC,
    0x858F0482, 0x24210FCC, 0x61F11C3A, 0x910B431C, 0xCBD104CC, 0xCC8DC6D2, 0x9D4A5D13, 0x3BE639A4, 0xC32BBFF1, 0x53E63ACA, 0x3AC52F2E,
    0x4709B8AE, 0x01844B14, 0x2C1EE89D, 0x075D64F6, 0x9A399FEB, 0x04E656FE, 0x3675A6F8, 0xF412078F, 0x3D0B58DA, 0x15311C1A, 0x9F8E53B3,
    0xCD6BB557, 0x2C294904, 0xB726D0BE, 0x337E2E21, 0x977DA26D, 0xD6E33270, 0x251C2CA2, 0x9DFCC702, 0x27F0755F, 0x84CFDA9A, 0xC4B8DD5F,
    0x84F1D1EB, 0x36BA45CD, 0xDC70444D, 0x8C213E4B, 0xD8F63B8A, 0xB95A2D0B, 0x4180DC91, 0x283DC063, 0xACFB92D6, 0xA4E407CD, 0xE7C8C696,
    0x89F77A00, 0x7441D4A6, 0xA8384B66, 0x6502D9B7, 0x7FC68B5B, 0x43CC607E, 0x60A14622, 0x3E110FCB, 0x43BC3C94, 0x2EF98193, 0x0CDC4A1D,
    0x310C0B64, 0xD5E55D30, 0x8D863251, 0xAB90502C, 0x3E46CC59, 0x9E886A92, 0x7CDA963B, 0x9EB16CE6, 0x2603B685, 0x29EE98F9, 0xF5206419,
    0xE03FB458, 0xEC4BD945, 0x4AA8F6BA, 0x777573CC, 0x54B32889, 0x5B1DF25E, 0xAD9FB4CD, 0x5198EE02, 0x2B2B81F3, 0x88D281D5, 0xE5BC5801,
    0x07CA01A5, 0x0665C32B, 0x552715F3, 0x35FD7626, 0x4FAD00DD, 0xD5AE45B9, 0x4832AC79, 0xCE7C511D, 0x194BC42B, 0x70EFA850, 0xBB15C201,
    0x2C5215CA, 0xBFE97CE6, 0x6B8D8734, 0xD0EE759A, 0x638AF013
  ]);

  const key = new Uint32Array([0xF0112808, 0x87C7BB01, 0xDF0FC4E1, 0x7830E0B9, 0x1FBB8BE4, 0xB2267CB9, 0x85AE25F3, 0x3B527253]);
  const iv = new Uint32Array([0x3212D579, 0xEE35452E, 0xD23E0D0C, 0x92841AA7, 0xD31B2E9B, 0xDEF2151E, 0x80D15860, 0x311C85DB]);

  const plainText = new Uint32Array([
    0x4b0af668, 0xcf60a358, 0x233f93b7, 0x341fca7e, 0x7f02a8c2, 0xba0d89b5, 0x3e054982, 0x8cca27e9, 0x66b301a4, 0x8fece2fc, 0xa5cf4d33,
    0xf4a11ea8, 0x77ba4aa5, 0x73907330, 0x02000000, 0xfe000100, 0xc71caeb9, 0xc6b1c904, 0x8e6c522f, 0x70f13f73, 0x980d4023, 0x8e3e21c1,
    0x4934d037, 0x563d930f, 0x48198a0a, 0xa7c14058, 0x229493d2, 0x2530f4db, 0xfa336f6e, 0x0ac92513, 0x9543aed4, 0x4cce7c37, 0x20fd51f6,
    0x9458705a, 0xc68cd4fe, 0x6b6b13ab, 0xdc974651, 0x29693284, 0x54f18faf, 0x8c595f64, 0x2477fe96, 0xbb2a941d, 0x5bcd1d4a, 0xc8cc4988,
    0x0708fa9b, 0x378e3c4f, 0x3a9060be, 0xe67cf9a4, 0xa4a69581, 0x1051907e, 0x162753b5, 0x6b0f6b41, 0x0dba74d8, 0xa84b2a14, 0xb3144e0e,
    0xf1284754, 0xfd17ed95, 0x0d5965b4, 0xb9dd4658, 0x2db1178d, 0x169c6bc4, 0x65b0d6ff, 0x9ca3928f, 0xef5b9ae4, 0xe418fc15, 0xe83ebea0,
    0xf87fa9ff, 0x5eed7005, 0x0ded2849, 0xf47bf959, 0xd956850c, 0xe929851f, 0x0d8115f6, 0x35b105ee, 0x2e4e15d0, 0x4b2454bf, 0x6f4fadf0,
    0x34b10403, 0x119cd8e3, 0xb92fcc5b, 0xfe000100, 0x262aaba6, 0x21cc4df5, 0x87dc94cf, 0x8252258c, 0x0b9337df, 0xb47545a4, 0x9cdd5c9b,
    0x8eae7236, 0xc6cadc40, 0xb24e8859, 0x0f1cc2cc, 0x762ebf1c, 0xf11dcc0b, 0x393caad6, 0xcee4ee58, 0x48001c73, 0xacbb1d12, 0x7e4cb930,
    0x72aa3d1c, 0x8151b6fb, 0x6aa6124b, 0x7cd782ea, 0xf981bdcf, 0xce9d7a00, 0xe423bd9d, 0x194e8af7, 0x8ef6501f, 0x415522e4, 0x4522281c,
    0x79d906dd, 0xb79c72e9, 0xc63d83fb, 0x2a940ff7, 0x79dfb5f2, 0xfd786fb4, 0xad71c9f0, 0x8cf48758, 0xe534e981, 0x5f634f1e, 0x3a80a5e1,
    0xc2af210c, 0x5ab76275, 0x5ad4b212, 0x6dfa61a7, 0x7fa9da96, 0x7d65dfd0, 0xafb5cdf2, 0x6c4d4e1a, 0x88b180f4, 0xe0d0b45b, 0xa1484f95,
    0xcb2712b5, 0x0bf3f596, 0x8d9d55c9, 0x9c0fb9fb, 0x67bff56d, 0x7d4481b6, 0x34514fba, 0x3488c4cd, 0xa2fc0659, 0x990e8e86, 0x8b286328,
    0x75a9aa70, 0x3bcdce8f, 0xcb7ae551, 0x99e2dddd, 0x536648d8,
  ]);

  const cipher = new AES_IGE(key, iv);
  expect(cipher.decrypt(cipherText)).toEqual(plainText);
  expect(cipher.encrypt(plainText)).toEqual(cipherText);
});