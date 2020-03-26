import getTypeScriptConfig from '../../scripts/rollup';

export default getTypeScriptConfig({
  packageName: 'hmac',
  entryFile: 'src/index.ts',
});
