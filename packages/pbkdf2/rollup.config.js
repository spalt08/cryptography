import getTypeScriptConfig from '../../scripts/rollup';

export default getTypeScriptConfig({
  packageName: 'pbkdf2',
  entryFile: 'src/index.ts',
});
