import getTypeScriptConfig from '../../scripts/rollup';

export default getTypeScriptConfig({
  packageName: 'sha1',
  entryFile: 'src/index.ts',
  inlineDynamicImports: true,
});
