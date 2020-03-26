import getTypeScriptConfig from '../../scripts/rollup';

export default getTypeScriptConfig({
  packageName: 'sha512',
  entryFile: 'src/index.ts',
  inlineDynamicImports: true,
});
