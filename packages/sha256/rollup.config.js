import getTypeScriptConfig from '../../scripts/rollup';

export default getTypeScriptConfig({
  packageName: 'sha256',
  entryFile: 'src/index.ts',
  inlineDynamicImports: true,
});
