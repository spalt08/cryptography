/* eslint-disable import/no-extraneous-dependencies */
const path = require('path');
const getPackageConfig = require('@cryptography/webpack-config');

module.exports = (env, argv) => {
  const { analyze } = argv;

  return getPackageConfig({
    entry: path.join(__dirname, './src/index'),
    libraryName: 'sha256',
    sourceDirectory: path.join(__dirname, 'src'),
    distDirectory: path.join(__dirname, 'dist'),
    analyze,
  });
};
