/* eslint-disable import/no-extraneous-dependencies */
const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

module.exports = function getPackageConfig({
  entry,
  libraryName,
  sourceDirectory,
  distDirectory,
  externals = {},
  plugins = [],
  analyze = false,
}) {
  const commonConfig = {
    entry,
    mode: 'production',
    devtool: undefined,
    plugins,
    externals,

    output: {
      path: `${distDirectory}/umd`,
      library: libraryName,
    },

    optimization: {
      minimizer: [
        new TerserPlugin({
          sourceMap: false,
          extractComments: false,
          terserOptions: {
            output: {
              comments: false,
            },
          },
        }),
      ],
    },

    module: {
      rules: [
        {
          test: /\.ts$/,
          exclude: /node_modules/,
          loader: 'ts-loader',
        },
      ],
    },

    resolve: {
      modules: [sourceDirectory, 'node_modules'],
      extensions: ['.js', '.ts'],
    },
  };

  return [
    {
      // UMD
      ...commonConfig,

      plugins: [
        ...commonConfig.plugins,
        ...(analyze ? [
          new BundleAnalyzerPlugin({
            analyzerPort: 3001,
          }),
        ] : []),
      ],

      output: {
        ...commonConfig.output,
        path: `${distDirectory}/umd`,
        filename: `${libraryName}.min.js`,
        libraryTarget: 'umd',
      },
    },
    {
      // CJS
      ...commonConfig,

      externals: {
        ...commonConfig.externals,
      },

      output: {
        ...commonConfig.output,
        path: `${distDirectory}/cjs`,
        filename: `${libraryName}.min.js`,
        libraryTarget: 'commonjs2',
      },
    },
  ];
};
