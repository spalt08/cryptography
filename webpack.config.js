const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

const sourceDirectory = 'src';

module.exports = (env, argv) => {
  const { analyze } = argv;
  const commonConfig = {
    entry: './src/index',

    mode: 'production',

    devtool: undefined,

    plugins: [],

    externals: {},

    output: {
      path: 'dist/umd',
      library: 'sha512',
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
        path: path.resolve(__dirname, 'dist/umd'),
        filename: 'sha512.min.js',
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
        path: path.resolve(__dirname, 'dist/cjs'),
        filename: 'sha512.min.js',
        libraryTarget: 'commonjs2',
      },
    },
  ];
};
