const path = require("path");
const webpack = require("webpack");

const config = {
  entry: "./src/library.ts",
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: "ts-loader",
        exclude: /node_modules/
      }
    ]
  },
  mode: "production",
  devServer: {
    contentBase: "./dist"
  },
  resolve: {
    extensions: [".tsx", ".ts", ".js"]
  },
  output: {
    path: path.resolve(__dirname, "dist"),
    libraryTarget: "umd",
    globalObject: "typeof self !== 'undefined' ? self : this"
  }
};

const webConfig = {
  ...config,
  target: "web",
  node: {
    buffer: true,
    crypto: true
  },
  output: { ...config.output, filename: "library.client.js" }
};

const serverConfig = {
  ...config,
  target: "node",
  output: { ...config.output, filename: "library.node.js" },
  plugins: [
    new webpack.ProvidePlugin({
      fetch: ["node-fetch", "default"]
    })
  ]
};

module.exports = [serverConfig, webConfig];
